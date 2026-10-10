package com.ghostdeveloper.spdecode.parity

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.json.JSONTokener
import org.json.JSONObject
import org.json.JSONArray

/**
 * Authenticated NPVS v5 field-document reconstruction.
 * Literal port of npvs.py _field_key and _document.
 * Call ONLY after signature, wrapped DEK and metadata binding have been verified.
 */
internal object NpvsV5Fields {
    private val ascii = Charsets.US_ASCII
    private fun sha256(data: ByteArray) = MessageDigest.getInstance("SHA-256").digest(data)
    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        require(length in 1..8160)
        val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val result = ByteArray(length)
        var previous = byteArrayOf()
        var pos = 0
        var counter = 1
        while (pos < length) {
            previous = hmac(prk, previous + info + byteArrayOf(counter.toByte()))
            val take = minOf(previous.size, length - pos)
            previous.copyInto(result, pos, 0, take)
            pos += take
            counter++
        }
        return result
    }
    private fun be16(id: Int) = byteArrayOf((id ushr 8).toByte(), id.toByte())
    private fun be32(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array()
    private fun key(dek: ByteArray, context: ByteArray, label: String, id: Int) =
        hkdf(dek, context, "NPV-fields-v1/${label}/".toByteArray(ascii) + be16(id))
    private fun parseJson(bytes: ByteArray): Any {
        val str = bytes.toString(Charsets.UTF_8)
        val value = JSONTokener(str).nextValue()
        require(value != null)
        return value
    }
    private fun resolve(node: Any?, records: Map<Int, Any>, used: MutableSet<Int>, depth: Int): Any? {
        require(depth <= 128) { "NPVS field layout too deep" }
        return when (node) {
            is JSONObject -> JSONObject().also { result ->
                val names = node.keys()
                while (names.hasNext()) {
                    val name = names.next()
                    result.put(name, resolve(node.get(name), records, used, depth + 1))
                }
            }
            is JSONArray -> JSONArray().also { result ->
                for (i in 0 until node.length()) result.put(resolve(node.get(i), records, used, depth + 1))
            }
            is Int -> {
                require(node in 1..65534 && records.containsKey(node)) { "Invalid NPVS field reference" }
                val value = records.getValue(node)
                require(value !is JSONObject && value !is JSONArray) { "NPVS scalar is a container" }
                used.add(node)
                value
            }
            else -> error("Invalid NPVS field reference type")
        }
    }
    fun decode(body: ByteArray, dek: ByteArray, context: ByteArray,
               openAead: (ByteArray, ByteArray, ByteArray, ByteArray) -> ByteArray): JSONObject {
        require(context.size == 32 && dek.size == 32)
        require(body.size >= 70 && body.copyOfRange(0, 4).contentEquals(byteArrayOf(78,80,70,1)))
        require(MessageDigest.isEqual(body.copyOfRange(4,36), context)) { "NPVS metadata binding mismatch" }
        val expected = hmac(key(dek,context,"inventory",0),body.copyOfRange(0,body.size-32))
        require(MessageDigest.isEqual(expected,body.copyOfRange(body.size-32,body.size))) { "NPVS inventory HMAC mismatch" }
        val count = ((body[36].toInt() and 255) shl 8) or (body[37].toInt() and 255)
        require(count > 0)
        val buffer = ByteBuffer.wrap(body).order(ByteOrder.BIG_ENDIAN)
        buffer.position(38)
        var lastId = 0
        val records = linkedMapOf<Int,Any>()
        repeat(count) {
            require(buffer.position() + 6 <= body.size - 32)
            val id = buffer.short.toInt() and 65535
            val length = buffer.int
            require(id > lastId && length in 16..1048592 && length <= body.size - 32 - buffer.position())
            val payload = ByteArray(length).also { buffer.get(it) }
            val aad = "NPV-fields-v1/record/".toByteArray(ascii) + context + be16(id) + be32(length - 16)
            val plain = openAead(key(dek,context,"field",id),ByteArray(12),payload,aad)
            records[id] = parseJson(plain)
            lastId = id
        }
        require(buffer.position() == body.size - 32 && records.containsKey(65535))
        val used = mutableSetOf<Int>()
        val document = resolve(records.getValue(65535),records,used,0)
        require(used == records.keys.filter { it != 65535 }.toSet())
        require(document is JSONObject && document.opt("configs") is JSONArray)
        return document
    }
}

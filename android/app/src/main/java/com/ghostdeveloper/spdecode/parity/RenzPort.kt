package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Python-compatible offline RENZ / 7NET file engine.
 *
 * Covers 16 suffixes through fourteen source profiles (including .osp => 7net
 * and .actun => actunnelvpn). Does not take ownership of Ultra .vlx or IZPH.
 * Main layer: AES-CBC -> customized XXTEA -> per-profile byte transform.
 * For 7NET, also tries historical typed 0/1/2/3. Nested host/path uses
 * HKDF/Threefish-256/AES-CBC; username/password uses PBKDF2/XXTEA/AES-CBC.
 *
 * CBC/XXTEA/Threefish are NOT authenticated. A successful parse does not
 * prove integrity. No network, remote key source or cleartext/credential logs.
 */
object RenzPort {
    const val MAX_INPUT_BYTES = 2 * 1024 * 1024
    private val gson = GsonBuilder().disableHtmlEscaping().serializeNulls()
        .setPrettyPrinting().create()
    private const val DELTA = 0x7A56D3E1
    private const val V2_DELTA = 2052510689
    private const val V2_OFFSET = 569837754
    private const val C240 = 0x1BD11BDAA9FC1A22L
    private val ROT = arrayOf(
        intArrayOf(14,16), intArrayOf(52,57), intArrayOf(23,40),
        intArrayOf(5,37), intArrayOf(25,33), intArrayOf(46,12),
        intArrayOf(58,22), intArrayOf(32,32),
    )
    private val PERM = intArrayOf(0,3,2,1)
    private val FIXED_SALT = hex("70ed508428ff7b5bcde0bcdd3b9474932ab1cabc5ff6870e6e584b4fa7925f55")
    private val BASE_MATERIAL = hex("deb72221be4652c347f930e85adc29970ccd499cf42e361b3d6b14918912bf3b")
    private val FIXED_IV = hex("2d2f3112a271edbba9a41ad58a3a99bf")
    private val TRP_KEY = hex("91f9eea7eb614fbbff2521e76306cea4")
    private val TCX_KEY = hex("6103102f3dfa7cac1aa5b8ff4ba12022")
    private val ZERO_IV = ByteArray(16)
    private val NO_SUBTRACT = setOf("xhypher","safetunnel","mhrtunnel","letsvpngo")
    private val SEVEN_ZERO_TWEAK = setOf(
        "7net","actunnelvpn","vipsnipherpro","deshtunnelvpn","hamotunnelplus"
    )

    fun decode(context: Context, suffix: String, input: ByteArray): String? {
        if (input.isEmpty() || input.size > MAX_INPUT_BYTES) return null
        val inventory = try { RenzProfileStore.read(context) } catch (_: RuntimeException) { return null }
        val name = suffix.lowercase(Locale.ROOT).removePrefix(".")
        val alias = inventory.aliases[name] ?: return null
        val source = try { utf8(input).trim() } catch (_: Exception) { return null }
        if (source.isBlank()) return null
        var token = source
        if ("://" in source) {
            val scheme = source.substringBefore("://").lowercase(Locale.ROOT) + "://"
            val assigned = schemes[scheme] ?: return null
            if (assigned != alias.profile) return null
            token = source.substringAfter("://")
        }
        if (token.isBlank()) return null
        val profile = inventory.profiles[alias.profile] ?: return null
        val decoded = try {
            decodeConfig(token,profile)
        } catch (_: Exception) { null } ?: return null
        val out = JsonObject()
        out.addProperty("application",alias.name)
        out.addProperty("extension","." + alias.suffix)
        out.add("config",decoded)
        return gson.toJson(out)
    }

    private val schemes = mapOf(
        "7net://" to "7net", "7netvpn://" to "7net",
        "tcx://" to "tcxtunnel", "tcxtunnelplus://" to "tcxtunnel",
        "ihome://" to "7net", "ihomevpn://" to "7net",
        "xhypher://" to "xhypher", "xhyphertunnelpro://" to "xhypher",
        "osp://" to "7net", "osptunnel://" to "7net",
        "actunnelvpn://" to "actunnelvpn", "actunnel://" to "actunnelvpn",
        "bshieldnet://" to "bshield", "bshield://" to "bshield",
        "safetunnel://" to "safetunnel", "mhrtunnel://" to "mhrtunnel",
        "letsvpngo://" to "letsvpngo", "aloplusvpn://" to "aloplusvpn",
        "cranetunnel://" to "cranetunnel", "vipsnipherpro://" to "vipsnipherpro",
        "deshtunnelvpn://" to "deshtunnelvpn",
        "hamotunnelplus://" to "hamotunnelplus", "gcpvpn://" to "gcpvpn"
    )

    private fun decodeConfig(input: String, profile: RenzProfileStore.Profile): JsonElement? {
        val outer = try { parse(main(input,profile)) } catch (_: Exception) { null }
        if (outer != null) {
            deepDecrypt(outer, profile)
            return outer
        }
        // Python only permits typed fallback for 7net; .osp shares that key.
        if (profile.id != "7net") return null
        val bytes = input.toByteArray(Charsets.UTF_8)
        val decoded = try { decodeBase64(input) } catch (_: Exception) { null }
        val candidates = listOfNotNull(bytes, decoded)
        for (type in 0..3) for (candidate in candidates) {
            val clear = try { typeDecode(type,candidate) } catch (_: Exception) { null }
            val parsed = clear?.let { parse(it) } ?: continue
            deepTyped(parsed)
            return parsed
        }
        return null
    }

    private fun main(input: String, p: RenzProfileStore.Profile): ByteArray {
        if (p.id == "tcxtunnel") {
            val xxtea = customXxtea(decodeBase64(input), TCX_KEY, tcx = true)
            return cbc(xxtea, TCX_KEY, ZERO_IV, unpad = true)
        }
        val key = sha256(p.seed).copyOf(16)
        val aes = cbc(decodeBase64(input), key, p.iv, unpad = true)
        val xxtea = customXxtea(aes,key)
        return if (p.id in NO_SUBTRACT) xxtea
            else ByteArray(xxtea.size) { i -> (xxtea[i].toInt() - 2).toByte() }
    }

    private fun typeDecode(type: Int, data: ByteArray): ByteArray {
        return when (type) {
            0 -> {
                val key = sha256(BASE_MATERIAL).copyOf(16)
                val aes = cbc(data,key,FIXED_IV,unpad=true)
                val xxtea = legacyXxtea(aes,key)
                ByteArray(xxtea.size) { i -> (xxtea[i].toInt() - 2).toByte() }
            }
            1 -> {
                val bytes = decodeBase64(utf8(data))
                val key16 = hkdf(BASE_MATERIAL,FIXED_SALT.copyOf(16),16)
                val key32 = hkdf(BASE_MATERIAL,FIXED_SALT,32)
                val tf = threefish(bytes,key32) { idx, _ -> longArrayOf(idx.toLong(),0) }
                    .dropLastWhile { it == 0.toByte() }.toByteArray()
                cbc(tf,key16,FIXED_IV,unpad=true)
            }
            2 -> {
                val bytes = decodeBase64(utf8(data))
                val key = GenericVpnPort.pbkdf2Sha256(BASE_MATERIAL,FIXED_SALT,100_000,32)
                val xxtea = legacyXxtea(bytes,key.copyOf(16))
                cbcPrefixed(xxtea,key)
            }
            3 -> cbcPrefixed(data,hkdf(BASE_MATERIAL,FIXED_SALT,32))
            else -> error("Unsupported typed RENZ")
        }
    }

    private fun cbcPrefixed(ciphertext: ByteArray, key: ByteArray): ByteArray {
        require(ciphertext.size >= 32)
        return cbc(ciphertext.copyOfRange(16,ciphertext.size),
            key,ciphertext.copyOfRange(0,16),unpad=true)
    }

    private fun cbc(data: ByteArray, key: ByteArray, iv: ByteArray, unpad: Boolean): ByteArray {
        require(data.isNotEmpty() && data.size <= MAX_INPUT_BYTES && data.size % 16 == 0)
        require(key.size in setOf(16,24,32) && iv.size == 16)
        val cipher = Cipher.getInstance(if (unpad) "AES/CBC/PKCS5Padding" else "AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        return cipher.doFinal(data)
    }

    private fun sha256(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)

    private fun utf8(input: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(input)).toString()

    private fun decodeBase64(input: String): ByteArray {
        val clean = input.filter { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" }
        require(clean.isNotEmpty() && clean.length <= MAX_INPUT_BYTES * 2)
        return Base64.decode(clean.padEnd((clean.length+3)/4*4,'='),Base64.DEFAULT)
    }

    private fun parse(input: ByteArray): JsonElement? = try {
        val el = JsonParser.parseString(utf8(input))
        if (el.isJsonObject || el.isJsonArray) el else null
    } catch (_: Exception) { null }

    private fun hex(source: String): ByteArray =
        ByteArray(source.length / 2) { i -> source.substring(i*2,i*2+2).toInt(16).toByte() }

    private fun leWords(data: ByteArray, extraLength: Boolean = false): IntArray {
        val words = (data.size + 3) / 4
        val out = IntArray(words + if (extraLength) 1 else 0)
        for (i in data.indices) {
            out[i/4] = out[i/4] or ((data[i].toInt() and 255) shl (8*(i%4)))
        }
        if (extraLength) out[words] = data.size
        return out
    }

    private fun fromWords(v: IntArray): ByteArray = ByteArray(v.size * 4) { i ->
        (v[i/4] ushr (8*(i%4))).toByte()
    }

    private fun prepareKey(key: ByteArray): IntArray {
        val material = key.copyOf(16)
        for (i in 0..14) if (material[i] == 0.toByte()) {
            for (j in i+1..15) material[j] = 0
            break
        }
        return leWords(material)
    }

    private fun mx(sum: Int, y: Int, z: Int, p: Int, e: Int, k: IntArray): Int =
        (((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) xor
        ((sum xor y) + (k[(p and 3) xor e] xor z))

    private fun customXxtea(data: ByteArray, key: ByteArray, tcx: Boolean = false): ByteArray {
        require(data.size >= 8 && data.size <= MAX_INPUT_BYTES)
        val v = leWords(data)
        val n = v.size
        require(n >= 2)
        val delta = if (tcx) 0x9E3779B9.toInt() else V2_DELTA
        val offset = if (tcx) 0x4AB325AA else V2_OFFSET
        val k = prepareKey(key)
        val rounds = 52/n + 6
        var sum = delta * (52/n) - offset
        repeat(rounds) {
            val e = (sum ushr 2) and 3
            var y = v[0]
            for (i in n-1 downTo 1) {
                val z = v[i-1]
                v[i] -= mx(sum,y,z,i,e,k)
                y = v[i]
            }
            val z = v[n-1]
            v[0] -= mx(sum,y,z,0,e,k)
            sum -= delta
        }
        require(sum == 0) { "Wrong XXTEA profile" }
        val length = v.last().toLong() and 0xFFFFFFFFL
        val paddedLength = v.size * 4
        require(length >= paddedLength - 7 && length <= paddedLength - 4)
        return fromWords(v).copyOf(length.toInt())
    }

    private fun legacyXxtea(data: ByteArray, key: ByteArray): ByteArray {
        require(data.size >= 8 && data.size <= MAX_INPUT_BYTES && data.size % 4 == 0)
        val v = leWords(data)
        val n = v.size
        val k = leWords(key.copyOf(16))
        var sum = DELTA * (6 + 52/n)
        repeat(6 + 52/n) {
            val e = (sum ushr 2) and 3
            var y = v[0]
            for (i in n-1 downTo 1) {
                val z = v[i-1]
                v[i] -= mx(sum,y,z,i,e,k)
                y = v[i]
            }
            val z = v[n-1]
            v[0] -= mx(sum,y,z,0,e,k)
            sum -= DELTA
        }
        val length = v.last().toLong() and 0xFFFFFFFFL
        require(length >= n*4-7 && length <= n*4-4)
        return fromWords(v).copyOf(length.toInt())
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, length: Int): ByteArray {
        require(length in 1..64)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt,"HmacSHA256"))
        val prk = mac.doFinal(ikm)
        mac.init(SecretKeySpec(prk,"HmacSHA256"))
        val blocks = mutableListOf<ByteArray>()
        var previous = byteArrayOf()
        var counter = 1
        while (blocks.sumOf { it.size } < length) {
            previous = mac.doFinal(previous + byteArrayOf(counter.toByte()))
            blocks.add(previous)
            counter++
        }
        prk.fill(0)
        return blocks.fold(byteArrayOf()) { acc, item -> acc + item }.copyOf(length)
    }

    /** Threefish-256 with 18 round groups (72 rounds), little-endian blocks. */
    private fun threefish(
        data: ByteArray, key: ByteArray,
        tweaks: (Int,LongArray) -> LongArray
    ): ByteArray {
        require(key.size >= 32 && data.size <= MAX_INPUT_BYTES &&
            data.isNotEmpty() && data.size % 32 == 0)
        val keyWords = longWords(key.copyOf(32))
        val result = ByteArray(data.size)
        for (offset in data.indices step 32) {
            val block = longWords(data.copyOfRange(offset, offset+32))
            val tw = tweaks(offset/32,block)
            require(tw.size == 2)
            val sub = subkeys(keyWords,tw)
            val state = block.clone()
            for (group in 17 downTo 0) {
                val keys = sub[group+1]
                for (j in 0..3) state[j] -= keys[j]
                for (step in 3 downTo 0) {
                    val permuted = LongArray(4) { state[PERM[it]] }
                    permuted.copyInto(state)
                    val rotation = ROT[(group*4 + step)%8]
                    unmix(state,0,rotation[0])
                    unmix(state,2,rotation[1])
                }
            }
            for (j in 0..3) state[j] -= sub[0][j]
            toBytes(state).copyInto(result,offset)
        }
        return result
    }

    private fun longWords(data: ByteArray): LongArray {
        require(data.size % 8 == 0)
        val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        return LongArray(data.size / 8) { b.long }
    }

    private fun toBytes(words: LongArray): ByteArray {
        val b = ByteBuffer.allocate(words.size*8).order(ByteOrder.LITTLE_ENDIAN)
        words.forEach { b.putLong(it) }
        return b.array()
    }

    private fun subkeys(key: LongArray, tweak: LongArray): Array<LongArray> {
        val words = key.copyOf(5)
        words[4] = C240 xor words[0] xor words[1] xor words[2] xor words[3]
        val t = longArrayOf(tweak[0],tweak[1],tweak[0] xor tweak[1])
        return Array(19) { i ->
            longArrayOf(
                words[i%5],
                words[(i+1)%5] + t[i%3],
                words[(i+2)%5] + t[(i+1)%3],
                words[(i+3)%5] + i.toLong()
            )
        }
    }

    private fun unmix(state: LongArray, at: Int, rotation: Int) {
        val y0 = state[at]
        val y1 = state[at+1]
        val x1 = java.lang.Long.rotateRight(y0 xor y1,rotation)
        state[at] = y0 - x1
        state[at+1] = x1
    }

    private fun special(value: String, p: RenzProfileStore.Profile): String? {
        if (p.id == "tcxtunnel") return try { utf8(main(value,p)) } catch (_: Exception) { null }
        val raw = decodeBase64(value)
        val salt = if (p.salt.isNotEmpty()) p.salt else ByteArray(32) { '0'.code.toByte() }
        val key16 = hkdf(p.seed,salt.copyOf(16),16)
        val key32 = hkdf(p.seed,salt,32)
        if (p.id == "cranetunnel") {
            val xxtea = customXxtea(raw,key16)
            return utf8(cbc(xxtea,key16,p.iv,unpad=true))
        }
        val tf = threefish(raw,key32) { idx,words ->
            var t0 = idx.toLong()
            var t1 = idx.toLong() * 64L
            if (p.id == "vipsnipherpro") t0 = 0L
            when {
                p.id in SEVEN_ZERO_TWEAK || p.id == "aloplusvpn" -> t1 = 0L
                p.id in NO_SUBTRACT -> t1 = idx.toLong() * 192L
            }
            if (p.id == "aloplusvpn") {
                for (i in 0..3) t1 = t1 xor (words[i] + i.toLong())
                t1 = t1 xor (idx.toLong() * 160L)
            }
            longArrayOf(t0,t1)
        }
        val trimmed = tf.dropLastWhile { it == 0.toByte() }.toByteArray()
        val clear = cbc(trimmed,key16,p.iv,unpad=false)
        // Source accepts both padded and non-PKCS7-terminated AES content.
        val last = clear.lastOrNull()?.toInt()?.and(255) ?: return null
        val plain = if (last in 1..16 && clear.takeLast(last).all { (it.toInt() and 255) == last })
            clear.copyOf(clear.size-last) else clear
        return utf8(plain).let { if (p.id.startsWith("xhkypher")) it.take(32) else it }
    }

    private fun sensitive(value: String, p: RenzProfileStore.Profile): String? {
        if (p.id == "tcxtunnel") return try { utf8(main(value,p)) } catch (_: Exception) { null }
        val len = if (p.id == "cranetunnel") 16 else 32
        val salt = if (p.salt.isNotEmpty()) p.salt else ByteArray(len) { '0'.code.toByte() }
        val key = GenericVpnPort.pbkdf2Sha256(p.seed,salt,100_000,len)
        val xxtea = customXxtea(decodeBase64(value),key)
        val aes = cbc(xxtea,key,p.iv,unpad=false)
        require(aes.size >= 16)
        val pad = aes.last().toInt() and 255
        val end = if (pad in 1..aes.size) aes.size-pad else aes.size
        var result = aes.copyOfRange(16,maxOf(16,end))
        if (p.id != "cranetunnel") {
            // Python source removes trailing control bytes iteratively.
            repeat(16) {
                if (result.isEmpty()) return@repeat
                val count = result.last().toInt() and 255
                if (count > 31) return@repeat
                // Python b[:-0] is empty: preserve its historical behavior.
                result = if (count == 0) byteArrayOf()
                    else result.copyOf(maxOf(0,result.size-count))
            }
        }
        return utf8(result)
    }

    private fun deepDecrypt(el: JsonElement, p: RenzProfileStore.Profile) {
        when {
            el.isJsonArray -> el.asJsonArray.forEach { deepDecrypt(it,p) }
            el.isJsonObject -> {
                val obj = el.asJsonObject
                for ((key,value) in obj.entrySet().toList()) {
                    when {
                        value.isJsonObject || value.isJsonArray -> deepDecrypt(value,p)
                        value.isJsonPrimitive && value.asJsonPrimitive.isString -> {
                            val raw = value.asString
                            if (raw.length <= 20) continue
                            val plain = try {
                                when {
                                    p.id == "tcxtunnel" -> utf8(main(raw,p))
                                    "host" in key.lowercase(Locale.ROOT) ||
                                        "path" in key.lowercase(Locale.ROOT) -> special(raw,p)
                                    "username" in key.lowercase(Locale.ROOT) ||
                                        "password" in key.lowercase(Locale.ROOT) -> sensitive(raw,p)
                                    else -> {
                                        val first = try { utf8(main(raw,p)) }
                                            catch (_: Exception) { null }
                                        if (first.isNullOrEmpty()) special(raw,p) else first
                                    }
                                }
                            } catch (_: Exception) { null }
                            if (!plain.isNullOrEmpty()) obj.addProperty(key,plain)
                        }
                    }
                }
            }
        }
    }

    private fun deepTyped(el: JsonElement) {
        when {
            el.isJsonArray -> el.asJsonArray.forEach { deepTyped(it) }
            el.isJsonObject -> {
                val obj = el.asJsonObject
                for ((key,v) in obj.entrySet().toList()) {
                    if (v.isJsonObject || v.isJsonArray) { deepTyped(v); continue }
                    if (!v.isJsonPrimitive || !v.asJsonPrimitive.isString ||
                        v.asString.length <= 10) continue
                    val text = v.asString
                    var updated: String? = null
                    val candidates = listOfNotNull(
                        text.toByteArray(Charsets.UTF_8),
                        try { decodeBase64(text) } catch (_: Exception) { null }
                    )
                    loop@ for (type in 0..3) for (bytes in candidates) {
                        val clear = try { utf8(typeDecode(type,bytes)) } catch (_: Exception) { null }
                        if (clear != null && clear.length > 5 &&
                            !clear.trim().matches(Regex("[A-Za-z0-9+/=]+"))) {
                            updated = clear
                            break@loop
                        }
                    }
                    if (updated != null) obj.addProperty(key,updated)
                }
            }
        }
    }
}

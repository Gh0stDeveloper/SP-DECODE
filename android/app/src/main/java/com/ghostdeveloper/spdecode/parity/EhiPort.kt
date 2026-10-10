package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import android.util.Base64
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * HTTP Injector .ehi original bypass IV route:
 * Java UTF-8 container -> AES-256-CBC -> AES-128-CBC -> XXTEA
 * -> original field-local custom Base64 XOR decoding.
 * Standard IV path: authenticated Argon2id + XChaCha20-Poly1305 (24-byte nonce).
 * The original Python decoder is the parity reference, not a fallback engine.
 */
object EhiPort {
    private val p=LegacyPortPrimitives
    private val l1=p.hex("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c")
    private val l2=p.hex("b2bc617c32d8b9eb1943a5ffa8051eea")
    private val eoo="null=V5kU5+FFrY\u0000".toByteArray(Charsets.UTF_8)
    private val bypassIvs=listOf("221d572349555f1d112133236b1f4a3f",
        "5543494c53443e3f4a6a4539384e776a",
        "374c2541575e4d531a3c327b75431e5f").map{p.hex(it)}
    private val standardIvs=listOf("2c5d1147bbad422b3b334d4d235f1a53",
        "522b01433a5e8b2fc7549e1ad368e541",
        "337a1035aaedf3458ca167e92d74b839").map{p.hex(it)}
    private const val NORMAL="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private const val CUSTOM="RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
    private fun unwrap(input:ByteArray):ByteArray {
        p.bounded(input)
        val bb=ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN)
        fun readUtf():String {
            require(bb.remaining()>=2)
            val n=bb.short.toInt()and 65535
            require(bb.remaining()>=n)
            return p.utf8(ByteArray(n).also{bb.get(it)})
        }
        readUtf();require(bb.remaining()>=8);bb.position(bb.position()+8)
        readUtf();require(bb.remaining()>=12);bb.position(bb.position()+8)
        val n=bb.int;require(n in 1..p.MAX_INPUT && bb.remaining()>=8+n)
        bb.position(bb.position()+8)
        return ByteArray(n).also{bb.get(it)}
    }
    private fun words(raw:ByteArray):IntArray=IntArray((raw.size+3)/4){i->
        var v=0;for(j in 0..3)if(i*4+j<raw.size)
            v=v or ((raw[i*4+j].toInt()and 255) shl (j*8))
        v
    }
    private fun xxtea(input:ByteArray):ByteArray {
        val v=words(input)
        require(v.size>=2)
        val k=words(eoo.copyOf(16))
        val n=v.size
        var sum=(6+52/n)*0x9e3779b9.toInt()
        while(sum!=0){
            val e=(sum ushr 2)and 3
            var y=v[0]
            for(i in n-1 downTo 1){
                val z=v[i-1]
                val mx=(((z ushr 5) xor (y shl 2))+
                    ((y ushr 3) xor (z shl 4))) xor
                    ((sum xor y)+(k[(i and 3) xor e] xor z))
                y=v[i]-mx
                v[i]=y
            }
            val z=v[n-1]
            val mx=(((z ushr 5) xor (y shl 2))+
                ((y ushr 3) xor (z shl 4))) xor
                ((sum xor y)+(k[e] xor z))
            v[0]-=mx
            sum-=0x9e3779b9.toInt()
        }
        val bytes=ByteArray(n*4)
        v.forEachIndexed { i,num->for(j in 0..3)bytes[i*4+j]=(num ushr(8*j)).toByte()}
        val count=v[n-1].toLong() and 0xffffffffL
        return if(count>0 && count<=bytes.size)bytes.copyOf(count.toInt())
            else bytes.dropLastWhile{it==0.toByte()}.toByteArray()
    }
    private fun field(value:String,key:String):String? {
        if(value.isBlank())return value
        return try {
            val clean=value.reversed().replace("?","").map{ch->
                val n=CUSTOM.indexOf(ch)
                if(n>=0)NORMAL[n]else ch
            }.joinToString("")
            var hex=p.utf8(p.b64(clean))
            if(hex.length%2!=0)hex="0"+hex
            val raw=p.hex(hex);require(key.isNotEmpty())
            val decoded=ByteArray(raw.size) {i->
                (raw[i].toInt() xor key[i%key.length].code).toByte()
            }.filter{it!=0.toByte()}.toByteArray()
            p.utf8(decoded)
        }catch(_:Exception){null}
    }
    private fun configMessage(encoded: String): String {
        if (encoded.isBlank()) return encoded
        return try {
            val bytes = Base64.decode(encoded.padEnd((encoded.length + 3) / 4 * 4, '='), Base64.DEFAULT)
            val chars = String(bytes, Charsets.UTF_8).toCharArray()
            val salt = "EHIMSG"
            String(CharArray(chars.size) { i -> (chars[i].code xor salt[i % salt.length].code).toChar() })
        } catch (_: Exception) { encoded }
    }

    private fun pythonScalar(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "None"
        is Boolean -> if (value) "True" else "False"
        else -> value.toString()
    }

    /** Preserve the exact concatenation order and default timestamp zeroes. */
    private fun masterKey(config: JSONObject): ByteArray {
        val fields = listOf("configAesKey", "configIdentifier", "configSalt",
            "configTimestamp", "configExpiryTimestamp", "lockModes", "lockModesHash",
            "configHwid", "configLockMobileOperatorId")
        val parts = fields.mapIndexed { i, name ->
            val value = if (!config.has(name) && i in 3..4) 0 else config.opt(name) ?: ""
            pythonScalar(value).takeUnless { value == "" } ?: ""
        }
        return MessageDigest.getInstance("SHA-256")
            .digest(parts.joinToString("").toByteArray(Charsets.UTF_8))
    }

    private fun intLe(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 255) or
        ((bytes[offset + 1].toLong() and 255) shl 8) or
        ((bytes[offset + 2].toLong() and 255) shl 16) or
        ((bytes[offset + 3].toLong() and 255) shl 24)

    private fun le(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 255) or
        ((bytes[at+1].toInt() and 255) shl 8) or
        ((bytes[at+2].toInt() and 255) shl 16) or
        ((bytes[at+3].toInt() and 255) shl 24)

    private fun putLe(out: ByteArray, at: Int, word: Int) {
        for (i in 0..3) out[at+i] = (word ushr (8*i)).toByte()
    }

    /** HChaCha20 for the 24-byte XChaCha20 nonce used by PyCryptodome. */
    private fun subkey(key: ByteArray, nonce: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 24)
        val constants = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
        val words = IntArray(16) { i ->
            when {
                i < 4 -> constants[i]
                i < 12 -> le(key, (i - 4) * 4)
                else -> le(nonce, (i - 12) * 4)
            }
        }
        fun qr(a:Int,b:Int,c:Int,d:Int) {
            words[a] += words[b]
            words[d] = Integer.rotateLeft(words[d] xor words[a],16)
            words[c] += words[d]
            words[b] = Integer.rotateLeft(words[b] xor words[c],12)
            words[a] += words[b]
            words[d] = Integer.rotateLeft(words[d] xor words[a],8)
            words[c] += words[d]
            words[b] = Integer.rotateLeft(words[b] xor words[c],7)
        }
        repeat(10) {
            qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15)
            qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14)
        }
        return ByteArray(32).also { out ->
            val indices = intArrayOf(0,1,2,3,12,13,14,15)
            indices.forEachIndexed { i, index -> putLe(out, i * 4, words[index]) }
        }
    }

    private fun standard(config: JSONObject, salt: String): JSONObject {
        val encoded = config.optString("configData")
        require(encoded.isNotBlank())
        val decoded = field(encoded, salt) ?: error("Invalid configData")
        val raw = p.b64(decoded)
        require(raw.size > 50)
        val passes = intLe(raw,1)
        val memoryKiB = intLe(raw,5)
        val lanes = raw[9].toInt() and 255
        // Untrusted file parameters: do not permit memory/CPU exhaustion.
        require(lanes in 1..8 && passes in 1..8 &&
            memoryKiB in (8L * lanes)..65536L)
        val saltBytes = raw.copyOfRange(10,26)
        val nonce = raw.copyOfRange(26,50)
        val key = ByteArray(32)
        val master = masterKey(config)
        try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(saltBytes)
                .withIterations(passes.toInt())
                .withMemoryAsKB(memoryKiB.toInt())
                .withParallelism(lanes)
                .build()
            Argon2BytesGenerator().apply { init(params) }.generateBytes(master,key)
            val derived = subkey(key,nonce)
            try {
                val nonce12 = ByteArray(12).also { System.arraycopy(nonce,16,it,4,8) }
                val aad = raw.copyOfRange(0,26)
                val encrypted = raw.copyOfRange(50,raw.size)
                val cipher = ChaCha20Poly1305()
                cipher.init(false, AEADParameters(KeyParameter(derived),128,nonce12,aad))
                val output = ByteArray(cipher.getOutputSize(encrypted.size))
                val first = cipher.processBytes(encrypted,0,encrypted.size,output,0)
                val count = first + cipher.doFinal(output,first)
                return JSONObject(p.utf8(output.copyOf(count)))
            } finally { derived.fill(0) }
        } finally {
            key.fill(0)
            master.fill(0)
        }
    }

    fun decode(input:ByteArray):String?=p.safeDecode {
        val payload=unwrap(input)
        var profile:JSONObject?=null
        var bypass=false
        for(iv in bypassIvs+standardIvs) {
            val first=try{p.utf8(p.cbc(payload,l1,iv))}catch(_:Exception){continue}
            val parts=first.split(':')
            if(parts.size<3)continue
            val raw=try{
                p.cbc(p.b64(parts[2]),l2,p.b64(parts[0]))
            }catch(_:Exception){continue}
            val clear=xxtea(raw)
            val begin=clear.indexOf('{'.code.toByte())
            if(begin<0)continue
            profile=try{JSONObject(p.utf8(clear.copyOfRange(begin,clear.size)))}catch(_:Exception){null}
            if(profile!=null){bypass=bypassIvs.any{it.contentEquals(iv)};break}
        }
        val config=profile?:error("Unknown EHI envelope")
        val salt=config.optString("configSalt","EVZJNI")
        val parsed=if(bypass) config else standard(config,salt)
        val filtered=JSONObject()
        for(key in p.keys(parsed)){
            val v=parsed.get(key)
            if(v is String&&v.isNotBlank()){
                val decoded=if(key=="configMessage")configMessage(v) else field(v,salt)
                // EHI exporters do not encrypt every textual field. Older ports
                // silently dropped strings when the field-local XOR decoder
                // rejected plaintext or a newer representation. Preserve the
                // original value rather than emitting incomplete JSON; no
                // unrelated cipher, fabricated plaintext or key guessing.
                filtered.put(key,decoded ?: v)
            }else filtered.put(key,v)
        }
        FinalJsonSurface.render(".ehi",FinalJsonSurface.body(filtered),
            trailingNewline=true)
    }
}

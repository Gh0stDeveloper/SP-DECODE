package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * TLS Tunnel 8.5.0 offline AES-256-GCM importer.
 * Six extracted configuration keys are tried in the exact Python order;
 * profile 6 is the historic single-key format. Unknown field indices are
 * retained, with strict tag authentication (never partial plaintext).
 * Evidence for actual 8.5.0 sample is documented in the Python branch.
 */
object TlsReferencePort {
    private const val MAX_INPUT_BYTES = 1024 * 1024
    private const val MAX_OUTPUT_BYTES = 1024 * 1024
    private val b64Alphabet=Regex("^[A-Za-z0-9+/]*={0,2}$")

    fun decode(context: Context, input: ByteArray): String? {
        if (input.isEmpty() || input.size > MAX_INPUT_BYTES) return null
        return try {
            val configKeys = AdditionalDecoderMaterials.tls(context)
            val text = strictUtf8(input).trim()
            val noScheme = if (text.startsWith("tls://",ignoreCase=true))
                text.substring(6) else text
            val token = noScheme.filterNot { it.isWhitespace() }.substringBefore(':')
            if (token.isEmpty() || token.length > MAX_INPUT_BYTES * 2) return null
            val encoded = token.reversed()
            require(b64Alphabet.matches(encoded))
            val raw = Base64.decode(encoded.padEnd((encoded.length + 3) / 4 * 4, '='), Base64.DEFAULT)
            if (raw.size < 148 || raw.size > MAX_INPUT_BYTES) return null

            // The historical container is 12 bytes + C1 + IV1(18) +
            // C2 + IV2(18) + 84 bytes, with C1/C2 of equal length.
            val ciphertextLength = raw.size - 132
            if (ciphertextLength < 16) return null
            val half = ciphertextLength / 2
            val c1 = raw.copyOfRange(12, 12 + half).reversedArray()
            val iv1 = raw.copyOfRange(12 + half, 30 + half).reversedArray()
            val c2 = raw.copyOfRange(30 + half, 30 + ciphertextLength).reversedArray()
            val iv2 = raw.copyOfRange(30 + ciphertextLength, 48 + ciphertextLength).reversedArray()
            val encrypted = c1 + c2
            if (encrypted.size < 16) return null
            val nonce = iv1 + iv2
            var plaintext:ByteArray?=null
            var profile=0
            for((index,key) in configKeys.withIndex()) {
                try {
                    val cipher=Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),
                        GCMParameterSpec(128,nonce))
                    plaintext=cipher.doFinal(encrypted)
                    profile=index+1
                    break
                } catch (_: java.security.GeneralSecurityException) {
                    // Different Android JCA providers may report an invalid
                    // tag as AEADBadTagException or BadPaddingException.
                    // Try the next known profile; expose none until verified.
                }
            }
            val clear=plaintext?:return null
            if (clear.size > MAX_OUTPUT_BYTES) return null
            formatPayload(strictUtf8(clear),profile)
        } catch (_: Exception) {
            null
        }
    }

    private fun formatPayload(clear:String,profile:Int):String {
        val parts=clear.split(':')
        fun part(index:Int):String=parts.getOrElse(index){""}
        fun intValue(index:Int)=part(index).toIntOrNull()?:0
        fun boolValue(index:Int)=part(index).equals("true",ignoreCase=true)
        val base64Positions=setOf(4,5,6,7,9,12,14,16,18,19,24,27)
        fun decoded(index:Int):String {
            val value=part(index)
            if(value.isEmpty())return ""
            return try {
                require(b64Alphabet.matches(value) && value.length%4!=1)
                val data=Base64.decode(value.padEnd((value.length+3)/4*4,'='),
                    Base64.DEFAULT)
                strictUtf8(data)
            }catch(_:Exception){value} // preserve unknown/unreadable field
        }
        val fields=linkedMapOf<String,Any?>()
        fun keep(name:String,value:String){if(value.isNotEmpty())fields[name]=value}
        fields["tlsvpnVersion"]=intValue(0)
        fields["server"]=intValue(1)
        fields["port"]=intValue(2)
        fields["pserver"]=boolValue(3)
        keep("sshuser",decoded(4))
        keep("sshpass",decoded(5))
        keep("sshhost",decoded(6))
        keep("server_port",decoded(7))
        keep("sshport",decoded(9))
        fields["metodo"]=intValue(10)
        fields["upayload"]=boolValue(11)
        keep("payload",decoded(12))
        fields["usnihost"]=boolValue(13)
        keep("snihost",decoded(14))
        fields["upayloadat"]=boolValue(15)
        keep("payloadat",decoded(16))
        fields["uproxy"]=boolValue(17)
        keep("prxhost",decoded(18))
        keep("prxport",decoded(19))
        // In the v8.5.0 sample, indices 20-23 are booleans, not old DNS
        // parameters. The old names apply only to the historic profile 6.
        if(profile==6) {
            fields["legacy_dns_mode"]=intValue(20)
            keep("dnsP",decoded(21))
            keep("dns_port",decoded(22))
            keep("nameserver",decoded(23))
            keep("public_key",decoded(24))
        }
        fields["bloqmc"]=boolValue(25)
        keep("mensagem",decoded(27).replace("Ѻ","\n").replace("ѻ","\r"))
        if(profile!=6)fields["_tls"]=linkedMapOf<String,Any?>(
            "authenticated" to true,
            "key_profile" to profile,
            "field_count" to parts.size,
            "fields" to parts.mapIndexed { index,raw ->
                linkedMapOf<String,Any?>(
                    "index" to index,
                    "raw" to raw,
                    "value" to if(index in base64Positions)decoded(index) else raw,
                )
            }
        )
        return "TLS Tunnel\n==============================\n\n"+
            pretty(fields)+"\n\n=============================="
    }

    /** The JSON body exactly preserves Python insertion order and indent=4. */
    private fun pretty(value:Any?,depth:Int=0):String {
        require(depth<=48)
        val indent=" ".repeat(depth*4)
        val inner=" ".repeat((depth+1)*4)
        return when(value) {
            is Map<*,*> -> {
                if(value.isEmpty())"{}" else value.entries.joinToString(
                    separator=",\n",prefix="{\n",postfix="\n$indent}"
                ){ (k,v) -> inner+jsonQuote(k.toString())+": "+pretty(v,depth+1) }
            }
            is List<*> -> {
                if(value.isEmpty())"[]" else value.joinToString(
                    separator=",\n",prefix="[\n",postfix="\n$indent]"
                ){ inner+pretty(it,depth+1) }
            }
            is String -> jsonQuote(value)
            is Boolean -> if(value)"true" else "false"
            is Number -> value.toString()
            null -> "null"
            else -> jsonQuote(value.toString())
        }
    }

    /**
     * Python json.dumps(ensure_ascii=False) compatible string escaping.
     * Android's JSONObject.quote escapes '/', changing golden raw bytes.
     * Preserve slash and all non-control Unicode code points verbatim.
     */
    private fun jsonQuote(value: String): String = buildString {
        append('"')
        for (ch in value) {
            when (ch) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\t' -> append("\\t")
                '\n' -> append("\\n")
                '\u000C' -> append("\\f")
                '\r' -> append("\\r")
                else -> {
                    if (ch.code < 0x20) {
                        append("\\u")
                        append(ch.code.toString(16).padStart(4, '0'))
                    } else {
                        append(ch)
                    }
                }
            }
        }
        append('"')
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun strictUtf8(bytes: ByteArray): String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
}

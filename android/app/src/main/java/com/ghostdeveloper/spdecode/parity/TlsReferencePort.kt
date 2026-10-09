package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Offline JCA reference port for the *synthetic* TLS Tunnel AES-256-GCM case.
 *
 * Does not imply compatibility with current third-party exporter versions.
 * A failed authentication tag is always an error, never partial plaintext.
 */
object TlsReferencePort {
    private const val MAX_INPUT_BYTES = 1024 * 1024
    private const val MAX_OUTPUT_BYTES = 1024 * 1024
    private const val KEY_HEX =
        "6b303068c2acc2b9c2b221352473c2b0c2b725c2a824614b674433c2b0467856"

    fun decode(input: ByteArray): String? {
        if (input.isEmpty() || input.size > MAX_INPUT_BYTES) return null
        return try {
            val text = strictUtf8(input).trim()
            val noScheme = if ("://" in text) text.substringAfter("://") else text
            val token = noScheme.filterNot { it.isWhitespace() }.substringBefore(':')
            if (token.isEmpty() || token.length > MAX_INPUT_BYTES * 2) return null
            val encoded = token.reversed()
            val raw = Base64.decode(encoded.padEnd((encoded.length + 3) / 4 * 4, '='), Base64.DEFAULT)
            if (raw.size < 148 || raw.size > MAX_INPUT_BYTES) return null

            // The historical container is 12 bytes + C1 + IV1(18) +
            // C2 + IV2(18) + 84 bytes, with C1/C2 of equal length.
            val ciphertextLength = raw.size - 132
            if (ciphertextLength < 16 || ciphertextLength % 2 != 0) return null
            val half = ciphertextLength / 2
            val c1 = raw.copyOfRange(12, 12 + half).reversedArray()
            val iv1 = raw.copyOfRange(12 + half, 30 + half).reversedArray()
            val c2 = raw.copyOfRange(30 + half, 30 + ciphertextLength).reversedArray()
            val iv2 = raw.copyOfRange(30 + ciphertextLength, 48 + ciphertextLength).reversedArray()
            val encrypted = c1 + c2
            if (encrypted.size < 16) return null
            val nonce = iv1 + iv2
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(hex(KEY_HEX), "AES"),
                GCMParameterSpec(128, nonce),
            )
            val clear = cipher.doFinal(encrypted) // ciphertext + 128-bit authentication tag
            if (clear.size > MAX_OUTPUT_BYTES) return null
            formatPayload(strictUtf8(clear))
        } catch (_: Exception) {
            null
        }
    }

    private fun formatPayload(clear: String): String {
        val parts = clear.split(':')
        fun part(index: Int): String = parts.getOrElse(index) { "" }
        fun intValue(index: Int): Int = part(index).toIntOrNull() ?: 0
        fun boolValue(index: Int): Boolean = part(index).equals("true", ignoreCase = true)
        fun decoded(index: Int): String {
            val value = part(index)
            if (value.isEmpty()) return ""
            return try {
                val padded = value.padEnd((value.length + 3) / 4 * 4, '=')
                strictUtf8(Base64.decode(padded, Base64.DEFAULT))
            } catch (_: Exception) { "" }
        }

        // Preserve the Python insertion order and only drop empty STRINGS.
        // Integer zero and boolean false are meaningful and must be retained.
        val fields = linkedMapOf<String, Any>()
        fun keep(name: String, value: String) { if (value.isNotEmpty()) fields[name] = value }
        fields["tlsvpnVersion"] = intValue(0)
        fields["server"] = intValue(1)
        fields["port"] = intValue(2)
        fields["pserver"] = boolValue(3)
        keep("sshuser", decoded(4))
        keep("sshpass", decoded(5))
        keep("sshhost", decoded(6))
        keep("server_port", decoded(7))
        keep("sshport", decoded(9))
        fields["metodo"] = intValue(10)
        fields["upayload"] = boolValue(11)
        keep("payload", decoded(12))
        fields["usnihost"] = boolValue(13)
        keep("snihost", decoded(14))
        fields["upayloadat"] = boolValue(15)
        keep("payloadat", decoded(16))
        fields["uproxy"] = boolValue(17)
        keep("prxhost", decoded(18))
        keep("prxport", decoded(19))
        fields["legacy_dns_mode"] = intValue(20)
        keep("dnsP", decoded(21))
        keep("dns_port", decoded(22))
        keep("nameserver", decoded(23))
        keep("public_key", decoded(24))
        fields["bloqmc"] = boolValue(25)
        keep("mensagem", decoded(27).replace("Ѻ", "\n").replace("ѻ", "\r"))

        return buildString {
            append("TLS Tunnel\n==============================\n\n{\n")
            fields.entries.forEachIndexed { index, (key, value) ->
                append("    ").append(JSONObject.quote(key)).append(": ")
                when (value) {
                    is String -> append(JSONObject.quote(value))
                    is Boolean -> append(if (value) "true" else "false")
                    else -> append(value.toString())
                }
                if (index < fields.size - 1) append(',')
                append('\n')
            }
            append("}\n\n==============================")
        }
    }

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }

    private fun strictUtf8(bytes: ByteArray): String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()
}

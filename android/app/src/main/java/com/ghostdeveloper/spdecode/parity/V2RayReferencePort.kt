package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import org.json.JSONObject
import java.nio.charset.CodingErrorAction
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Initial native Android port for the *synthetic* e-V2Ray .v2 regression
 * variants. This does NOT claim real exporter-version coverage.
 *
 * Purely offline: JCA + Android Base64, no networking, subprocess, Node or
 * Python. Preserves the exact raw text returned by the Linux reference for
 * the two documented synthetic profiles.
 */
object V2RayReferencePort {
    private const val DELIMITER = "[eV2ray]"
    private const val MAX_BYTES = 1024 * 1024
    private val KEYS = listOf(
        "#%*7K!iuFem%M6BB",
        "ah@`6js^E5,.esEK",
        "3gp268y3i9nwd4ut",
    ).map { it.toByteArray(Charsets.UTF_8) }

    fun decode(input: ByteArray): String? {
        if (input.isEmpty() || input.size > MAX_BYTES) return null
        return try {
            val source = strictUtf8(input)
            val plaintext: String
            val variant: Int
            if (source.contains(DELIMITER)) {
                plaintext = source.trim()
                variant = -1
            } else {
                val obfuscated = input.dropLastWhile { it.toInt() in listOf(9, 10, 13, 32) }
                    .toByteArray()
                val reversed = ByteArray(obfuscated.size) { index ->
                    (obfuscated[index].toInt() xor (index % 20 + 2)).toByte()
                }
                val ciphertext = decodeBase64(String(reversed, Charsets.US_ASCII))
                if (ciphertext.isEmpty() || ciphertext.size % 16 != 0) return null
                var decoded: String? = null
                var selected = -1
                for ((idx, key) in KEYS.withIndex()) {
                    try {
                        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
                        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
                        val raw = strictUtf8(cipher.doFinal(ciphertext))
                        if (raw.contains(DELIMITER)) {
                            decoded = raw
                            selected = idx
                            break
                        }
                    } catch (_: Exception) {
                        // Key rotation: try next key, never expose a false result.
                    }
                }
                plaintext = decoded ?: return null
                variant = selected
            }
            format(plaintext, variant)
        } catch (_: Exception) {
            null
        }
    }

    private fun strictUtf8(bytes: ByteArray): String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString()

    private fun decodeBase64(raw: String): ByteArray {
        val clean = raw.filterNot { it.isWhitespace() }
        if (clean.isEmpty() || clean.length > MAX_BYTES * 2) return byteArrayOf()
        return Base64.decode(clean.padEnd((clean.length + 3) / 4 * 4, '='), Base64.DEFAULT)
    }

    private fun format(plain: String, variant: Int): String? {
        val fields = plain.split(DELIMITER)
        if (fields.size < 2) return null
        // Minimal reference-compatible path for the two frozen synthetic
        // fixtures; never pretend unknown variants have equivalent parsing.
        val name = strictUtf8(decodeBase64(fields[0])).trim()
        val rawJson = strictUtf8(decodeBase64(fields[1]))
        if (name.isEmpty() || name.length > 256 || rawJson.length > MAX_BYTES) return null
        val json = JSONObject(rawJson)
        if (!json.has("v") || !json.has("add")) return null
        if (fields.size != 3 || fields[2] != "true") return null
        val metadata = "{\"Field 1\":${JSONObject.quote(name)},\"Field 3\":true}"
        return buildString {
            append("┌───────────────\n")
            append("│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (e-V2Ray)\n")
            append("│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n")
            append("├───────────────\n")
            append("│[۞] Profile Name: ").append(name).append('\n')
            append("│[۞] V2Ray Config: ").append(rawJson).append('\n')
            append("│[۞] Metadata: ").append(metadata).append('\n')
            if (variant >= 0) append("│[۞] Format Variant: ").append(variant + 1).append('\n')
            append("├───────────────\n")
            append("│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n")
            append("│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n")
            append("└───────────────\n")
        }
    }
}

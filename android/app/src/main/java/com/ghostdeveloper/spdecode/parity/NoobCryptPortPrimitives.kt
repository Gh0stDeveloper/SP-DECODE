package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject

/**
 * Port of the original decoders/Python/_noobcrypt.py implementation.
 * Two caller decoders supply different authoritative keys, never a
 * guessed password or a recovered key from unrelated extensions.
 */
internal object NoobCryptPortPrimitives {
    private val p = LegacyPortPrimitives

    fun decode(input: ByteArray, keyHex: String, suffix: String, app: String): String {
        p.bounded(input)
        val key = p.hex(keyHex)
        require(key.size == 32)
        val raw = p.b64(p.utf8(input))
        require(raw.size >= 32 && (raw.size - 16) % 16 == 0)
        val decrypted = p.utf8(p.cbc(raw.copyOfRange(16, raw.size),
            key, raw.copyOfRange(0, 16)))
        val start = decrypted.indexOf('{')
        require(start >= 0 && decrypted.trimEnd().endsWith('}'))
        val payload = JSONObject(decrypted.substring(start))
        require(payload.length() > 0)
        val fields = recursive(payload, key, 0)
        return "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.$suffix)\n" +
            "│[۞] Aplicación: $app\n├───────────────\n" +
            p.prettyJson(fields) + "\n└───────────────\n\n"
    }

    private fun recursive(value: Any, key: ByteArray, depth: Int): Any {
        require(depth <= 32)
        return when (value) {
            is JSONObject -> {
                val out = JSONObject()
                for (field in p.keys(value)) {
                    out.put(field, recursive(value.get(field), key, depth + 1))
                }
                out
            }
            is JSONArray -> {
                val out = JSONArray()
                for (index in 0 until value.length()) {
                    out.put(recursive(value.get(index), key, depth + 1))
                }
                out
            }
            is String -> {
                if (value.isEmpty() || value.length < 36) return value
                try {
                    val encoded = value.filterNot { it.isWhitespace() }
                    val bytes = p.b64(encoded)
                    if (bytes.size < 28) value else p.utf8(p.gcm(
                        bytes.copyOfRange(12, bytes.size), key,
                        bytes.copyOfRange(0, 12)))
                } catch (_: Exception) {
                    // Original _noobcrypt preserves an unrecognized string.
                    value
                }
            }
            else -> value
        }
    }
}

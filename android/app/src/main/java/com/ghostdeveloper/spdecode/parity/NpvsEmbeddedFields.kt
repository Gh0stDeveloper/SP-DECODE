package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * Native equivalent of Python npvs.py::_decode_embedded_npvs1.
 *
 * Only explicit npvs1: wrappers are Base64-decoded. Base64-looking credentials
 * without that marker must remain byte-for-byte unchanged. This transformation
 * runs AFTER the signed NPVS envelope and authenticated field inventory pass.
 */
internal object NpvsEmbeddedFields {
    private const val MAX_DEPTH = 64
    private const val PREFIX = "npvs1:"
    private val BASE64_CHARS = Regex("^[A-Za-z0-9+/_-]+={0,2}$")

    fun unwrap(value: Any?, depth: Int = 0): Any? {
        require(depth <= MAX_DEPTH) { "Nested NPVS field encoding exceeds maximum depth" }
        return when (value) {
            is JSONObject -> JSONObject().also { result ->
                for (name in LegacyPortPrimitives.keys(value)) {
                    result.put(name, unwrap(value.get(name), depth + 1))
                }
            }
            is JSONArray -> JSONArray().also { result ->
                for (index in 0 until value.length()) {
                    result.put(unwrap(value.get(index), depth + 1))
                }
            }
            is String -> if (value.startsWith(PREFIX)) {
                decodeWrapped(value, depth)
            } else value
            else -> value
        }
    }

    private fun decodeWrapped(value: String, depth: Int): Any {
        // Python uses "".join(value[6:].split()) before strict Base64 parsing.
        val token = value.substring(PREFIX.length).filterNot { it.isWhitespace() }
        require(token.isNotEmpty() && token.length <= 2 * NpvsPort.MAX_INPUT) {
            "Invalid NPVS embedded Base64 field size"
        }
        require(BASE64_CHARS.matches(token)) { "Invalid NPVS embedded Base64 characters" }
        val unpadded = token.trimEnd('=')
        require(unpadded.length % 4 != 1) { "Invalid NPVS embedded Base64 length" }
        val payload = token.replace('-', '+').replace('_', '/')
            .padEnd((token.length + 3) / 4 * 4, '=')
        // Character/length validation above compensates for Android's lenient
        // Base64 decoder; this is not a heuristic decode of unmarked strings.
        val decoded = Base64.decode(payload, Base64.NO_WRAP)
        val text = LegacyPortPrimitives.utf8(decoded) // strict UTF-8, no replacement chars

        if (text.startsWith(PREFIX)) return unwrap(text, depth + 1)!!
        if (text.trimStart().startsWith('{') || text.trimStart().startsWith('[')) {
            // A plaintext string may begin with a brace: match Python by
            // retaining the string when it is not a complete JSON document.
            val nested = try {
                NpvsJson.parse(decoded)
            } catch (_: Exception) {
                null
            }
            if (nested is JSONObject || nested is JSONArray) {
                return unwrap(nested, depth + 1)!!
            }
        }
        return text
    }
}

package com.ghostdeveloper.spdecode.parity

import android.content.Context
import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Phase B: the ONLY generic VPN native decoding entrypoint.
 *
 * Mirrors Python generic_aes.py and generic_des.py, including 1000 rounds
 * PBKDF2-HMAC-SHA256 over raw password bytes, 16-byte AES-GCM keys and strict
 * authentication, and the legacy DES-first route for the six dual profiles.
 *
 * This class NEVER guesses passwords from another suffix and never logs keys,
 * source configuration, plain text, or failed authentication material.
 */
object GenericVpnPort {
    const val MAX_INPUT_BYTES = 2 * 1024 * 1024
    private val json = GsonBuilder()
        .disableHtmlEscaping().serializeNulls().setPrettyPrinting().create()
    private val entry = Regex(
        """<entry\s+key\s*=\s*["'](?<key>[^"']+)["']\s*(?:>(?<value>.*?)</entry\s*>|/>)""",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )

    fun decode(context: Context, suffix: String, input: ByteArray): String? {
        if (input.isEmpty() || input.size > MAX_INPUT_BYTES) return null
        val profile = try {
            GenericProfileStore.profile(context, suffix)
        } catch (_: IllegalArgumentException) {
            return null
        } catch (_: org.json.JSONException) {
            return null
        } ?: return null

        // Source selection: DES first, only when the same suffix has DES
        // and the decrypted bytes are credible XML/JSON. AES-GCM is the
        // authenticated fallback for exactly the six dual-profile suffixes.
        if (profile.desPassword != null) {
            val desPlain = decryptDes(input, profile.desPassword)
            if (desPlain != null) return render(desPlain)
        }
        if (profile.aesPasswords.isEmpty()) return null
        val aesPlain = decryptAes(input, profile.aesPasswords) ?: return null
        return render(aesPlain)
    }

    private fun decryptAes(input: ByteArray, passwords: List<ByteArray>): String? {
        val parts = try {
            val text = decodeUtf8Strict(input).trim()
            val parts = text.split(".")
            if (parts.size != 3) return null
            parts.map { value ->
                // Python uses b"".join(value.split()) for Base64 segments.
                GenericProfileStore.strictBase64(
                    value.filterNot(Char::isWhitespace)
                )
            }
        } catch (_: IllegalArgumentException) {
            return null
        } catch (_: java.nio.charset.CharacterCodingException) {
            return null
        }
        val salt = parts[0]
        val nonce = parts[1]
        val ciphertext = parts[2]
        if (salt.size !in 1..128 || nonce.size !in 1..128 ||
            ciphertext.size <= 16) return null
        for (password in passwords) {
            if (password.isEmpty()) continue
            var key: ByteArray? = null
            try {
                key = pbkdf2Sha256(password, salt, 1000, 16)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
                val clear = decodeUtf8Strict(cipher.doFinal(ciphertext))
                if (clear.isNotBlank()) return clear
            } catch (_: GeneralSecurityException) {
                // Wrong password, malformed ciphertext, bad GCM tag or a
                // device provider rejecting an unsupported historical nonce.
            } catch (_: IllegalArgumentException) {
                // Invalid encoded key/nonce parameters.
            } catch (_: java.nio.charset.CharacterCodingException) {
                // Unlike String(bytes,UTF8), never replace damaged bytes.
            } finally {
                key?.fill(0)
            }
        }
        return null
    }

    private fun decryptDes(input: ByteArray, password: ByteArray): String? {
        if (password.isEmpty()) return null
        val key = ByteArray(8)
        password.copyInto(key, endIndex = minOf(8, password.size))
        try {
            val candidates = mutableListOf(input)
            val base64 = try {
                // Python accepts Base64-wrapped binary as a compatibility
                // variant and uses the same XML/JSON credibility gate.
                val compact = decodeUtf8Strict(input)
                    .filterNot(Char::isWhitespace)
                GenericProfileStore.strictBase64(compact)
            } catch (_: IllegalArgumentException) {
                null
            } catch (_: java.nio.charset.CharacterCodingException) {
                null
            }
            if (base64 != null && !base64.contentEquals(input)) {
                candidates.add(base64)
            }
            val cipher = Cipher.getInstance("DES/ECB/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "DES"))
            for (candidate in candidates) {
                if (candidate.size < 8 || candidate.size % 8 != 0) continue
                val clear = try {
                    decodeUtf8Strict(cipher.doFinal(candidate)).trim()
                } catch (_: GeneralSecurityException) {
                    continue
                } catch (_: java.nio.charset.CharacterCodingException) {
                    continue
                }
                if (clear.isBlank()) continue
                if (entry.containsMatchIn(clear)) return clear
                if (isJsonContainer(clear)) return clear
            }
        } catch (_: GeneralSecurityException) {
            return null
        } finally {
            key.fill(0)
        }
        return null
    }

    /**
     * Avoid SecretKeyFactory/PBEKeySpec char[] encoding differences.
     * The Python reference uses PBKDF2(password: bytes) directly; this
     * implementation accepts the same byte strings, including 0x01.
     */
    internal fun pbkdf2Sha256(
        password: ByteArray, salt: ByteArray, iterations: Int, length: Int,
    ): ByteArray {
        require(password.isNotEmpty() && salt.isNotEmpty())
        require(iterations in 1..100_000 && length in 1..32)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        val block = ByteArray(salt.size + 4)
        salt.copyInto(block)
        block[block.lastIndex] = 1
        var u = mac.doFinal(block)
        val result = u.clone()
        repeat(iterations - 1) {
            u = mac.doFinal(u)
            for (i in result.indices) {
                result[i] = (result[i].toInt() xor u[i].toInt()).toByte()
            }
        }
        u.fill(0)
        block.fill(0)
        return result.copyOf(length).also { result.fill(0) }
    }

    private fun decodeUtf8Strict(data: ByteArray): String =
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(data)).toString()

    private fun isJsonContainer(text: String): Boolean = try {
        val parsed = JsonParser.parseString(text)
        parsed.isJsonObject || parsed.isJsonArray
    } catch (_: RuntimeException) {
        false
    }

    /** Render exactly the content, including duplicate/empty XML values. */
    private fun render(plain: String): String {
        try {
            return json.toJson(JsonParser.parseString(plain))
        } catch (_: RuntimeException) {
            // Valid non-JSON decrypted text is still meaningful.
        }
        val matches = entry.findAll(plain).toList()
        if (matches.isEmpty()) return plain
        val allEntries = JsonArray()
        for (match in matches) {
            val item = JsonObject()
            item.addProperty("key", match.groups["key"]!!.value)
            item.addProperty("value", match.groups["value"]?.value ?: "")
            allEntries.add(item)
        }
        val result = JsonObject()
        result.add("entries", allEntries)
        result.addProperty("raw_xml", plain)
        return json.toJson(result)
    }
}

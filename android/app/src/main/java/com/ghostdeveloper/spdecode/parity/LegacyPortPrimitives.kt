package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Only the standard cryptographic primitives and byte-preserving formatting
 * are shared. Each named decoder retains its own container, key and formatter.
 * No guessing a format from cryptographic success. Offline JCA only.
 */
internal object LegacyPortPrimitives {
    const val MAX_INPUT = 1024 * 1024
    private const val MAX_CLEAR = 1024 * 1024
    private val BASE64_PATTERN = Regex("^[A-Za-z0-9+/]*={0,2}$")

    fun bounded(input: ByteArray) {
        require(input.isNotEmpty() && input.size <= MAX_INPUT) { "Input exceeds byte limit" }
    }

    fun utf8(data: ByteArray): String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(data)).toString()

    fun b64(encoded: String): ByteArray {
        val clean = encoded.filterNot { it.isWhitespace() }
        require(clean.isNotEmpty() && clean.length <= MAX_INPUT * 2)
        val unpadded = clean.trimEnd('=')
        require(BASE64_PATTERN.matches(clean))
        require(unpadded.length % 4 != 1)
        return Base64.decode(clean.padEnd((clean.length + 3) / 4 * 4, '='), Base64.DEFAULT)
    }

    fun hex(value: String): ByteArray {
        require(value.length % 2 == 0 && value.length <= MAX_INPUT * 2)
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    fun cbc(ciphertext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        require(iv.size == 16 && ciphertext.isNotEmpty() &&
            ciphertext.size <= MAX_INPUT && ciphertext.size % 16 == 0)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(ciphertext).also { require(it.size <= MAX_CLEAR) }
    }

    fun gcm(ciphertextAndTag: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
        require(ciphertextAndTag.size >= 16 && ciphertextAndTag.size <= MAX_INPUT)
        require(nonce.size in 8..32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertextAndTag).also { require(it.size <= MAX_CLEAR) }
    }

    // PyCryptodome: PBKDF2(password, salt, dkLen=16, count=1000, hmac_hash_module=SHA256).
    fun pbkdf2Sha256(password: String, salt: ByteArray): ByteArray {
        require(salt.isNotEmpty() && salt.size <= 256)
        val spec = PBEKeySpec(password.toCharArray(), salt, 1000, 128)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally { spec.clearPassword() }
    }

    fun dotGcm(input: ByteArray, password: String): String {
        bounded(input)
        val parts = utf8(input).trim().split('.')
        require(parts.size == 3)
        val salt = b64(parts[0])
        val nonce = b64(parts[1])
        val contents = b64(parts[2])
        return utf8(gcm(contents, pbkdf2Sha256(password, salt), nonce))
    }

    fun header(suffix: String, leadingLine: Boolean = false): String =
        (if (leadingLine) "\n" else "") +
        "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 $suffix\n" +
        "│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────"

    fun footer(channel: String = "@GhostDeve"): String =
        "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n" +
        "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : $channel\n└───────────────\n\n"

    /**
     * Python's print()-stdout rules are preserved, including legacy empty
     * lines and order. Only syntactically recognized XML <entry> lines render.
     */
    fun simpleEntries(xml: String, strictStartsWith: Boolean = false,
                      phcStyle: Boolean = false): String {
        val ordered = linkedMapOf<String, String>()
        for (original in xml.split('\n')) {
            val line = if (strictStartsWith) original else original.trim()
            if (!line.startsWith("<entry")) continue
            val tokens = line.replace("<entry key=\"", "")
                .replace("</entry" + if (phcStyle) "" else ">", "")
                .replace(if (phcStyle) "" else "\"/>", "")
                .split("\">", limit = 2)
            val name: String
            val value: String
            if (tokens.size > 1) {
                name = tokens[0]
                value = if (phcStyle) tokens[1].trim('>') else tokens[1]
            } else {
                name = tokens[0].trim('"', '/', '>')
                value = if (phcStyle) " ***" else "***"
            }
            ordered[name] = value
        }
        return ordered.entries.joinToString("") { (key,value) -> "│[۞] $key: $value\n" }
    }

    fun pythonValue(value: Any?): String = when (value) {
        null, JSONObject.NULL -> "None"
        is Boolean -> if (value) "True" else "False"
        is String -> value
        else -> value.toString()
    }

    fun keys(obj: JSONObject): List<String> {
        val items = mutableListOf<String>()
        val it = obj.keys()
        while (it.hasNext()) items.add(it.next())
        return items
    }

    fun jsonQuote(value: String): String = buildString {
        append('"')
        for (char in value) {
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\t' -> append("\\t")
                '\n' -> append("\\n")
                '\u000C' -> append("\\f")
                '\r' -> append("\\r")
                else -> {
                    if (char.code < 32) {
                        append("\\u")
                        append(char.code.toString(16).padStart(4, '0'))
                    } else append(char)
                }
            }
        }
        append('"')
    }

    fun prettyJson(value: Any?, depth: Int = 0): String {
        require(depth <= 32)
        val indentation = " ".repeat(depth * 4)
        val childIndent = " ".repeat((depth + 1) * 4)
        return when (value) {
            is JSONObject -> {
                val fields = keys(value)
                if (fields.isEmpty()) "{}" else fields.joinToString(
                    ",\n", "{\n", "\n$indentation}"
                ) { k -> childIndent + jsonQuote(k) + ": " + prettyJson(value.get(k), depth + 1) }
            }
            is JSONArray -> {
                if (value.length() == 0) "[]" else (0 until value.length()).joinToString(
                    ",\n", "[\n", "\n$indentation]"
                ) { i -> childIndent + prettyJson(value.get(i), depth + 1) }
            }
            is String -> jsonQuote(value)
            null, JSONObject.NULL -> "null"
            is Boolean -> if (value) "true" else "false"
            else -> value.toString()
        }
    }

    fun safeDecode(block: () -> String): String? =
        try { block().takeIf { it.isNotEmpty() && it.length <= MAX_CLEAR } }
        catch (_: Exception) { null }
}

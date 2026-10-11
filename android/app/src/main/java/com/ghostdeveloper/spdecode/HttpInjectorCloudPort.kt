package com.ghostdeveloper.spdecode

import android.content.Context
import android.util.Base64
import com.ghostdeveloper.spdecode.parity.EhiPort
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.URI
import java.net.URLEncoder
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.DataFormatException
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection

/**
 * HTTP Injector cloud import (6.5.0/244). Online by explicit user action only.
 * Does not alter existing offline decoders or TextProtocolDecoder.
 *
 * Reference protocol constants below are taken from the attached public
 * research scripts. They are embedded protocol material, NOT private user
 * credentials, and are extractable from client APKs. Server compatibility
 * and authorization are controlled by the independent remote provider.
 */
internal object HttpInjectorCloudPort {
    private const val ENDPOINT = "https://www.ehi.tools/httpinjector/import_config"
    private const val BUILD = "244"
    private const val SIGN_KEY = "xn1WSCjY25RKW1pDQr0s3cdg6VSiQLb0"
    private const val RESPONSE_KEY = "GialHt24BQOZ+pwUE2++82H/EtnTqFh4"
    private const val MAX_BYTES = 8 * 1024 * 1024
    private const val EMOJI_OFFSET = 128467
    private const val EMOJI_BEGIN = 0x1F489
    private const val EMOJI_END = 0x1F680
    private val keyPattern = Regex("[A-Za-z0-9_]{1,128}")
    private val base64Alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    private val utf8 = StandardCharsets.UTF_8

    internal enum class Reason { REFERENCE, NETWORK, SERVER, INTEGRITY, DECODER }
    internal class CloudException(val reason: Reason) : Exception("Cloud import failed: $reason")

    fun parseReference(input: String): String {
        val reference = input.trim().removePrefix("\uFEFF")
        if (reference.length > 1024) throw CloudException(Reason.REFERENCE)
        if (reference.codePointCount(0, reference.length) >= 2 &&
            reference.codePointAt(0) == EMOJI_BEGIN &&
            reference.codePointBefore(reference.length) == EMOJI_END) {
            return emojiReference(reference)
        }
        if (keyPattern.matches(reference)) return reference
        val url = try { URI(reference) } catch (_: Exception) {
            throw CloudException(Reason.REFERENCE)
        }
        if ((url.scheme != "https" && url.scheme != "ehi") ||
            url.host != "ehi.link" || url.port != -1 ||
            url.rawUserInfo != null || url.rawQuery != null || url.rawFragment != null ||
            !url.rawPath.startsWith("/")) throw CloudException(Reason.REFERENCE)
        val key = url.rawPath.substring(1)
        if (!keyPattern.matches(key)) throw CloudException(Reason.REFERENCE)
        return key
    }

    private fun emojiReference(token: String): String {
        val end = token.offsetByCodePoints(0, token.codePointCount(0, token.length) - 1)
        var index = Character.charCount(EMOJI_BEGIN)
        val encoded = StringBuilder()
        while (index < end) {
            val point = token.codePointAt(index)
            val ascii = point - EMOJI_OFFSET
            if (ascii !in 0..127 || base64Alphabet.indexOf(ascii.toChar()) < 0)
                throw CloudException(Reason.REFERENCE)
            encoded.append(ascii.toChar())
            index += Character.charCount(point)
        }
        val canonical = encoded.toString()
        val bytes = strictBase64(canonical, MAX_BYTES, Reason.REFERENCE)
        return try {
            val decoder = utf8.newDecoder()
            val clear = decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
            if (!keyPattern.matches(clear)) throw CloudException(Reason.REFERENCE)
            clear
        } catch (_: java.nio.charset.CharacterCodingException) {
            throw CloudException(Reason.REFERENCE)
        } finally {
            bytes.fill(0)
        }
    }

    private fun strictBase64(text: String, maxSize: Int, problem: Reason): ByteArray {
        if (text.isEmpty() || text.length > maxSize * 2 || text.length % 4 != 0 ||
            text.any { it !in base64Alphabet }) throw CloudException(problem)
        val bytes = try { Base64.decode(text, Base64.NO_WRAP) } catch (_: Exception) {
            throw CloudException(problem)
        }
        if (bytes.isEmpty() || bytes.size > maxSize ||
            Base64.encodeToString(bytes, Base64.NO_WRAP) != text) {
            bytes.fill(0)
            throw CloudException(problem)
        }
        return bytes
    }

    private fun hex(data: ByteArray): String =
        data.joinToString("") { "%02X".format(it.toInt() and 255) }

    private fun digest(name: String, value: String): String =
        hex(MessageDigest.getInstance(name).digest(value.toByteArray(utf8)))

    private fun enc(value: String): String =
        URLEncoder.encode(value, "UTF-8").replace("+", "%2B")

    internal fun signedRequest(key: String, timestamp: Long, nonce: String,
        identity: String): Pair<ByteArray, Map<String, String>> {
        if (!keyPattern.matches(key)) throw CloudException(Reason.REFERENCE)
        val headers = linkedMapOf(
            "x-nonce" to nonce,
            "x-timestamp" to timestamp.toString(),
            "x-sign-version" to "1.0",
            "x-uid" to digest("SHA-1", identity),
            "x-did" to digest("MD5", identity),
            "x-platform" to "android",
            "x-device" to "Android",
            "x-os-api" to "35",
            "x-app-build" to BUILD,
        )
        val canonicalFields = (headers + ("config_key" to key))
            .toSortedMap().entries.joinToString("&") { (name, value) -> "$name=$value" }
        val message = listOf("POST", ENDPOINT, canonicalFields)
            .joinToString("&") { enc(it) }
        val signatureKey = (enc("-1") + "&" + enc(SIGN_KEY)).toByteArray(utf8)
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(signatureKey, "HmacSHA1"))
        val signature = mac.doFinal(message.toByteArray(utf8))
        signatureKey.fill(0)
        headers["x-signature"] = enc(Base64.encodeToString(signature, Base64.NO_WRAP))
        signature.fill(0)
        return ("config_key=" + key).toByteArray(StandardCharsets.US_ASCII) to headers
    }

    private fun fetch(key: String): ByteArray {
        val (body, headers) = signedRequest(key, System.currentTimeMillis() / 1000,
            UUID.randomUUID().toString(), UUID.randomUUID().toString())
        val connection = (URL(ENDPOINT).openConnection() as HttpsURLConnection)
        try {
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10000
            connection.readTimeout = 20000
            connection.doOutput = true
            headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("User-Agent", "okhttp/4.12.0")
            connection.outputStream.use { it.write(body) }
            if (connection.responseCode != 200) throw CloudException(Reason.SERVER)
            val output = ByteArrayOutputStream()
            connection.inputStream.use { stream ->
                val chunk = ByteArray(8192)
                while (true) {
                    val n = stream.read(chunk)
                    if (n < 0) break
                    if (output.size() + n > MAX_BYTES) throw CloudException(Reason.SERVER)
                    output.write(chunk, 0, n)
                }
            }
            return output.toByteArray()
        } catch (e: CloudException) {
            throw e
        } catch (_: Exception) {
            throw CloudException(Reason.NETWORK)
        } finally {
            body.fill(0)
            connection.disconnect()
        }
    }

    private fun inflateStrict(compressed: ByteArray): ByteArray {
        val inflater = Inflater()
        val output = ByteArrayOutputStream()
        try {
            inflater.setInput(compressed)
            val buffer = ByteArray(8192)
            while (!inflater.finished()) {
                val n = try { inflater.inflate(buffer) }
                    catch (_: DataFormatException) { throw CloudException(Reason.INTEGRITY) }
                if (n == 0) throw CloudException(Reason.INTEGRITY)
                if (output.size() + n > MAX_BYTES) throw CloudException(Reason.INTEGRITY)
                output.write(buffer, 0, n)
            }
            if (inflater.remaining != 0) throw CloudException(Reason.INTEGRITY)
            return output.toByteArray()
        } finally {
            inflater.end()
        }
    }

    /** Offline-testable API response decoder; does NOT contact the server. */
    fun decodeResponse(context: Context, response: ByteArray): String {
        if (response.isEmpty() || response.size > MAX_BYTES)
            throw CloudException(Reason.SERVER)
        val outer = try { JSONObject(String(response, utf8)) }
            catch (_: Exception) { throw CloudException(Reason.SERVER) }
        if (outer.optInt("code", -1) != 200) throw CloudException(Reason.SERVER)
        val data = strictBase64(outer.optString("data"), MAX_BYTES, Reason.INTEGRITY)
        try {
            if (data.size < 64 || (data.size - 48) % 16 != 0)
                throw CloudException(Reason.INTEGRITY)
            val iv = data.copyOfRange(0, 16)
            val macReceived = data.copyOfRange(16, 48)
            val ciphertext = data.copyOfRange(48, data.size)
            val shared = RESPONSE_KEY.toByteArray(utf8)
            val inflated = try {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(shared, "HmacSHA256"))
                val expected = mac.doFinal(ciphertext)
                try {
                    if (!MessageDigest.isEqual(expected, macReceived))
                        throw CloudException(Reason.INTEGRITY)
                } finally { expected.fill(0) }
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(shared, "AES"),
                    IvParameterSpec(iv))
                inflateStrict(cipher.doFinal(ciphertext))
            } catch (e: CloudException) { throw e }
            catch (_: Exception) { throw CloudException(Reason.INTEGRITY) }
            finally {
                shared.fill(0); iv.fill(0); macReceived.fill(0); ciphertext.fill(0)
            }
            try {
                val imported = try { JSONObject(String(inflated, utf8)) }
                    catch (_: Exception) { throw CloudException(Reason.INTEGRITY) }
                if (imported.optString("status") != "success")
                    throw CloudException(Reason.SERVER)
                val payload = strictBase64(imported.optString("config_data"),
                    MAX_BYTES, Reason.DECODER)
                try {
                    if (payload.size % 16 != 0) throw CloudException(Reason.DECODER)
                    // This header is a local EHI adapter, never an original .ehi file.
                    val wrapped = ByteArrayOutputStream().use { buffer ->
                        DataOutputStream(buffer).use { out ->
                            out.writeUTF("ehi")
                            out.writeLong(0L)
                            out.writeUTF(BUILD)
                            out.writeLong(0L)
                            out.writeInt(payload.size)
                            out.writeLong(0L)
                            out.write(payload)
                        }
                        buffer.toByteArray()
                    }
                    try {
                        return EhiPort.decode(context, wrapped)
                            ?: throw CloudException(Reason.DECODER)
                    } finally { wrapped.fill(0) }
                } finally { payload.fill(0) }
            } finally { inflated.fill(0) }
        } finally { data.fill(0) }
    }

    /** Only call from the dedicated user-triggered cloud button. */
    fun decodeOnline(context: Context, reference: String): String {
        val key = parseReference(reference)
        val response = fetch(key)
        return try { decodeResponse(context, response) }
            finally { response.fill(0) }
    }
}

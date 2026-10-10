package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Native Argon2id v19 + AES-256-GCM Ultra/Sandok decoder.
 *
 * Source: decoders/Python/ultra.py. The 41 bot-only suffixes map to 19
 * historical source profiles. .ost is deliberately NOT routed here.
 * AAD(salt) and no-AAD are both attempted, always with authenticated tags.
 * The 11 known inner fields use the per-profile second password.
 *
 * Offline only; no network, subprocess, key brute force outside the profile
 * order in the historical source, or secret-bearing logs.
 */
object UltraSandokPort {
    private const val MAX_INPUT = 2 * 1024 * 1024
    private const val NONCE_LENGTH = 12
    private const val SALT_LENGTH = 16
    private const val TAG_LENGTH = 16
    private val gson = GsonBuilder()
        .disableHtmlEscaping().serializeNulls().setPrettyPrinting().create()
    private val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    fun decode(context: Context, suffix: String, data: ByteArray): String? {
        if (data.isEmpty() || data.size > MAX_INPUT) return null
        val manifest = try { UltraProfileStore.read(context) }
        catch (_: RuntimeException) { return null }
        val suffixName = suffix.lowercase(Locale.ROOT).removePrefix(".")
        val alias = manifest.aliases[suffixName] ?: return null
        // The historic .ost decoder is not replaced by Ultra.
        if (suffixName == "ost") return null
        var content = String(data, Charsets.UTF_8).trim()
        if ("://" in content) content = content.substringAfter("://")
        content = content.filterNot { it.isWhitespace() }
        if (content.isEmpty()) return null

        val order = linkedSetOf<String>()
        order.add(alias.profile)
        order.add(detectType(content))
        order.addAll(manifest.fallback)

        for (candidate in candidates(content)) {
            val decoded = try { decodeB64(candidate) } catch (_: IllegalArgumentException) { continue }
            if (decoded.size < SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH) continue
            val salt = decoded.copyOfRange(0, SALT_LENGTH)
            val nonce = decoded.copyOfRange(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH)
            val sealed = decoded.copyOfRange(SALT_LENGTH + NONCE_LENGTH, decoded.size)
            if (sealed.size < TAG_LENGTH) continue

            for (selected in order) {
                val profile = manifest.profiles[selected] ?: manifest.profiles["default"] ?: continue
                var key: ByteArray? = null
                try {
                    val derived = derive(profile.password, salt, profile.memoryKiB)
                    key = derived
                    var decrypted: ByteArray? = null
                    for (aad in arrayOf(salt, null)) {
                        decrypted = decryptGcm(derived, nonce, sealed, aad)
                        if (decrypted != null) break
                    }
                    val plain = decrypted ?: continue
                    val text = try { utf8(plain) }
                    catch (_: java.nio.charset.CharacterCodingException) { continue }
                    val first = text.indexOf('{')
                    val last = text.lastIndexOf('}')
                    if (first < 0 || last < first) continue
                    val root = try { JsonParser.parseString(text.substring(first, last + 1)) }
                    catch (_: RuntimeException) { continue }
                    if (!root.isJsonObject) continue
                    val cfg = root.asJsonObject
                    for (field in manifest.fields) {
                        val value = cfg.get(field) ?: continue
                        if (!value.isJsonPrimitive || !value.asJsonPrimitive.isString) continue
                        val raw = value.asString
                        if (raw.isEmpty() || raw.length < 44) continue
                        val inner = decryptField(raw, profile)
                        if (inner != null) cfg.addProperty(field, inner)
                    }
                    cfg.addProperty("_vpn_type",profile.name)
                    cfg.addProperty("_vpn_key",profile.key)
                    val out = JsonObject()
                    out.addProperty("application",alias.name)
                    out.addProperty("extension","." + alias.suffix)
                    out.add("config",cfg)
                    return gson.toJson(out)
                } catch (_: RuntimeException) {
                    // Invalid/corrupt configuration or provider failure.
                } finally {
                    key?.fill(0)
                }
            }
        }
        return null
    }

    private fun decryptField(source: String, profile: UltraProfileStore.Config): String? {
        val bytes = try { decodeB64(source) } catch (_: IllegalArgumentException) { return null }
        if (bytes.size < 44) return null
        val salt = bytes.copyOfRange(0, 16)
        val nonce = bytes.copyOfRange(16, 28)
        val sealed = bytes.copyOfRange(28, bytes.size)
        var key: ByteArray? = null
        return try {
            val derived = derive(profile.password2, salt, profile.memoryKiB)
            key = derived
            val plain = decryptGcm(derived, nonce, sealed, null) ?: return null
            utf8(plain)
        } catch (_: RuntimeException) { null }
          catch (_: java.nio.charset.CharacterCodingException) { null }
          finally { key?.fill(0) }
    }

    private fun derive(password: ByteArray, salt: ByteArray, mem: Int): ByteArray {
        require(mem in setOf(4096,8192,16384) && salt.size == 16 && password.isNotEmpty())
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withSalt(salt)
            .withIterations(3)
            .withMemoryAsKB(mem)
            .withParallelism(1)
            .build()
        val key = ByteArray(32)
        try {
            Argon2BytesGenerator().apply { init(params) }.generateBytes(password, key)
            return key
        } catch (e: Exception) {
            key.fill(0)
            throw e
        }
    }

    private fun decryptGcm(
        key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray?
    ): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key,"AES"),GCMParameterSpec(128,nonce))
            if (aad != null) cipher.updateAAD(aad)
            cipher.doFinal(sealed)
        } catch (_: GeneralSecurityException) { null }
    }

    private fun utf8(input: ByteArray): String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(input)).toString()

    private fun decodeB64(raw: String): ByteArray {
        val token = raw.filterNot { it.isWhitespace() }
        require(token.isNotEmpty() && token.all { it in ALPHABET } && token.length % 4 == 0)
        val decoded = Base64.decode(token,Base64.NO_WRAP)
        require(Base64.encodeToString(decoded,Base64.NO_WRAP) == token)
        return decoded
    }

    /** Python encrypted_candidates tries cleaned input, padding and 16 deletion repairs. */
    private fun candidates(raw: String): List<String> {
        val clean = raw.filter { it in ALPHABET }
        if (clean.isEmpty()) return emptyList()
        val out = linkedSetOf(clean)
        when (clean.length % 4) {
            2, 3 -> out.add(clean.padEnd((clean.length+3)/4*4,'='))
            1 -> for (i in 0 until minOf(16,clean.length))
                out.add(clean.removeRange(i,i+1))
        }
        return out.filter { it.isNotBlank() }
    }

    private fun detectType(data: String): String {
        val text=data.lowercase(Locale.ROOT)
        return when {
            "greattunnel" in text || "great" in text -> "greattunnel"
            "newdecryptlibpasswordiicore" in text || "mmtunnel" in text -> "mmtunnel"
            "vlxteam" in text || "vlxtunnel" in text -> "vlxtunnelvpn"
            "wolftunnel" in text || "wolfcustom" in text -> "wolfcustom"
            "tiktunnel" in text -> "tiktunnelvpn"
            "binkevpn" in text || "beevpn" in text -> "beevpn"
            "txtunnel" in text -> "txtunnel"
            "t20vpn" in text || "newdecryptlibpasswordt20" in text -> "t20vpn"
            "luckyproxy" in text || "luckyvip" in text -> "luckyproxy"
            "auranet" in text -> "auranetvpn"
            "velmora" in text -> "velmoravpn"
            "mehaf" in text -> "mehafvpn"
            "deep" in text -> "deepvpn"
            "nurchickenpowder" in text || "ultra" in text -> "ultratunnel"
            else -> "default"
        }
    }
}

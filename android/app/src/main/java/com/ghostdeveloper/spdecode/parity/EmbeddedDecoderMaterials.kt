package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject

/**
 * Phase S.2 — source-derived decoder constants outside Android DEX literals.
 *
 * Only the authenticated SecureAssetVault may provide this material. It is
 * historical public decoder data and remains recoverable by an analyst with
 * access to the APK. Never add production signing, API or user secrets here.
 *
 * Keep decoding byte-for-byte identical to the original Kotlin constants.
 */
internal object EmbeddedDecoderMaterials {
    private const val ASSET = "embedded_kotlin_profiles.json"
    @Volatile private var cached: JSONObject? = null

    private fun source(ctx: Context): JSONObject = cached ?: synchronized(this) {
        cached ?: JSONObject(SecureAssetVault.readText(ctx, ASSET)).also { root ->
            require(root.getInt("schemaVersion") == 1)
            cached = root
        }
    }

    data class Hat(val aesKey: ByteArray, val xorPassword: String)
    data class IndependentF1(val ltmPassword: ByteArray, val vn7Passwords: List<ByteArray>)

    fun hat(ctx: Context): Hat {
        val data = source(ctx).getJSONObject("hat")
        val aes = GenericProfileStore.strictBase64(data.getString("aesKeyB64"))
        require(aes.size == 16) { "HAT source key length mismatch" }
        val xor = data.getString("profileV5XorPassword")
        require(xor.length == 20) { "HAT profile v5 source parameter mismatch" }
        return Hat(aes, xor)
    }

    fun httpCustomXor(ctx: Context): ByteArray {
        val hex = source(ctx).getJSONObject("httpCustom").getString("outerXorKeyHex")
        require(hex.length == 22 && hex.matches(Regex("[0-9a-f]{22}")))
        return ByteArray(hex.length / 2) { i ->
            hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        }
    }

    fun independentF1(ctx: Context): IndependentF1 {
        val data = source(ctx).getJSONObject("independentF1")
        val hex = data.getString("ltmPasswordHex")
        require(hex.length % 2 == 0 && hex.length in 64..256)
        require(hex.matches(Regex("[0-9a-f]+")))
        val rawLtm = ByteArray(hex.length / 2) { i ->
            hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        }
        // Preserve historical source behavior exactly:
        // hex bytes -> UTF-8 replacement decoding -> UTF-8 encoding.
        val ltm = String(rawLtm, Charsets.UTF_8).toByteArray(Charsets.UTF_8)
        rawLtm.fill(0)
        val arr = data.getJSONArray("vn7Passwords")
        require(arr.length() == 2)
        val candidates = (0 until arr.length()).map { index ->
            arr.getString(index).also { require(it.isNotEmpty() && it.length <= 128) }
                .toByteArray(Charsets.UTF_8)
        }
        return IndependentF1(ltm, candidates)
    }
}

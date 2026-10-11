package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject

/**
 * S.2 continuation — historical TLS/EHI/Dark Tunnel constants from SPV1 vault.
 *
 * These bytes are already public in the source repository and are recoverable
 * through reverse engineering. This avoids direct DEX string literals, not
 * reverse engineering or offline key recovery.
 */
internal object AdditionalDecoderMaterials {
    @Volatile private var cache: JSONObject? = null
    private fun source(context: Context): JSONObject = cache ?: synchronized(this) {
        cache ?: JSONObject(SecureAssetVault.readText(context, "embedded_kotlin_profiles.json"))
            .also { root ->
                require(root.getInt("schemaVersion") == 1)
                cache = root
            }
    }
    private fun bytes(hex: String): ByteArray {
        require(hex.isNotEmpty() && hex.length % 2 == 0)
        require(hex.all { it in '0'..'9' || it in 'a'..'f' })
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
    private fun fixedHex(hex: String, size: Int): ByteArray =
        bytes(hex).also { require(it.size == size) }

    data class Ehi(
        val firstKey: ByteArray,
        val secondKey: ByteArray,
        val xxteaKey: ByteArray,
        val bypassIvs: List<ByteArray>,
        val standardIvs: List<ByteArray>,
    )

    data class Dark(
        val outerKey: ByteArray,
        val nestedKey: ByteArray,
        val iv: ByteArray,
    )

    fun tls(context: Context): List<ByteArray> {
        val values = source(context).getJSONObject("tls").getJSONArray("hexProfiles")
        require(values.length() == 6)
        return (0 until values.length()).map { i ->
            fixedHex(values.getString(i), 32)
        }
    }

    fun ehi(context: Context): Ehi {
        val data = source(context).getJSONObject("ehi")
        fun ivs(key: String): List<ByteArray> {
            val list = data.getJSONArray(key)
            require(list.length() == 3)
            return (0 until list.length()).map { fixedHex(list.getString(it),16) }
        }
        val xxtea = data.getString("xxteaKeyText").toByteArray(Charsets.UTF_8)
        require(xxtea.size == 16)
        return Ehi(
            fixedHex(data.getString("firstKeyHex"),32),
            fixedHex(data.getString("secondKeyHex"),16),
            xxtea,
            ivs("bypassIvHex"),
            ivs("standardIvHex"),
        )
    }

    fun dark(context: Context): Dark {
        val data = source(context).getJSONObject("dark")
        val outer = data.getString("outerKeyText").toByteArray(Charsets.UTF_8)
        val nested = data.getString("nestedKeyText").toByteArray(Charsets.UTF_8)
        require(outer.size == 32 && nested.size == 24)
        return Dark(outer, nested, fixedHex(data.getString("ivHex"),16))
    }
}

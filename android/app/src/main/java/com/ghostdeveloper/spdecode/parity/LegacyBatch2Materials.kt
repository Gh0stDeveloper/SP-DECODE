package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import org.json.JSONObject

/**
 * S.2 second legacy-engine batch: source-exact historical reference material.
 *
 * Offline APK protection only. The APK and public repository permit recovery
 * through reverse engineering; these are NOT private application credentials.
 */
internal object LegacyBatch2Materials {
    @Volatile private var cached: JSONObject? = null
    private fun source(context: Context): JSONObject = cached ?: synchronized(this) {
        cached ?: JSONObject(SecureAssetVault.readText(context, "embedded_kotlin_profiles.json"))
            .getJSONObject("legacyBatch2").also { cached = it }
    }

    private fun fixedHex(value: String, count: Int): ByteArray {
        require(value.length == count * 2 && value.all { it in '0'..'9' || it in 'a'..'f' })
        return ByteArray(count) { i -> value.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun b64(value: String, size: Int): ByteArray {
        require(value.matches(Regex("[A-Za-z0-9+/]+={0,2}")))
        return Base64.decode(value, Base64.DEFAULT).also { require(it.size == size) }
    }

    data class Sip(val aesKey: ByteArray, val ver8Key: ByteArray)
    data class Cloudy(val aesKey: ByteArray, val iv: ByteArray)
    data class Tnl(
        val passwords: List<String>,
        val oplSecret: String,
        val otKey: ByteArray,
    )

    fun sip(context: Context): Sip {
        val data = source(context).getJSONObject("sip")
        val aes = fixedHex(data.getString("outerAesHex"), 16)
        val ver8 = data.getString("ver8Key").toByteArray(Charsets.US_ASCII)
        require(ver8.size == 32)
        return Sip(aes, ver8)
    }

    fun ssh(context: Context): ByteArray {
        val key = source(context).getJSONObject("ssh")
            .getString("blowfishPassword").toByteArray(Charsets.US_ASCII)
        require(key.size == 39)
        return key
    }

    fun sks(context: Context): String {
        val key = source(context).getJSONObject("sks").getString("configKey")
        require(key.length == 32 && key.all { it.isLetterOrDigit() })
        return key
    }

    fun cloudy(context: Context): Cloudy {
        val data = source(context).getJSONObject("cloudy")
        return Cloudy(b64(data.getString("aesKeyB64"), 32), b64(data.getString("ivB64"), 16))
    }

    fun goldSeed(context: Context): ByteArray {
        val bytes = source(context).getJSONObject("gold")
            .getString("hashSeed").toByteArray(Charsets.UTF_8)
        require(bytes.size in 1..64)
        return bytes
    }

    fun tnl(context: Context): Tnl {
        val data = source(context).getJSONObject("tnl")
        val arr = data.getJSONArray("passwords")
        require(arr.length() == 2)
        val passwords = (0 until arr.length()).map { arr.getString(it) }
        require(passwords[0].length == 32 && passwords[1].length == 17)
        val opl = data.getString("oplSecret")
        require(opl.length == 64 && opl.all { it in '0'..'9' || it in 'a'..'f' })
        return Tnl(passwords, opl, fixedHex(data.getString("otKeyHex"), 32))
    }
}

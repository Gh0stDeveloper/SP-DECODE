package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.util.Locale

/**
 * Ultra/Sandok source inventory. No remote URLs/user agents are embedded.
 * Passwords are historical per-app decryption constants already shipped by
 * the bot; Base64 is an encoding, NOT a confidentiality mechanism.
 */
internal object UltraProfileStore {
    data class Config(
        val key: String,
        val name: String,
        val memoryKiB: Int,
        val password: ByteArray,
        val password2: ByteArray,
    )
    data class Alias(val suffix: String, val name: String, val profile: String)
    data class Data(
        val profiles: Map<String, Config>,
        val aliases: Map<String, Alias>,
        val fallback: List<String>,
        val fields: List<String>,
    )
    @Volatile private var cached: Data? = null
    fun read(context: Context): Data = cached ?: synchronized(this) {
        cached ?: parse(context).also { cached = it }
    }

    private fun parse(context: Context): Data {
        val raw = context.assets.open("ultra_c_profiles.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() }
        val root = JSONObject(raw)
        require(root.getInt("schemaVersion") == 1)
        require(root.getInt("suffixCount") == 41 && root.getInt("profileCount") == 19)
        require(root.getBoolean("legacyOstIsolated"))
        require(root.getInt("argonIterations") == 3)
        require(root.getInt("argonLanes") == 1)
        require(root.getInt("argonKeyBytes") == 32)
        val profiles = linkedMapOf<String, Config>()
        val list = root.getJSONArray("profiles")
        require(list.length() == 19)
        for (i in 0 until list.length()) {
            val item = list.getJSONObject(i)
            val key = item.getString("key")
            val memoryKiB = item.getInt("memoryKiB")
            require(key.isNotBlank() && memoryKiB in setOf(4096, 8192, 16384))
            val password = decodeBase64(item.getString("password"))
            val password2 = decodeBase64(item.getString("password2"))
            require(password.isNotEmpty() && password2.isNotEmpty())
            require(profiles.put(key, Config(key, item.getString("name"),
                memoryKiB, password, password2)) == null)
        }
        val aliases = linkedMapOf<String, Alias>()
        val arr = root.getJSONArray("aliases")
        require(arr.length() == 41)
        for (i in 0 until arr.length()) {
            val item = arr.getJSONObject(i)
            val suffix = item.getString("suffix")
            val profile = item.getString("profile")
            require(suffix.isNotBlank() && suffix == suffix.lowercase(Locale.ROOT))
            require(suffix != "ost" && profile in profiles)
            require(aliases.put(suffix, Alias(suffix,item.getString("name"),profile)) == null)
        }
        require(aliases.size == 41 && profiles.size == 19)
        val fallback = root.getJSONArray("fallbackProfiles").let {
            (0 until it.length()).map { i -> it.getString(i) }
        }
        require(fallback.size == 16 && fallback.toSet().size == 16)
        require(fallback.all { it in profiles })
        val fields = root.getJSONArray("encryptedFields").let {
            (0 until it.length()).map { i -> it.getString(i) }
        }
        require(fields.size == 11 && fields.toSet().size == 11)
        return Data(profiles,aliases,fallback,fields)
    }

    internal fun decodeBase64(source: String): ByteArray {
        // Be strict for source-controlled key material: don't allow Android's
        // permissive Base64 decoder to silently skip arbitrary characters.
        require(source.isNotEmpty() && source.length % 4 == 0)
        require(source.matches(Regex("""(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?""")))
        return Base64.decode(source,Base64.NO_WRAP).also {
            require(Base64.encodeToString(it,Base64.NO_WRAP) == source)
        }
    }
}

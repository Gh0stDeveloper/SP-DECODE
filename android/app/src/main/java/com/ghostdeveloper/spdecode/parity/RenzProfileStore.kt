package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import java.util.Locale

/**
 * Exact, read-only Phase D source profiles, extracted from renz.RENZ_KEYS.
 * URL metadata is deliberately excluded. Embedded historical keys are public
 * decoder constants, not private credentials or signing secrets.
 */
internal object RenzProfileStore {
    data class Profile(val id: String, val seed: ByteArray, val iv: ByteArray, val salt: ByteArray)
    data class Alias(val suffix: String, val profile: String, val name: String)
    data class Data(val profiles: Map<String, Profile>, val aliases: Map<String, Alias>)
    @Volatile private var cache: Data? = null

    fun read(context: Context): Data = cache ?: synchronized(this) {
        cache ?: load(context).also { cache = it }
    }

    private fun bytes(hex: String): ByteArray {
        require(hex.length % 2 == 0 && hex.matches(Regex("[0-9a-f]*")))
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    private fun load(context: Context): Data {
        val root = JSONObject(context.assets.open("renz_d_profiles.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
        require(root.getInt("schemaVersion") == 1)
        require(root.getInt("suffixCount") == 16 && root.getInt("profileCount") == 14)
        val types = root.getJSONArray("legacyTypes")
        require(types.length() == 4 && (0 until types.length()).all { types.getInt(it) == it })
        val profiles = linkedMapOf<String, Profile>()
        val p = root.getJSONArray("profiles")
        require(p.length() == 14)
        for (i in 0 until p.length()) {
            val row = p.getJSONObject(i)
            val id = row.getString("key")
            val seed = bytes(row.getString("seed"))
            val iv = bytes(row.getString("iv"))
            val salt = bytes(row.getString("salt"))
            if (id == "tcxtunnel") {
                require(seed.isEmpty() && iv.isEmpty() && salt.isEmpty())
            } else {
                require(seed.isNotEmpty() && iv.size == 16 && salt.size in setOf(16, 32))
            }
            require(profiles.put(id, Profile(id,seed,iv,salt)) == null)
        }
        val aliases = linkedMapOf<String, Alias>()
        val a = root.getJSONArray("aliases")
        require(a.length() == 16)
        for (i in 0 until a.length()) {
            val row = a.getJSONObject(i)
            val suffix = row.getString("suffix")
            val profile = row.getString("profile")
            require(suffix.isNotBlank() && suffix == suffix.lowercase(Locale.ROOT))
            require(profile in profiles)
            require(aliases.put(suffix,Alias(suffix,profile,row.getString("name"))) == null)
        }
        require(aliases.size == 16 && profiles.size == 14)
        require(aliases["osp"]?.profile == "7net")
        require(aliases["actun"]?.profile == "actunnelvpn")
        require("vlx" !in aliases && "izph" !in aliases)
        return Data(profiles.toMap(),aliases.toMap())
    }
}

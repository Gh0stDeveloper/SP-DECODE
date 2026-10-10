package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import org.json.JSONObject
import java.util.Locale

/**
 * Historical, already-public generic decryption profiles copied reproducibly
 * from the bot's selected 81 suffixes; NOT secrets protected by Base64.
 *
 * The manifest is regenerated and checked against generic_profiles.py by
 * scripts/android_b_generic_profiles.py. No private signing keys are shipped.
 */
internal object GenericProfileStore {
    data class Profile(
        val aesPasswords: List<ByteArray>,
        val desPassword: ByteArray?,
    )

    @Volatile private var cached: Map<String, Profile>? = null

    fun profile(context: Context, suffix: String): Profile? {
        val normalized = suffix.lowercase(Locale.ROOT).removePrefix(".")
        val profiles = cached ?: synchronized(this) {
            cached ?: load(context).also { cached = it }
        }
        return profiles[normalized]
    }

    fun availableSuffixes(context: Context): Set<String> {
        val profiles = cached ?: synchronized(this) {
            cached ?: load(context).also { cached = it }
        }
        return profiles.keys
    }

    private fun load(context: Context): Map<String, Profile> {
        val root = JSONObject(context.assets.open("generic_b_profiles.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
        require(root.getInt("schemaVersion") == 1)
        require(root.getInt("formatCount") == 81)
        require(root.getInt("aesProfileCount") == 74)
        require(root.getInt("desProfileCount") == 13)
        require(root.getInt("dualProfileCount") == 6)
        val entries = root.getJSONArray("profiles")
        require(entries.length() == 81)
        val result = linkedMapOf<String, Profile>()
        var aesCount = 0
        var desCount = 0
        var bothCount = 0
        for (i in 0 until entries.length()) {
            val row = entries.getJSONObject(i)
            val suffix = row.getString("suffix")
            require(suffix.isNotBlank() && suffix == suffix.lowercase(Locale.ROOT))
            val aes = row.getJSONArray("aesKeys")
            val passwords = (0 until aes.length()).map { at ->
                val bytes = strictBase64(aes.getString(at))
                require(bytes.isNotEmpty())
                bytes
            }
            val des = if (row.isNull("desKey")) null
                      else strictBase64(row.getString("desKey")).also {
                          require(it.isNotEmpty())
                      }
            require(passwords.isNotEmpty() || des != null)
            if (passwords.isNotEmpty()) aesCount++
            if (des != null) desCount++
            if (passwords.isNotEmpty() && des != null) bothCount++
            require(result.put(suffix, Profile(passwords, des)) == null) {
                "Duplicate generic B profile: $suffix"
            }
        }
        require(result.size == 81 && aesCount == 74 && desCount == 13 && bothCount == 6)
        return result.toMap()
    }

    /** Strict RFC4648 with padding; android.util.Base64 is otherwise permissive. */
    internal fun strictBase64(source: String): ByteArray {
        require(source.isNotBlank() && source.length % 4 == 0)
        require(source.matches(Regex("""(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?""")))
        val value = Base64.decode(source, Base64.NO_WRAP)
        require(Base64.encodeToString(value, Base64.NO_WRAP) == source)
        return value
    }
}

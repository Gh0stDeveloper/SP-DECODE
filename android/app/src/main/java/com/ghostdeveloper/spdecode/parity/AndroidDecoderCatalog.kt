package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import java.util.Locale

/**
 * Catalog is sourced from the canonical Linux registry and deliberately
 * marks 0 suffixes as NOT IMPLEMENTED on Android (experimental only).
 */
object AndroidDecoderCatalog {
    data class Format(
        val suffix: String,
        val appName: String,
        val portStatus: String,
        val androidVerified: Boolean,
    )

    fun read(context: Context): List<Format> {
        val raw = context.assets.open("decoder_catalog.json").bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
        val doc = JSONObject(raw)
        require(doc.getInt("schemaVersion") == 2)
        require(doc.getInt("androidCertifiedSuffixes") == 0)
        val list = doc.getJSONArray("entries")
        require(list.length() == 61)
        return (0 until list.length()).map { index ->
            val item = list.getJSONObject(index)
            Format(
                suffix = item.getString("suffix"),
                appName = item.getString("name"),
                portStatus = item.getString("androidPortStatus"),
                androidVerified = item.getBoolean("androidVerified"),
            )
        }
    }

    fun detect(filename: String, formats: List<Format>): Format? {
        val candidate = filename.substringAfterLast('/').substringAfterLast('\\')
            .lowercase(Locale.ROOT)
        if (candidate.isBlank()) return null
        return formats.filter { candidate.endsWith("." + it.suffix.lowercase(Locale.ROOT)) }
            .maxByOrNull { it.suffix.length }
    }
}

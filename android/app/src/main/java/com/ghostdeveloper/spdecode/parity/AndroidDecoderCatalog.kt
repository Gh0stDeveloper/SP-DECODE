package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import java.util.Locale

/**
 * Complete read-only bot inventory for Android migration, not a certification list.
 *
 * Phase A preserves the 61 original native routes and registers the other
 * 178 suffixes as explicitly NOT IMPLEMENTED. No file is dispatched to an
 * Android crypto engine merely because its suffix is present here.
 *
 * The JSON is reproducibly built by scripts/android_a24_catalog.py from
 * spdecode.registry.DECODER_REGISTRY, never from a hand-maintained alias table.
 */
object AndroidDecoderCatalog {
    const val TOTAL_SUFFIXES = 239
    const val LEGACY_NATIVE_SUFFIXES = 61
    const val PENDING_NATIVE_SUFFIXES = TOTAL_SUFFIXES - LEGACY_NATIVE_SUFFIXES
    const val PENDING_STATUS = "registered_not_implemented"

    data class Format(
        val suffix: String,
        val appName: String,
        val portStatus: String,
        val androidVerified: Boolean,
        val script: String,
        val originalRuntime: String,
        val migrationPhase: String,
        val sourceCatalog: String,
    ) {
        val hasNativeDecoder: Boolean
            get() = migrationPhase == "legacy" &&
                portStatus != PENDING_STATUS && portStatus != "not_implemented"
        val isPending: Boolean get() = !hasNativeDecoder
    }

    fun read(context: Context): List<Format> {
        val source = context.assets.open("decoder_catalog.json").bufferedReader(Charsets.UTF_8)
            .use { it.readText() }
        val doc = JSONObject(source)
        require(doc.getInt("schemaVersion") == 3)
        require(doc.getInt("botRegisteredSuffixes") == TOTAL_SUFFIXES)
        require(doc.getInt("androidExistingSuffixes") == LEGACY_NATIVE_SUFFIXES)
        require(doc.getInt("androidPendingNativeSuffixes") == PENDING_NATIVE_SUFFIXES)
        require(doc.getInt("androidCertifiedSuffixes") == 0)
        val entries = doc.getJSONArray("entries")
        require(entries.length() == TOTAL_SUFFIXES)
        val formats = (0 until entries.length()).map { index ->
            val item = entries.getJSONObject(index)
            Format(
                suffix = item.getString("suffix"),
                appName = item.getString("name"),
                portStatus = item.getString("androidPortStatus"),
                androidVerified = item.getBoolean("androidVerified"),
                script = item.getString("script"),
                originalRuntime = item.getString("originalRuntime"),
                migrationPhase = item.getString("migrationPhase"),
                sourceCatalog = item.getString("sourceCatalog"),
            )
        }
        require(formats.map { it.suffix }.toSet().size == TOTAL_SUFFIXES)
        require(formats.all { it.suffix.isNotEmpty() && it.suffix == it.suffix.lowercase(Locale.ROOT) })
        require(formats.none { it.androidVerified })
        require(formats.count { it.hasNativeDecoder } == LEGACY_NATIVE_SUFFIXES)
        require(formats.count { it.isPending } == PENDING_NATIVE_SUFFIXES)
        require(formats.filter { it.hasNativeDecoder }.all {
            it.sourceCatalog == "decoders.json"
        })
        require(formats.filter { it.isPending }.all {
            it.portStatus == PENDING_STATUS && it.sourceCatalog == "spdecode.registry"
        })
        return formats
    }

    /** Longest suffix wins; .sksrv.png must not be confused with .png. */
    fun detect(filename: String, formats: List<Format>): Format? {
        val candidate = filename.substringAfterLast('/').substringAfterLast('\\')
            .lowercase(Locale.ROOT)
        if (candidate.isBlank()) return null
        return formats.filter {
            candidate.endsWith("." + it.suffix.lowercase(Locale.ROOT))
        }.maxByOrNull { it.suffix.length }
    }
}

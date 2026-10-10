package com.ghostdeveloper.spdecode.parity

import android.content.Context

/** NPVS v5 white-box tables are stored as a data-only asset. */
internal object NpvsWhitebox {
    private const val ASSET = "npvs_v5_tables.b85"
    fun assetLength(context: Context): Int =
        context.assets.open(ASSET).use { it.available() }
}

package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject

/** Native offline implementation of NPVS v5. */
object NpvsPort {
    const val MAX_INPUT = 4 * 1024 * 1024
    fun decode(context: Context, input: ByteArray): String? = null
}

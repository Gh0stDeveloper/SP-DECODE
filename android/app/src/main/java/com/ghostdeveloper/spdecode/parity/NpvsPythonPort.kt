package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

/** Runs the unmodified decoders/Python/npvs.py engine on-device. No network or fallback. */
internal object NpvsPythonPort {
    private const val MAX_FILE = 4 * 1024 * 1024

    fun decode(context: Context, input: ByteArray): String? {
        if (input.size !in 89..MAX_FILE ||
            input[0] != 'N'.code.toByte() || input[1] != 'P'.code.toByte() ||
            input[2] != 'V'.code.toByte() || input[3] != 'S'.code.toByte() ||
            input[4] != 5.toByte()) return null
        return try {
            synchronized(this) {
                if (!Python.isStarted()) Python.start(AndroidPlatform(context.applicationContext))
            }
            val payload = Base64.encodeToString(input, Base64.NO_WRAP)
            Python.getInstance().getModule("npvs_bridge")
                .callAttr("decode_b64", payload).toString()
        } catch (_: Exception) {
            null
        }
    }
}

package com.ghostdeveloper.spdecode.parity

import android.content.Context

import org.json.JSONObject

/** .cloudy: fixed AES-256-CBC key/IV decoded from original Base64 constants. */
object CloudyPort {

    fun decode(context: Context, input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        p.bounded(input)
        val material=LegacyBatch2Materials.cloudy(context)
        val plaintext = p.cbc(p.b64(p.utf8(input)), material.aesKey, material.iv)
        val decoded = try { p.utf8(plaintext) }
        catch (_: Exception) { String(plaintext, Charsets.ISO_8859_1) }
        val json = JSONObject(decoded)
        require(json.length() > 0)
        val fields = p.keys(json).joinToString("") {
            key -> "│[۞] $key : " + p.pythonValue(json.get(key)) + "\n"
        }
        // The original exporter labels .cloudy output as .aro. Preserve golden.
        p.header("(.aro)", leadingLine = true) + "\n" + fields + p.footer()
    }
}

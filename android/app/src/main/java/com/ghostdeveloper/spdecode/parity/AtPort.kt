package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import org.json.JSONArray

/** ASH Tunnel .at: dual authenticated AES-GCM with a per-profile seed. */
object AtPort {
    private val p = LegacyPortPrimitives
    private val static = "AF4nnvvn10XpsrrR".toByteArray(Charsets.US_ASCII)
    private fun openHex(value: String): String {
        val raw = p.hex(value)
        require(raw.size >= 16 + 12 + 16 + 12 + 16)
        val seed = raw.copyOfRange(0, 16)
        val stage1 = p.gcm(raw.copyOfRange(28, raw.size), seed + static, raw.copyOfRange(16,28))
        require(stage1.size >= 28)
        return p.utf8(p.gcm(stage1.copyOfRange(12,stage1.size), seed,
            stage1.copyOfRange(0,12)))
    }
    private fun expand(value: Any?, depth: Int): Any? {
        require(depth <= 32)
        return when(value) {
            is JSONObject -> {
                for (key in p.keys(value)) {
                    val item = value.get(key)
                    if (item is String && item.length > 10) {
                        try { value.put(key, openHex(item)) } catch (_: Exception) { }
                    } else if (item is JSONObject || item is JSONArray) expand(item,depth+1)
                }
                value
            }
            is JSONArray -> { for (i in 0 until value.length()) expand(value.get(i),depth+1); value }
            else -> value
        }
    }
    fun decode(input: ByteArray): String? = p.safeDecode {
        p.bounded(input)
        val json = JSONObject(openHex(p.utf8(input).trim()))
        p.prettyJson(expand(json,0)) + "\n"
    }
}

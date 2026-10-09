package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import org.json.JSONArray

/** NetMod .nm: original three candidate AES-ECB keys, in defined order. */
object NmPort {
    private val p = LegacyPortPrimitives
    private val keys = listOf("<n3t5yn4^n3tm0d>", "_netsyna_netmod_", "nicetrybuddygoon")
    private val omitted = setOf("Opts","Note","Remark")
    private fun flatten(name: String, value: Any?, target: MutableMap<String,MutableList<Any?>>,depth:Int) {
        require(depth <= 32)
        if (name in omitted || value == null || value == JSONObject.NULL || value == "") return
        when(value) {
            is JSONObject -> {
                if (value.has("Value")) {
                    val candidate = value.get("Value")
                    if (candidate != JSONObject.NULL && candidate.toString().trim().isNotEmpty())
                        target.getOrPut(name){mutableListOf()}.add(candidate)
                }
                for (key in p.keys(value)) if (key != "Value") flatten(key,value.get(key),target,depth+1)
            }
            is JSONArray -> for (i in 0 until value.length()) {
                val child=value.get(i)
                if (child is JSONObject) for (key in p.keys(child))
                    flatten(key,child.get(key),target,depth+1)
            }
            is String,is Number -> if (value.toString().trim().isNotEmpty())
                target.getOrPut(name){mutableListOf()}.add(value)
        }
    }
    fun decode(input: ByteArray): String? = p.safeDecode {
        p.bounded(input)
        val data = p.b64(p.utf8(input).trim())
        val decrypted = keys.firstNotNullOfOrNull { key ->
            try { Batch20Primitives.ecb(data,key.toByteArray(Charsets.US_ASCII)) }
            catch (_: Exception) { null }
        } ?: throw IllegalArgumentException("No known NetMod key")
        val obj=JSONObject(p.utf8(decrypted))
        val flat=linkedMapOf<String,MutableList<Any?>>()
        for (key in p.keys(obj)) flatten(key,obj.get(key),flat,0)
        val out=JSONObject()
        for ((key,values) in flat) {
            out.put(key,if(values.size == 1) values[0] else JSONArray(values))
        }
        p.prettyJson(out).replace(Regex("(?m)^ +")) { m -> " ".repeat(m.value.length / 2) } + "\n"
    }
}

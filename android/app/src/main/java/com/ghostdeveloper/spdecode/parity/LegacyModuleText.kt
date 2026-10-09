package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject

/** Byte-exact rendering of the original Node lib/mainUtils.js English layout. */
internal object LegacyModuleText {
    private val p = LegacyPortPrimitives

    fun render(context: Context, data: LinkedHashMap<String, String>): String {
        val lang=JSONObject(context.assets.open("legacy_module_english_labels.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
        val result=StringBuilder("\n").append(p.header("",leadingLine=true)).append("\n")
        for ((key,value) in data) {
            val labelKey="_"+key
            if(lang.has(labelKey) && value.isNotEmpty())
                result.append("│[۞] ").append(lang.getString(labelKey))
                    .append(value).append("\r\n")
        }
        return result.append('\n').toString()
    }

    fun keys(context:Context):JSONObject=JSONObject(context.assets
        .open("legacy_epro_npv2_keys.json").bufferedReader(Charsets.UTF_8).use {it.readText()})
}

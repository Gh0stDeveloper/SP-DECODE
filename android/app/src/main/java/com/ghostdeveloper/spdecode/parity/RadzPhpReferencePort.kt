package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import org.json.JSONArray

/** Common Radz PHP source primitive. The jez/hrt filtering decisions differ. */
internal object RadzPhpReferencePort {
    private val p=LegacyPortPrimitives
    private val key=p.sha256("Radz_11_2021".toByteArray(Charsets.UTF_8))
    private fun decodeNested(value:Any?,depth:Int):Any? {
        require(depth<=32)
        return when(value) {
            is JSONObject -> {
                for(k in p.keys(value))value.put(k,decodeNested(value.get(k),depth+1))
                value
            }
            is JSONArray -> {for(i in 0 until value.length())value.put(i,decodeNested(value.get(i),depth+1));value}
            is String -> {
                try {
                    val bytes=p.b64(value)
                    p.utf8(bytes)
                } catch (_:Exception) {value}
            }
            else -> value
        }
    }
    fun decode(input:ByteArray,extension:String):String?=p.safeDecode {
        p.bounded(input)
        val json=JSONObject(p.utf8(p.cbc(p.b64(p.utf8(input).trim()),key,ByteArray(16))))
        val nested=decodeNested(json,0) as JSONObject
        val fields=p.keys(nested).mapNotNull { k->
            val value=nested.get(k)
            val show=extension=="hrt" || value != JSONObject.NULL && value != "" &&
                value != false && value != 0 || value == "0" || value == 0
            if(!show)null else "│[۞] $k : " + when(value) {
                JSONObject.NULL->""
                is Boolean -> if(value) "1" else ""
                is JSONObject,is JSONArray -> value.toString()
                else -> value.toString()
            } + "\n"
        }.joinToString("")
        require(fields.isNotEmpty())
        p.header("($extension)",leadingLine=true)+"\n"+fields+p.footer().dropLast(1)
    }
}

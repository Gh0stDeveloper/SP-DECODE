package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject

/** ARO: custom Base64 envelope with additive +18 byte transform. */
object AroPort {
    private val p = LegacyPortPrimitives
    private fun decodeValues(node:JSONObject,depth:Int) {
        require(depth <= 32)
        for (key in p.keys(node)) {
            when(val value=node.get(key)) {
                is String -> {
                    if (value.isEmpty()) node.put(key,"enzo pro")
                    else {
                        try {
                            val once=p.b64(value)
                            val latin=String(once,Charsets.ISO_8859_1)
                            node.put(key,String(p.b64(latin),Charsets.ISO_8859_1))
                        } catch (_:Exception) { }
                    }
                }
                is JSONObject -> decodeValues(value,depth+1)
            }
        }
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val envelope=p.b64(p.utf8(input))
        val decoded=ByteArray(envelope.size) { i -> ((envelope[i].toInt() and 255)+18).toByte() }
        val payload=JSONObject(p.utf8(decoded))
        decodeValues(payload,0)
        val config=payload.getJSONObject("CONFIG")
        require(config.length()>0)
        val lines=p.keys(config).joinToString("") { "│[۞] $it: "+p.pythonValue(config.get(it))+"\n" }
        p.header("(.aro)",leadingLine=true)+"\n"+lines+p.footer()
    }
}

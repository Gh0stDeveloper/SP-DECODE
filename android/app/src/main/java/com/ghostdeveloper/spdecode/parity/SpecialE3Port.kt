package com.ghostdeveloper.spdecode.parity

import com.google.gson.JsonElement
import com.google.gson.JsonParser
import java.util.Locale

/** Phase E.3: nine XOR-family file suffixes sharing the exact 12-byte source key. */
internal object SpecialE3Port {
    val extensions=setOf("apnalite","apnatnl","bdnet","hxt","fnf",
        "4ulite","omanova","ursa","hsome")
    private val schemes=extensions.map{ "$it://" }.toSet()+"hamaratnl://"
    private val key="4%PdXch>fkP]".toByteArray(Charsets.US_ASCII)
    private val p=SpecialCrypto

    fun decode(suffix:String,data:ByteArray):String?{
        if(suffix !in extensions || !p.check(data))return null
        val text=try{p.utf8(data).trim()}catch(_:Exception){return null}
        var raw=text
        if("://" in raw){
            val prefix=raw.substringBefore("://").lowercase(Locale.ROOT)+"://"
            if(prefix !in schemes)return null
            raw=raw.substringAfter("://")
        }
        if(raw.isEmpty() || raw.length%2!=0 ||
            !raw.matches(Regex("[0-9a-fA-F]+")))return null
        return try {
            val bytes=p.hex(raw)
            val clear=ByteArray(bytes.size){i->(bytes[i].toInt() xor key[i%key.size].toInt()).toByte()}
            val value=p.utf8(clear)
            val parsed=p.parse(value)
            if(parsed!=null)p.gson.toJson(deep(parsed,0))
            else value.takeIf{it.isNotEmpty()&&it.all{ch->!Character.isISOControl(ch)}}
        }catch(_:Exception){null}
    }
    private fun deep(node:JsonElement,depth:Int):JsonElement{
        if(depth>24)return node
        if(node.isJsonObject){
            val obj=node.asJsonObject
            for((k,v) in obj.entrySet().toList())if(v.isJsonPrimitive && v.asJsonPrimitive.isString){
                val value=v.asString
                if(value.length>4&&value.length%2==0&&value.matches(Regex("[0-9a-fA-F]+"))){
                    try {
                        val b=p.hex(value)
                        val dec=ByteArray(b.size){i->(b[i].toInt() xor key[i%key.size].toInt()).toByte()}
                        obj.addProperty(k,String(dec,Charsets.UTF_8))
                    }catch(_:Exception){}
                }
            }else if(v.isJsonArray||v.isJsonObject) deep(v,depth+1)
        }else if(node.isJsonArray)node.asJsonArray.forEach{deep(it,depth+1)}
        return node
    }
}

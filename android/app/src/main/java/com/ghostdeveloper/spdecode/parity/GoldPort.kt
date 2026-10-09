package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import org.json.JSONArray

/** Gold Tunnel: SHA256("goldtunnel") AES-CBC/IV=0 with field-local decrypt. */
object GoldPort {
    private val p=LegacyPortPrimitives
    private val key=p.sha256("goldtunnel".toByteArray(Charsets.UTF_8))
    private const val OBF="主tt畫s://u畫땬둣t二日s的为.xyz/u畫就的둣땬s/日s的为/小듌둣딨들둣中二天大듌く天中女大天땬둣듽.日s的为与没딸当国땀山"
    private const val CLEAR="https://updatejson.xyz/uploads/json/f5ac7a6e015406210da3.jsongibkm98"
    private val charMap=linkedMapOf<Char,Char>().apply {
        for(i in 0 until minOf(OBF.length,CLEAR.length))
            if(OBF[i]!=CLEAR[i])put(OBF[i],CLEAR[i])
    }
    private fun decrypt(s:String):String =
        p.utf8(p.cbc(p.b64(s),key,ByteArray(16)))
    private fun replaceObfuscated(s:String):String=s.map { charMap[it]?:it }.joinToString("")
    private fun recurse(value:Any?,depth:Int):Any? {
        require(depth<=32)
        return when(value){
            is JSONObject -> {
                for(name in p.keys(value)) {
                    val item=value.get(name)
                    if(item is String && item.length>20 && '=' in item) {
                        try { value.put(name,replaceObfuscated(decrypt(item))) } catch (_:Exception) {}
                    } else if(item is JSONObject || item is JSONArray) recurse(item,depth+1)
                }
                value
            }
            is JSONArray -> {for(i in 0 until value.length())recurse(value.get(i),depth+1);value}
            else -> value
        }
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val json=JSONObject(decrypt(p.utf8(input).trim()))
        val network=json.getString("network")
        json.put("network",JSONObject(network.replace("\\\"","\"").replace("ALUKt53Zd7wN6SoBNpv2lw==","")))
        recurse(json,0)
        "╔━━━━━━━━━━━━━━━═╗\n" +
        "╠▸ ◉ *Universal Decodez Bot* ◉\n" +
        "╠━━━━━━━━━━━━━━━ ★\n" +
        "╠▸ Code by : `𝕭𝖔𝖓𝖞 𝕸𝕷 🇨🇩`\n" +
        "╠▸ 𝑇𝑒𝑙𝑒𝑔𝑟𝑎𝑚 : `t.me/+vrk0HxI_av9iNDg0`\n" +
        "╚━━━━━━━━━━━━━━━═╝\n\n" +
        "╔━━━━━༺ - ༻━━━━━╗\n╠▸ App Name : `Gold Tunnel`\n" +
        "╚━━━━━༺ - ༻━━━━━╝\n\n" + Batch20Primitives.pyRepr(json) + "\n"
    }
}

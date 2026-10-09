package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import org.json.JSONArray

/** Exact SSCCUSTOM.py three-key ChaCha20/64-bit nonce, original mapping.
 * Only SSC's two source-declared outer formats are accepted.
 */
object SscPort {
    private val p=LegacyPortPrimitives
    private val key1=p.hex("c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b")
    private val key2=p.hex("7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e")
    private val key3=p.hex("d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e")
    private val nonce=p.hex("74d0f3879f9d47f7")
    private val mapping=linkedMapOf("a" to "CONFIGS","b" to "NOTE","c" to "EXPIRY DATE",
        "e" to "CONFIGNAME","f" to "PAYLOAD ENABLED","g" to "PAYLOAD",
        "h" to "PROXY","i" to "PROXY PORT","j" to "TYPE",
        "k" to "PROXY ENABLED","l" to "ADDRESS","m" to "PORT",
        "n" to "IS PREMIUM","o" to "USERNAME","p" to "PASSWORD",
        "q" to "TIMEOUT","r" to "PROTOCOL","s" to "VERSION",
        "t" to "ENCRYPTION","u" to "COMPRESSIONLEVEL","v" to "DNS",
        "w" to "NSSERVER","x" to "PUBKEY","y" to "ISDEFAULT","z" to "LOCALPORT")
    private val hidden=setOf("g","h","l","o","p","v","x","i","w")
    private fun dec(key:ByteArray,iv:ByteArray,data:ByteArray):ByteArray =
        LegacyChaCha8.decrypt(key,iv,data)
    private fun parse(bytes:ByteArray):JSONObject? {
        val text=String(bytes,Charsets.UTF_8).substringBefore('\u0000')
        val start=text.indexOf('{');val end=text.lastIndexOf('}')
        if(start<0||end<start)return null
        return try{JSONObject(text.substring(start,end+1))}catch(_:Exception){null}
    }
    private fun sanitise(name:String,v:Any?):Any?{
        if(v !is String)return v
        val filtered=v.filter{it.code>=32}
        if(name in setOf("ADDRESS","DNS","H","NSSERVER")){
            val ip=Regex("(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d+)?").find(filtered)
            return ip?.value ?: filtered.filter{it.isLetterOrDigit()||it in ".-_"}
        }
        if(name in setOf("USERNAME","PASSWORD")){
            if(filtered.all{it.isLetterOrDigit()})return filtered
            val m=Regex("^[a-zA-Z0-9!@#\\$%^&*()._-]+").find(filtered)
            if(m!=null)return m.value
        }
        return if(name=="PAYLOAD"&&"[crlf]" in filtered)filtered.substringBefore('\u0000')
            else filtered.trim()
    }
    private fun process(obj:JSONObject):JSONObject {
        val rows=obj.optJSONArray("a")
        if(rows!=null){
            val list=JSONArray()
            for(i in 0 until rows.length()){
                val row=rows.getJSONObject(i)
                val userKey=row.optString("b")
                if(userKey.length==32){
                    try{
                        val encoded=userKey.substring(16,32).reversed()+"68"+
                            userKey.substring(0,16)
                        val iv=p.hex(encoded).copyOfRange(0,8)
                        for(field in hidden)if(row.opt(field) is String &&
                            row.getString(field).length>16){
                            try {
                                val text=String(dec(key3,iv,p.hex(row.getString(field))),
                                    Charsets.UTF_8).substringBefore('\u0000')
                                val sanitized=if(field in setOf("l","v","w","h"))
                                    text.filter{it.isLetterOrDigit()||it in ".-:_"}
                                    else text
                                row.put(field,sanitized)
                            }catch(_:Exception){}
                        }
                    }catch(_:Exception){}
                }
                val formatted=JSONObject()
                for(k in p.keys(row)){
                    val newName=mapping[k]?:k
                    val value=sanitise(newName,row.get(k))
                    if(value=="" && k in hidden)continue
                    formatted.put(newName,value)
                }
                list.put(formatted)
            }
            obj.put("a",list)
        }
        val out=JSONObject()
        for(k in p.keys(obj)) {
            val value=obj.get(k)
            out.put(mapping[k]?:k,if(k=="a" && value is JSONArray)value
                else sanitise(mapping[k]?:k,value))
        }
        return out
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        var content=p.utf8(input).trim()
        if(content.startsWith("ssc://"))content=content.substring(6).reversed()
        val encrypted=p.hex(content.filterNot{it.isWhitespace()})
        val obj=parse(dec(key1,nonce,encrypted))?:error("Invalid SSC stage one")
        val target=if(obj.has("c")&&obj.opt("a") is String) {
            val iv=p.hex(obj.getString("a").take(16))
            parse(dec(key2,iv,p.hex(obj.getString("c"))))
        }else if(obj.opt("a") is JSONArray)obj else null
        require(target!=null)
        FinalJsonSurface.render("ssc",FinalJsonSurface.body(process(target)))
    }
}

package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject
import android.util.Base64
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Original DARKTUNNEL.py: outer Base64 JSON, AES-256-CFB(128) MessagePack,
 * optional inner AES-192-CFB MessagePack and selected Encrypted* fields.
 */
object DarkPort {
    private val p=LegacyPortPrimitives
    private val key256=("$"+"B&E)H@McQfThWmZq4t7w!z%C*F-JaNd").toByteArray(Charsets.UTF_8)
    private val key192="F)J@NcRfUjXn2r4u7x!A%D*G".toByteArray(Charsets.UTF_8)
    private val iv=p.hex("232e39185523184a5723586242200e05")
    /** DARKTUNNEL.py _base64_decode_safe accepts URL-safe Base64 and ignores
     * non-alphabet transport characters (Python b64decode(validate=false)).
     * Applied only to Dark Tunnel; other decoders keep their strict input rules.
     * Subsequent JSON/MessagePack parsing still rejects malformed containers.
     */
    private fun darkBase64(value:String):ByteArray {
        val clean=value.replace('-','+').replace('_','/')
            .filter { it in 'A'..'Z' || it in 'a'..'z' ||
                it in '0'..'9' || it=='+' || it=='/' || it=='=' }
        require(clean.isNotEmpty() && clean.length<=p.MAX_INPUT*2 &&
            clean.trimEnd('=').length%4!=1)
        return Base64.decode(clean.padEnd((clean.length+3)/4*4,'='),Base64.DEFAULT)
            .also { require(it.size<=p.MAX_INPUT) }
    }
    private fun inputText(input:ByteArray):String =
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.IGNORE)
            .onUnmappableCharacter(CodingErrorAction.IGNORE)
            .decode(ByteBuffer.wrap(input)).toString()
    /** Match Python's _is_utf8_printable: C0 controls except TAB/LF/CR
     * and DEL are represented as an array of raw bytes, not as text.
     */
    private fun printable(raw:ByteArray):String? {
        if(raw.isEmpty())return null
        val text=try { p.utf8(raw) } catch(_:Exception) { return null }
        return text.takeIf { value -> value.all { ch ->
            val n=ch.code
            n>=32 || n==9 || n==10 || n==13
        } && '\u007f' !in value }
    }

    private fun cfb(raw:ByteArray,key:ByteArray):ByteArray {
        require(raw.size in 1..p.MAX_INPUT)
        val cipher=Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        return cipher.doFinal(raw)
    }
    private fun json(value:Any?,depth:Int=0):Any?{
        require(depth<=32)
        return when(value) {
            is Map<*,*>->JSONObject().also{obj->
                for((k,v)in value)if(k is String && k!="Password")obj.put(k,json(v,depth+1))
            }
            is List<*>->JSONArray().also{arr->value.forEach{arr.put(json(it,depth+1))}}
            is ByteArray->printable(value) ?:
                JSONArray().also{arr->value.forEach{arr.put(it.toInt()and 255)}}
            null->JSONObject.NULL
            else->value
        }
    }
    private fun decryptNested(value:Any?,depth:Int=0):Any? {
        require(depth<=32)
        return when(value){
            is Map<*,*>->{
                val obj=linkedMapOf<String,Any?>()
                for((key,v)in value)if(key is String)
                    obj[key]=if(key.startsWith("Encrypted")&&v is ByteArray&&v.isNotEmpty()){
                        try{cfb(v,key192)}catch(_:Exception){v}
                    }else decryptNested(v,depth+1)
                obj
            }
            is List<*>->value.map{decryptNested(it,depth+1)}
            else->value
        }
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        var text=inputText(input).trim()
        if("://" in text)text=text.substringAfter("://")
        val envelope=JSONObject(p.utf8(darkBase64(text)))
        val decoded=cfb(darkBase64(envelope.getString("encryptedLockedConfig")),key256)
        val outer=StrictMessagePack(decoded).decode() as? Map<*,*>
            ?:error("Expected DARK MessagePack map")
        val inner=outer["EncryptedLockedConfig"]
        val copy=linkedMapOf<String,Any?>()
        for((name,value)in outer)if(name is String)
            copy[name]=if(name=="EncryptedLockedConfig" && inner is ByteArray){
                decryptNested(StrictMessagePack(cfb(inner,key192)).decode())
            }else value
        envelope.put("encryptedLockedConfig",json(copy))
        val filtered=JSONObject()
        for(k in p.keys(envelope))if(k!="Password")
            filtered.put(k,envelope.get(k))
        FinalJsonSurface.render(".dark",FinalJsonSurface.body(filtered))
    }
}

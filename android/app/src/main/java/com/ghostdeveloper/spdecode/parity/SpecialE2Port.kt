package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale

/** Phase E.2: WyrLite(3), WyrVPN, IntVPN, FTHP(2), AR/MSY(2), EC = 10. */
internal object SpecialE2Port {
    private val p=SpecialCrypto
    private val wyrKey="84EE1C1019099C62".toByteArray(Charsets.UTF_8)
    private val intKey="AD079CFF21766C8A".toByteArray(Charsets.UTF_8)
    private val wyrlHard=p.hex("bb7f0ac243b7e737ad621c1c43b620b8c240c08f10ebccc97ef91e1bd57afaea")
    private val mainAr=p.hex("496f8d4107be912a6b3b23057dd5ffafaa999bdf77c6a53d1b49b6b0fc555333")
    private val fieldAr=p.hex("d4b28c7cc782e7b756718e84cdb4ff4ba79a3a3cb2ddbec55b8c235853e22dca")
    private val fieldIv=p.hex("0123456789abcdef1032547698badcfe")
    private val arFields=setOf("Payload","WSPayload","SNIHost","BUGHost","DNSHost",
        "ProxySet","UDPhost","UDPobfs","UDPauth","V2Ejson","v2Esni","EwgConf","Server")
    private val wyrFields=setOf("dnstt_dns","custom_proxy","custom_proxy_port","password",
        "sni","http","v2ray_host","v2ray_json")
    private val ecKey="technore_101014".toByteArray(Charsets.US_ASCII)
    private val DELTA=0x9E3779B9.toInt()

    fun decode(suffix:String,data:ByteArray):String? {
        if(!p.check(data))return null
        return try {
            when(suffix){
                "wyrlite","wyrl","wyrvpnlite"->wyrlite(data)
                "wyr"->wyrvpn(data)
                "int"->intvpn(data)
                "fthp","ftp"->fthp(data)
                "ar","msy"->ar(data)
                "ec"->ec(data)
                else->null
            }
        }catch(_:Exception){null}
    }
    private fun compact(data:ByteArray):String=String(data,Charsets.UTF_8).trim()
        .filterNot{it.isWhitespace()}

    private fun wyrlDecrypt(value:String):String? {
        val encoded=p.b64(value.padEnd((value.length+3)/4*4,'='))
        if(encoded.size<28)return null
        val nonce=encoded.copyOfRange(0,12)
        val tag=encoded.copyOfRange(12,28)
        val ciphertext=encoded.copyOfRange(28,encoded.size)
        val pbkdfKey=p.pbkdf("acf54cb87cb8bca0".toByteArray(),byteArrayOf(),10000,32)
        for(method in 0..2)try{
            val out= when(method){
                0->p.chacha(wyrlHard,nonce,tag,ciphertext)
                1->p.chacha(pbkdfKey,nonce,tag,ciphertext)
                else->p.gcm(pbkdfKey,nonce,ciphertext+tag)
            }
            return p.utf8(out)
        }catch(_:Exception){}
        return null
    }
    private fun wyrlDeep(node:JsonElement,depth:Int):JsonElement{
        if(depth>24)return node
        when {
            node.isJsonArray->{
                val arr=node.asJsonArray
                for(i in 0 until arr.size())arr.set(i,wyrlDeep(arr[i],depth+1))
            }
            node.isJsonObject->{
                val o=node.asJsonObject
                for((key,value) in o.entrySet().toList())o.add(key,wyrlDeep(value,depth+1))
            }
            node.isJsonPrimitive&&node.asJsonPrimitive.isString->{
                val raw=node.asString
                if(raw.length>=20){
                    val dec=try{wyrlDecrypt(raw)}catch(_:Exception){null}
                    if(!dec.isNullOrBlank()){
                        val nested=p.parseDocument(dec)
                        return if(nested!=null)wyrlDeep(nested,depth+1)
                        else p.gson.toJsonTree(dec)
                    }
                }
            }
        }
        return node
    }
    private fun wyrlite(data:ByteArray):String?{
        var input=compact(data)
        if("://" in input)input=input.substringAfter("://")
        val decoded=try{wyrlDecrypt(input)}catch(_:Exception){null}
        val obj=p.parseDocument(decoded?:input)?:return null
        return p.gson.toJson(wyrlDeep(obj,0))
    }

    private fun wyrGcm(value:String):String{
        val decoded=p.b64(value.padEnd((value.length+3)/4*4,'='))
        require(decoded.size>=31)
        val nonce=decoded.copyOfRange(3,15)
        return p.utf8(p.gcm(wyrKey,nonce,decoded.copyOfRange(15,decoded.size)))
    }
    private fun wyrNested(doc:JsonElement):JsonElement{
        if(doc.isJsonObject){
            val obj=doc.asJsonObject
            for((key,v) in obj.entrySet().toList()){
                if(key in wyrFields && v.isJsonPrimitive && v.asJsonPrimitive.isString
                    && v.asString.startsWith("djAx")){
                    try{obj.addProperty(key,wyrGcm(v.asString))}catch(_:Exception){}
                }
            }
        }else if(doc.isJsonArray)for(v in doc.asJsonArray)wyrNested(v)
        return doc
    }
    private fun wyrvpn(data:ByteArray):String?{
        var s=compact(data)
        if("wyrvpn://" in s)s=s.substringAfter("wyrvpn://")
        val clear=wyrGcm(s)
        val parsed=p.parse(clear)
        return if(parsed!=null)p.gson.toJson(wyrNested(parsed))else clear
    }

    private fun clean64(value:String)=value.filter { it in
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" }
            .let{it.padEnd((it.length+3)/4*4,'=')}
    private fun intDecrypt(value:String):ByteArray{
        require(value.startsWith("djAx"))
        val stripped=value.substring(4)
        require(stripped.length>=16)
        val nonce=p.b64(clean64(stripped.substring(0,16)))
        val ciphertext=p.b64(clean64(stripped.substring(16)))
        return p.gcm(intKey,nonce,ciphertext)
    }
    private fun intDeep(doc:JsonElement,depth:Int):JsonElement{
        if(depth>24)return doc
        if(doc.isJsonObject){
            val obj=doc.asJsonObject
            for((k,v) in obj.entrySet().toList())obj.add(k,intDeep(v,depth+1))
        }else if(doc.isJsonArray){
            val arr=doc.asJsonArray
            for(i in 0 until arr.size())arr.set(i,intDeep(arr[i],depth+1))
        }else if(doc.isJsonPrimitive&&doc.asJsonPrimitive.isString
            && doc.asString.startsWith("djAx")){
            val raw=try{p.utf8(intDecrypt(doc.asString))}catch(_:Exception){null}
            if(raw!=null)return p.gson.toJsonTree(raw)
        }
        return doc
    }
    private fun intvpn(data:ByteArray):String?{
        var raw=compact(data)
        if(raw.startsWith("intvpn://"))raw=raw.substring(9)
        val plain=intDecrypt(raw)
        val parsed=try{p.parseDocument(p.utf8(plain))}catch(_:Exception){null}
        if(parsed!=null)return p.gson.toJson(intDeep(parsed,0))
        val obj=JsonObject().apply {addProperty("raw_base64",Base64.encodeToString(plain,Base64.NO_WRAP))}
        return p.gson.toJson(obj)
    }
    private fun fthp(data:ByteArray):String? {
        val parts=compact(data).split(".")
        if(parts.size!=3)return null
        val salt=p.b64(parts[0]);val nonce=p.b64(parts[1]);val encrypted=p.b64(parts[2])
        if(salt.isEmpty())return null
        for(pass in listOf("furious0982","Version6")){
            try{
                val k=p.pbkdf(pass.toByteArray(),salt,1000,16)
                val out=p.utf8(p.gcm(k,nonce,encrypted))
                if(out.isNotEmpty())return p.render(out)
            }catch(_:Exception){}
        }
        return null
    }

    private fun arField(value:String):String?{
        val raw=try{p.b64Strict(value)}catch(_:Exception){return null}
        fun clean(b:ByteArray):String=String(b,Charsets.UTF_8).trimEnd('\u0000','\u000f','\u0010')
        val cfb=try{clean(p.cfb(fieldAr,fieldIv,raw))}catch(_:Exception){null}
        if(!cfb.isNullOrBlank()&&cfb.any{!it.isISOControl()})return cfb
        return try{clean(p.cbc(mainAr,ByteArray(16),raw))}catch(_:Exception){null}
    }
    private fun ar(data:ByteArray):String?{
        var input=String(data,Charsets.UTF_8).trim()
        if("://" in input)input=input.substringAfter("://")
        val outer=try{p.utf8(p.cbc(mainAr,ByteArray(16),p.b64Strict(input)))}catch(_:Exception){null}
        val doc=p.parseDocument(outer?:input)?.takeIf{it.isJsonObject}
            ?:p.parseDocument(try{p.utf8(p.b64Strict(input))}catch(_:Exception){""})
                ?.takeIf{it.isJsonObject}?:return null
        val obj=doc.asJsonObject
        for(name in arFields)if(obj.has(name)){
            val valObj=obj.get(name)
            if(valObj.isJsonPrimitive&&valObj.asJsonPrimitive.isString&&valObj.asString.isNotEmpty()){
                val decrypted=arField(valObj.asString)
                if(!decrypted.isNullOrEmpty())obj.addProperty(name,decrypted)
            }
        }
        return p.gson.toJson(obj)
    }

    /** Standard XXTEA with original-length trailer, equivalent to ec._decrypt_xxtea. */
    private fun ecXXtea(bytes:ByteArray):ByteArray {
        require(bytes.size>=8 && bytes.size%4==0)
        val buf=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val v=IntArray(bytes.size/4){buf.int}
        val kb=ecKey.copyOf(16)
        val keyBuff=ByteBuffer.wrap(kb).order(ByteOrder.LITTLE_ENDIAN)
        val k=IntArray(4){keyBuff.int}
        val n=v.size-1
        var sum=DELTA*(6+52/(n+1))
        while(sum!=0){
            val e=(sum ushr 2)and 3
            var y=v[0]
            for(i in n downTo 1){
                val z=v[i-1]
                val mx=(((z ushr 5) xor (y shl 2))+((y ushr 3) xor (z shl 4))) xor
                    ((sum xor y)+(k[(i and 3)xor e] xor z))
                v[i]-=mx;y=v[i]
            }
            val z=v[n]
            val mx=(((z ushr 5) xor (y shl 2))+((y ushr 3) xor (z shl 4))) xor
                ((sum xor y)+(k[e] xor z))
            v[0]-=mx
            sum-=DELTA
        }
        val real=v.last().toLong() and 0xffffffffL
        require(real in ((v.size*4-7).toLong())..((v.size*4-4).toLong()))
        val out=ByteBuffer.allocate(bytes.size).order(ByteOrder.LITTLE_ENDIAN)
        for(word in v)out.putInt(word)
        return out.array().copyOf(real.toInt())
    }
    private fun ec(data:ByteArray):String? {
        val text=String(data,Charsets.US_ASCII).filterNot{it.isWhitespace()}
        val raw=p.b64Strict(text)
        return p.render(p.utf8(ecXXtea(raw)))
    }
}

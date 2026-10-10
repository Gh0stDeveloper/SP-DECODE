package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * IZPH Pro standalone port: four Sevnet compatibility types (0..3), source
 * HKDF/XXTEA/Threefish/PBKDF2 and named recursive fields.
 *
 * The bytes happen to match historical GCPVPN/7NET material, but this class
 * deliberately owns its fixed IV/salt and follows izph.py dispatch, NOT a
 * RENZ VPN suffix fallback. The original Python returns raw JSON untouched.
 */
internal object IzphNativePort {
    private val crypto=IndependentCrypto
    private val sc=SpecialCrypto
    private val base=crypto.hex("8968cb6e895105be625839ad9b9ba6ace8dcd4413d7c5ecfaa1069413ffeb044")
    private val iv=crypto.hex("49e59fdf67eb479ce8b96c24d2495bd1")
    private val salt=crypto.hex("c27fd7bee17196d650530886cf4c24f52cac5abb8bff6ad3a48ebb10f4b1f632")
    private val key16=sc.sha(base).copyOf(16)
    private val hkdf16 by lazy { RenzPort.hkdf(base,salt.copyOf(16),16) }
    private val hkdf32 by lazy { RenzPort.hkdf(base,salt,32) }
    private val pbkdf32 by lazy { sc.pbkdf(base,salt,100000,32) }
    private val networkKeys=setOf("Name","SNIHost","Payload","Info","DNSServerHost",
        "DNSResolver","TLSVersion")
    private val serverKeys=setOf("Name","ServerIPHost","Subname","OpenVPNTCPPort",
        "OpenVPNSSLPort","flag","CustomCert","Username","Password","CloudfrontDNS",
        "ServerHTTP","Obfs")

    fun decode(input:ByteArray):String? {
        if(input.isEmpty()||input.size>crypto.MAX)return null
        val original=try{crypto.utf8(input).trim()}catch(_:Exception){return null}
        var text=original
        for(prefix in listOf("izph://","izphvpnpro://")){
            if(text.startsWith(prefix,true)){text=text.substring(prefix.length).trim();break}
        }
        if(text.isEmpty())return null
        // Source run(): JSON object without encryption is returned unchanged.
        if(text.startsWith("{")){
            val parsed=sc.parseDocument(text)
            if(parsed?.isJsonObject==true)return sc.gson.toJson(parsed)
        }
        // Source izph_full_decode: decrypt outer with the first valid type.
        for(kind in 0..3){
            val decoded=decryptText(text,kind)?:continue
            val obj=sc.parseDocument(decoded)
            if(obj?.isJsonObject==true) {
                val result=obj.asJsonObject
                try{nested(result)}catch(_:Exception){}
                return sc.gson.toJson(result)
            }
        }
        return null
    }
    private fun decodeBase64Relaxed(text:String):ByteArray? {
        return try {
            val clean=text.filter{it in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}
            if(clean.isEmpty()) null
            else Base64.decode(clean.padEnd((clean.length+3)/4*4,'='),Base64.DEFAULT)
        } catch(_:Exception) { null }
    }

    private fun decryptText(text:String,kind:Int):String?{
        val b64=decodeBase64Relaxed(text)
        val candidates=listOfNotNull(b64, text.toByteArray(Charsets.UTF_8))
        for(candidate in candidates){
            val clear=try{typeDecode(candidate,kind)}catch(_:Exception){null}
            if(clear!=null) {
                val txt=try{crypto.utf8(clear)}catch(_:Exception){null}
                if(txt!=null)return txt
            }
        }
        return null
    }
    private fun typeDecode(candidate:ByteArray,kind:Int):ByteArray{
        return when(kind){
            0 -> {
                val aes=sc.cbc(key16,iv,candidate)
                val plain=RenzPort.legacyXxtea(aes,key16)
                ByteArray(plain.size){i->(plain[i].toInt()-2).toByte()}
            }
            1 -> {
                val raw=decodeBase64Relaxed(crypto.utf8(candidate))?:error("type1 inner Base64")
                val three=RenzPort.threefish(raw,hkdf32,inversePermutationAfterUnmix=true) {idx,_ ->
                    longArrayOf(idx.toLong(),idx.toLong()*64L)
                }
                sc.cbc(hkdf16,iv,three.dropLastWhile{it==0.toByte()}.toByteArray())
            }
            2 -> {
                val raw=decodeBase64Relaxed(crypto.utf8(candidate))?:error("type2 inner Base64")
                val xx=RenzPort.legacyXxtea(raw,pbkdf32.copyOf(16))
                prefixed(xx,pbkdf32)
            }
            3 -> prefixed(candidate,hkdf32)
            else -> error("IZPH type not registered")
        }
    }
    private fun prefixed(data:ByteArray,key:ByteArray):ByteArray{
        require(data.size>=32&&data.size%16==0)
        return sc.cbc(key,data.copyOfRange(0,16),
            data.copyOfRange(16,data.size))
    }

    private fun nestedText(value:String,priority:Int):String {
        val order=listOf(priority)+(0..3).filter{it!=priority}
        for(kind in order) {
            val plain=decryptText(value,kind)
            if(plain!=null)return plain
        }
        val raw=decodeBase64Relaxed(value)
        if(raw!=null){
            val plain=try{crypto.utf8(raw)}catch(_:Exception){null}
            if(plain!=null && (plain.startsWith("GET")||plain.startsWith("CONNECT")||
                "Host:" in plain||plain.startsWith("vless://")))return plain
            for(gzip in listOf(false,true)){
                try{return crypto.utf8(crypto.inflateCompressed(raw,gzip))}
                catch(_:Exception){}
            }
        }
        return value
    }
    private fun applyFields(obj:com.google.gson.JsonObject,fields:Set<String>,mode:(String)->Int){
        for(field in fields){
            val value=obj.get(field)
            if(value?.isJsonPrimitive==true && value.asJsonPrimitive.isString &&
                value.asString.isNotEmpty()){
                obj.addProperty(field,nestedText(value.asString,mode(field)))
            }
        }
    }
    private fun network(obj:com.google.gson.JsonObject){
        applyFields(obj,networkKeys){ if(it=="SNIHost"||it=="Payload")1 else 0 }
        obj.get("ProxySettings")?.takeIf{it.isJsonObject}?.asJsonObject?.let{
            applyFields(it,setOf("Squid","Port")){0}
        }
        obj.get("V2Ray")?.takeIf{it.isJsonObject}?.asJsonObject?.let{
            applyFields(it,setOf("SNIHost","CustomV2RAY","CustomV2RAYConfig","Config")){
                if(it=="CustomV2RAYConfig"||it=="SNIHost")1 else 0
            }
        }
    }
    private fun server(obj:com.google.gson.JsonObject){
        applyFields(obj,serverKeys){ when(it){
            "Username","Password"->2
            "ServerIPHost"->1
            else->0
        }}
        obj.get("V2Ray")?.takeIf{it.isJsonObject}?.asJsonObject?.let{
            applyFields(it,setOf("V2RayConfig","V2RayHost","UUID","PATH")){
                if(it=="V2RayHost"||it=="PATH")1 else 0
            }
        }
        obj.get("SlowDNS")?.takeIf{it.isJsonObject}?.asJsonObject?.let{
            applyFields(it,setOf("NSNameServer","PubKey")){0}
        }
    }
    private fun nested(obj:com.google.gson.JsonObject){
        applyFields(obj,setOf("Username","Password")){2}
        val servers=obj.get("Servers")
        val networks=obj.get("Networks")
        if(servers?.isJsonArray==true)for(e in servers.asJsonArray)if(e.isJsonObject)server(e.asJsonObject)
        if(networks?.isJsonArray==true)for(e in networks.asJsonArray)if(e.isJsonObject)network(e.asJsonObject)
        if(servers==null&&networks==null) {
            val names=obj.keySet()
            if(names.any{it in setOf("SNIHost","Payload","DNSServerHost","DNSResolver","TLSVersion")})
                network(obj)
            else if(names.any{it in setOf("ServerIPHost","OpenVPNTCPPort","OpenVPNSSLPort")})
                server(obj)
        }
    }
}

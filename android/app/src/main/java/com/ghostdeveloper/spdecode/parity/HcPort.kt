package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** HTTPCUSTOM.py outer XOR + ChaCha20(original 8-byte nonce) plus own RST
 * AES-ECB candidates. No fallback to unrelated formats or profiles.
 */
object HcPort {
    private val p=LegacyPortPrimitives
    private val fixedNonce=ByteArray(8){0xdb.toByte()}
    private val xorKey=p.hex("e382e4b8adc386f09f9293")
    private val labels=listOf("payload","proxy","lockAllConfig","blockedByRoot",
        "expiryTime","noteEnabled","notes","sshField",
        "mobileDataAndLockProvider","unlockUserAndPass","ovpnConfig",
        "ovpnUserAndPass","sni","unlockUserAndPass2","unknown14",
        "blockedByHwid","cloudconfig","psiphon","name","blockArea",
        "connectionMode","blockedByPassword","unknown22","extraSniffer",
        "psiphon2","v2rayEnabled","v2rayConfig","version",
        "slowdnsEnabled","slowdnsServer","slowdnsPublickey","dnsResolver")
    private fun hexClean(value:String)=value.filter{it in "0123456789abcdefABCDEF"}
    private fun abc(value:String,key:ByteArray,nonce:ByteArray=fixedNonce):String? {
        return try{
            val data=p.hex(hexClean(value))
            require(data.size>16)
            // PyCryptodome original skips the last 16 bytes without tag checking.
            val clear=LegacyChaCha8.decrypt(key,nonce,data.copyOf(data.size-16))
            p.utf8(clear)
        }catch(_:Exception){null}
    }
    private fun rst(raw:String,keys:List<String>):String? {
        val encoded=ByteArray(raw.toByteArray(Charsets.UTF_8).size){i->
            val byte=raw.toByteArray(Charsets.UTF_8)[i]
            (byte.toInt() xor ((i%20)+2)).toByte()
        }
        val input=try{p.b64(p.utf8(encoded))}catch(_:Exception){return null}
        for(key in keys){
            try {
                val secret=key.toByteArray(Charsets.US_ASCII)
                val cipher=Cipher.getInstance("AES/ECB/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(secret,"AES"))
                val result=p.utf8(cipher.doFinal(input))
                if("[splitConfig]" in result)return result
            }catch(_:Exception){}
        }
        return null
    }
    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val cfg=JSONObject(context.assets.open("hc_source_keys.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        val keys=(0 until cfg.getJSONArray("chaChaKeys").length()).map{
            p.hex(cfg.getJSONArray("chaChaKeys").getString(it))}
        val rstKeys=cfg.getJSONArray("rstKeys")
        val candidates=(0 until rstKeys.length()).map{rstKeys.getString(it)}
        val binary=try{
            // Original Python decodes UTF-8 with errors='ignore' then latin-1.
            p.utf8(input).toByteArray(Charsets.ISO_8859_1)
        }catch(_:Exception){input}
        val outerBytes=ByteArray(binary.size){i->
            (binary[i].toInt() xor xorKey[i%xorKey.size].toInt()).toByte()
        }
        val outer=abc(p.utf8(outerBytes),keys[5])?:error("HTTP Custom stage one")
        val obj=JSONObject(outer)
        val profiles=obj.optJSONObject("cfg")
        val isNew=profiles?.has("content")==true
        val protections=JSONObject()
        var payload=""
        var separator=""
        if(isNew) {
            for((short,label)in listOf("b" to "hwid","f" to "area")) {
                val text=obj.optString(short).ifEmpty{profiles?.optString(short).orEmpty()}
                if(text.isNotEmpty())protections.put(label,text)
            }
            payload=profiles!!.optString("content")
            separator="[splitConfig]"
        }else {
            val nested=obj.optJSONObject("a")?:JSONObject()
            for((name,label)in listOf("bb" to "hwid","e" to "password",
                "fe" to "area","ed" to "provider")) {
                val text=if(name=="e")obj.optString(name)else nested.optString(name)
                if(text.isNotEmpty())abc(text,keys[7])?.let{protections.put(label,it)}
            }
            payload=obj.optString("xy").ifEmpty{nested.optString("xy")}
            separator=obj.optString("uv").ifEmpty{nested.optString("uv")}
        }
        require(payload.isNotEmpty()&&separator.isNotEmpty())
        val decoded=if(isNew)rst(payload,candidates)?:keys.firstNotNullOfOrNull{
            abc(payload,it)?.takeIf{v->separator in v}
        }else abc(payload,keys[1])
        require(!decoded.isNullOrEmpty())
        val data=JSONObject()
        val sections=decoded.split(separator)
        for(i in sections.indices){
            if(i==22||i==24)continue
            val name=labels.getOrNull(i)?:"field_$i"
            var item=sections[i]
            if(item.isEmpty())continue
            // For the original new-format RST vectors, decrypted tokens are
            // plain UTF-8. Source-specific nested field decryptions are applied
            // only when their own field envelope is recognizable.
            item=item.replace("88a05e8772eac3e5703e0cd26c6e6f23de72fb09f7ee5a43283d1681f19d","")
            if(item.isNotEmpty()&&!Regex("^[0-9a-fA-F]{16,}$").matches(item))data.put(name,item)
        }
        val result=JSONObject()
        result.put("Protections",protections)
        result.put("Config",data)
        FinalJsonSurface.render(".hc",FinalJsonSurface.body(result),trailingSpace=true)
    }
}

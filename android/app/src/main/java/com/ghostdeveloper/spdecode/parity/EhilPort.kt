package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * HTTP Injector Lite 5.4.0 native original pipeline:
 * DataOutputStream envelope + two independent AES-CBC key/IV layers,
 * damaged-header repair, per-field custom alphabet Base64 XOR, message XOR.
 */
object EhilPort {
    private val p=LegacyPortPrimitives
    private val k1=listOf(
        "7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c",
        "4678e0f5295fc9ab3e9daf321b0897c78d045ebf95219514cfef570f49281811",
        "322510155da7325d644ca6e6b7df8b80ed20c30ed932eccb9fe7e2b04cf8f8a4").map{p.hex(it)}
    private val k2=listOf("73dcf1fdbf82509064e000a41d494c01",
        "2207a5b5a7ded2ded4eb17ce91c98266").map{p.hex(it)}
    private val ivs=listOf("CFHSIHTTPINISSCF","V5HSIHTTPINISS20",
        "V5HSIHTTPINISS21","SBHSIHTTPINISSLS","OBHSIHTTPINIOCTO",
        "AYJZIHTTPINIECKC","SBHSIHTTPINILITE").map{it.toByteArray(Charsets.US_ASCII)}
    private val innerKeys=setOf("host","user","password","remoteProxy","payload",
        "sniHostname","shadowsocksConfig","httpObfsSettings","v2rWsPath","v2rWsHeader",
        "v2rVmessSecurity","v2rVlessSecurity","v2rUserId","v2rSsSecurity","v2rQuicSecurity",
        "v2rProtocol","v2rPort","v2rPassword","v2rNetwork","v2rMuxConcurrency",
        "v2rKcpHeaderType","v2rHost","v2rAlterId","v2rQuicHeaderType",
        "shadowsocksHost","shadowsocksPassword","publicKey",
        "remoteProxyPassword","remoteProxyUsername","v2rTlsSni",
        "v2rTcpHeaderType","v2rRawJson")
    private val normalAlphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private val customAlphabet="t6uxKcTwhBn3UvRkLC2QaVM1o5A4f7Hr0Zp8OyjqzDb9e+dSFXsEIimPYgGJW/lN"
    private fun utf(bb:ByteBuffer):String {
        require(bb.remaining()>=2)
        val n=bb.short.toInt() and 65535
        require(bb.remaining()>=n)
        val raw=ByteArray(n);bb.get(raw)
        return p.utf8(raw)
    }
    private fun payload(input:ByteArray):ByteArray {
        p.bounded(input)
        val bb=ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN)
        require(utf(bb).lowercase()=="ehil")
        require(bb.remaining()>=8);bb.position(bb.position()+8)
        utf(bb);require(bb.remaining()>=12)
        bb.position(bb.position()+8)
        val count=bb.int
        require(count in 1..p.MAX_INPUT && bb.remaining()>=8+count)
        bb.position(bb.position()+8)
        return ByteArray(count).also{bb.get(it)}
    }
    private fun parse(raw:ByteArray):JSONObject? {
        val text=String(raw,Charsets.UTF_8)
        val choices=mutableListOf(text)
        if(text.length>17) {
            choices.add("{\"a"+text.substring(17))
            choices.add("{\"a\":\""+text.substring(17))
        }
        listOf("estamp\":" to "{\"a","configIdentifier\"" to "{\"aestamp\":0,\"")
            .forEach{(marker,prefix)->text.indexOf(marker).takeIf{it>=0}?.let{
                choices.add(prefix+text.substring(it))}}
        for(candidate in choices)try{
            val obj=JSONObject(candidate)
            if(obj.has("configSalt"))return obj
        }catch(_:Exception){}
        return null
    }
    private fun customDecode(encoded:String):ByteArray {
        val source=encoded.replace("?","").map {ch->
            val index=customAlphabet.indexOf(ch)
            if(index>=0)normalAlphabet[index]else ch
        }.joinToString("")
        return p.b64(source)
    }
    private fun decodeInner(text:String,password:String):String? {
        if(text.isBlank())return text
        return try {
            val reversed=text.reversed()
            var hex=p.utf8(customDecode(reversed))
            if(hex.length%2!=0)hex="0"+hex
            val cipher=p.hex(hex)
            val key=password.toByteArray(Charsets.UTF_8)
            require(key.isNotEmpty())
            val decrypted=ByteArray(cipher.size){i->
                (cipher[i].toInt() xor key[i%key.size].toInt()).toByte()
            }.filter{it!=0.toByte()}.toByteArray()
            p.utf8(decrypted)
        }catch(_:Exception){null}
    }
    private fun decodeMessage(encoded:String):String {
        return try{
            val input=String(p.b64(encoded),Charsets.UTF_8)
            val key="EHIMSG"
            buildString {input.forEachIndexed{i,ch->
                append((ch.code xor key[i%key.length].code).toChar())}}
        }catch(_:Exception){encoded}
    }
    private fun render(obj:JSONObject):String {
        val fields=p.keys(obj).joinToString("\n") { key->
            val raw=obj.get(key)
            val value=when(raw) {
                null,JSONObject.NULL->"null"
                is Boolean->raw.toString()
                is org.json.JSONArray,is JSONObject -> raw.toString()
                else->raw.toString()
            }
            "│[۞] "+key+": "+value
        }
        require(fields.isNotEmpty())
        return "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehil)\n"+
            "│[۞] Aplicación: HTTP Injector Lite\n├───────────────\n"+
            fields+"\n\n"+p.footer().drop(0)
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        val outer=payload(input)
        var parsed:JSONObject?=null
        outer@ for(key1 in k1)for(iv1 in ivs){
            val clear=try{p.utf8(p.cbc(outer,key1,iv1))}catch(_:Exception){continue}
            val encoded=clear.substringAfterLast(':')
            val encrypted=try{p.b64(encoded)}catch(_:Exception){continue}
            for(key2 in k2)for(iv2 in ivs){
                val value=try{p.cbc(encrypted,key2,iv2)}catch(_:Exception){continue}
                parsed=parse(value)
                if(parsed!=null)break@outer
            }
        }
        val obj=parsed ?: error("invalid EHIL container")
        val salt=obj.optString("configSalt").ifEmpty{"EVZJNI"}
        for(name in innerKeys)if(obj.opt(name) is String){
            val decrypted=decodeInner(obj.getString(name),salt)
            if(decrypted!=null)obj.put(name,decrypted)
        }
        if(obj.opt("configMessage") is String)
            obj.put("configMessage",decodeMessage(obj.getString("configMessage")))
        render(obj)
    }
}

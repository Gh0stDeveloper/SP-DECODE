package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec

/** F.2: seven suffixes, five independent reference decoders. */
internal object IndependentF2Port {
    private val crypto=IndependentCrypto
    private val sc=SpecialCrypto
    private val crevKeys=listOf("DEV_CREEB","CREEB","dev_creeb","DEV_CREV")
    private val crevFields=setOf("Payload","Nameserver","Slowchave","ServerPass",
        "ServerUser","ProxyHost","DnsHost","ServerHost","SNI")
    private val ktrKey=crypto.hex("6f8deb1015ca70be2b53aef0858d77811f352c073b6708d72d9d10a30914dff9")
    private val ktrIv=crypto.hex("000102030405060708090a0b0c0d0e0f")
    private val javaField=Regex("^[A-Z][A-Z0-9_]{1,60}$")
    private val javaB64=Regex("[A-Za-z0-9+/]{20,}={0,2}")
    private val skipPrefix=listOf("java.","com.","org.","sun.","javax.","Ljava.","[L","Lsc.","Lcom/")
    private val skipExact=setOf("key","value","next","hash","this\$0","serialVersionUID")
    private val devSky="demondevs".toByteArray()
    private val devPassword="❤️🧑‍💻Bøbõ⁰⁰!!"
    private val devChars="           ​‌‍‎‏"

    fun decode(suffix:String,input:ByteArray):String? {
        if(input.isEmpty() || input.size>IndependentCrypto.MAX)return null
        return try { when(suffix){
            "crev","cer","cerv"->crev(input)
            "zoba"->zoba(input)
            "dev"->dev(input)
            "ktr"->ktr(input)
            "n4"->n4(input)
            else->null
        } }catch(_:Exception){null}
    }

    private fun crevOne(encoded:String,key:String):String? {
        val raw=crypto.b64(encoded)
        val clear=crypto.xxteaDecrypt(raw,key.toByteArray(),-1703701580)?:return null
        return crypto.utf8Ignore(clear)
    }
    private fun crev(input:ByteArray):String?{
        var text=crypto.utf8Ignore(input).trim()
        text=crypto.stripScheme(text).filterNot{it.isWhitespace()}
        for(key in crevKeys) {
            val raw=try{crevOne(text,key)}catch(_:Exception){null}?:continue
            val doc=sc.parseDocument(raw)?.takeIf{it.isJsonObject}?:continue
            val obj=doc.asJsonObject
            if(obj.has("Tweaks") && obj.get("Tweaks").isJsonArray){
                for(t in obj.getAsJsonArray("Tweaks")){
                    if(!t.isJsonObject)continue
                    val entry=t.asJsonObject
                    for(field in crevFields)if(entry.has(field) && entry.get(field).isJsonPrimitive &&
                        entry.get(field).asJsonPrimitive.isString) {
                        val value=entry.get(field).asString
                        if(value.isNotEmpty()){
                            val plain=try{crevOne(value,key)}catch(_:Exception){null}
                            if(!plain.isNullOrEmpty())entry.addProperty(field,plain)
                        }
                    }
                }
            }
            return sc.gson.toJson(obj)
        }
        return null
    }

    private fun zoba(input:ByteArray):String? {
        val raw=try{crypto.b64(crypto.utf8Ignore(input))}catch(_:Exception){input}
        val clear=crypto.xxteaDecrypt(raw,"technore_008515\u0000".toByteArray(),-1704280)
            ?:return null
        val text=crypto.utf8Ignore(clear)
        val json=sc.parseDocument(text)
        return if(json!=null)sc.gson.toJson(json)
        else text.takeIf{it.length>3 && it.all{ch->!ch.isISOControl()}}
    }

    private fun devKey():ByteArray {
        val input=devPassword.toByteArray(Charsets.UTF_8)
        val hex=input.joinToString(""){"%02X".format(it.toInt() and 255)}
        return sc.sha(hex.toByteArray(Charsets.UTF_8))
    }
    private fun devDecodeChars(raw:String):String{
        if(raw.length%2!=0)return raw
        return try{
            val bytes=ByteArray(raw.length/2) { i->
                val first=devChars.indexOf(raw[2*i])
                val second=devChars.indexOf(raw[2*i+1])
                require(first>=0&&second>=0)
                ((first shl 4) or second).toByte()
            }
            crypto.utf8(bytes)
        }catch(_:Exception){raw}
    }
    private fun devInner(raw:String,key:ByteArray):String{
        return try{
            val encoded=devDecodeChars(raw)
            val encrypted=crypto.b64(encoded)
            val cipher=Cipher.getInstance("AES/CBC/NoPadding")
            require(encrypted.isNotEmpty()&&encrypted.size%16==0)
            cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(ByteArray(16)))
            val output=cipher.doFinal(encrypted)
            val pad=output.last().toInt() and 255
            val cut=if(pad==0)0 else maxOf(0,output.size-pad)
            crypto.utf8(output.copyOf(cut))
        }catch(_:Exception){raw}
    }
    private fun dev(input:ByteArray):String?{
        val encoded=crypto.utf8Ignore(input).trim()
        val clear=crypto.xxteaDecrypt(crypto.b64(encoded),devSky,0x9a7393b4.toInt())
            ?:return null
        val doc=sc.parseDocument(crypto.utf8(clear))?.takeIf{it.isJsonObject}?:return null
        val obj=doc.asJsonObject
        val key=devKey()
        for((name,value) in obj.entrySet().toList()){
            if(value.isJsonPrimitive && value.asJsonPrimitive.isString &&
                value.asString.isNotEmpty()){
                obj.addProperty(name,devInner(value.asString,key))
            }
        }
        return sc.gson.toJson(obj)
    }

    private val table2="′':‽,·ထ\u200cယငခပဆအနတမ"
    private val table3="′':‽,·難手火水日山田金中大"
    private val table4="           ​‌‍‎‏"
    private val preserveN4=setOf("isSSL","isPayloadSSL","isDirect","isSSLRp","isInject",
        "isUdp","isV2ray","isSlow","isOvpn","isHwid","isReward")
    private val n4Morse=mapOf(
        ".-" to "A","-..." to "B","-.-." to "C","-.." to "D","." to "E",
        "..-." to "F","--." to "G","...." to "H",".." to "I",".---" to "J",
        "-.-" to "K",".-.." to "L","--" to "M","-." to "N","---" to "O",
        ".--." to "P","--.-" to "Q",".-." to "R","..." to "S","-" to "T",
        "..-" to "U","...-" to "V",".--" to "W","-..-" to "X","-.--" to "Y",
        "--.." to "Z","n4vpn" to "0","n" to "1","n4" to "2","n4." to "3",
        "p.p" to "4","n7." to "5","pro" to "6","L.W" to "7","n4.v" to "8",
        "v.p.n" to "9",".-.-.-" to ".","--..--" to ",","..--.." to "?",
        "-.-.--" to "!","/" to " "
    )
    private fun n4MorseText(input:String):String {
        if(input.isEmpty())return ""
        val out=StringBuilder()
        for(word in input.split(" / ")){
            for(c in word.split(" "))out.append(n4Morse[c]?:"")
            out.append(' ')
        }
        return out.toString().trim()
    }
    private fun n4DecryptField(value:String,table:String):String {
        if(value.length<2||value.length%2!=0)return value
        return try {
            val bytes=ByteArray(value.length/2) { index->
                val high=table.indexOf(value[index*2]);val low=table.indexOf(value[index*2+1])
                require(high>=0&&low>=0)
                ((high shl 4)or low).toByte()
            }
            val encoded=crypto.utf8(bytes)
            val ciphertext=crypto.b64(encoded)
            val password="modmkk".toByteArray()
            val hex=password.joinToString(""){"%02X".format(it.toInt() and 255)}
            val key=sc.sha(hex.toByteArray())
            crypto.utf8(sc.cbc(key,ByteArray(16),ciphertext))
        }catch(_:Exception){value}
    }
    private fun n4Deep(obj:JsonElement,level:Int):JsonElement {
        if(level>32)return obj
        if(obj.isJsonObject){
            val data=obj.asJsonObject
            for((key,value) in data.entrySet().toList()) {
                if(key=="ServerPort"&&value.isJsonPrimitive&&value.asJsonPrimitive.isString){
                    data.addProperty(key,n4MorseText(value.asString))
                } else if(key in preserveN4){
                    continue
                }else if(value.isJsonPrimitive&&value.asJsonPrimitive.isString&&value.asString.isNotEmpty()){
                    val raw=value.asString
                    val plain=when(key){
                        "N4User","N4Pass"->n4DecryptField(raw,table2)
                        "ServerIP","ProxyIP"->n4DecryptField(raw,table3)
                        "Payload","SNI","v2rayjson","ovpn_config"->n4DecryptField(raw,table4)
                        else -> {
                            var result=raw
                            for(table in listOf(table2,table3,table4)){
                                result=n4DecryptField(raw,table)
                                if(result!=raw)break
                            }
                            result
                        }
                    }
                    data.addProperty(key,plain)
                }else if(value.isJsonObject||value.isJsonArray){
                    data.add(key,n4Deep(value,level+1))
                }
            }
        }else if(obj.isJsonArray){
            val arr=obj.asJsonArray
            for(i in 0 until arr.size())arr.set(i,n4Deep(arr[i],level+1))
        }
        return obj
    }
    private fun n4(input:ByteArray):String?{
        val source=crypto.utf8Ignore(input).filterNot{it.isWhitespace()}
        val encrypted=crypto.b64(source)
        require(encrypted.size%16==0 && encrypted.isNotEmpty())
        val cipher=Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(sc.sha("jdk".toByteArray()),"AES"))
        val clear=crypto.utf8(cipher.doFinal(encrypted))
        val doc=sc.parseDocument(clear)?.takeIf{it.isJsonObject}?:return null
        return sc.gson.toJson(n4Deep(doc,0))
    }

    private fun ktrDecrypt(raw:String):String?{
        if(raw.length<4||raw.length%4!=0)return null
        return try {
            val bytes=crypto.b64(raw)
            if(bytes.size<16||bytes.size%16!=0)return null
            val clear=crypto.utf8(sc.cbc(ktrKey,ktrIv,bytes))
            if(clear.isEmpty())return null
            val printable=clear.count{!it.isISOControl()||it=='\r'||it=='\n'||it=='\t'}
            if(printable.toDouble()/clear.length<0.85)return null
            clear
        }catch(_:Exception){null}
    }
    private fun ktrExtract(data:ByteArray):List<String>{
        val result=mutableListOf<String>()
        var i=0
        while(i<data.size){
            val tag=data[i].toInt() and 255
            val head=when(tag){0x74->3;0x7c->9;else->0}
            if(head>0&&i+head<=data.size){
                val len= if(head==3){
                    ((data[i+1].toInt() and 255) shl 8)or(data[i+2].toInt() and 255)
                }else{
                    val l=ByteBuffer.wrap(data,i+1,8).order(ByteOrder.BIG_ENDIAN).long
                    if(l<=0||l>10_000_000)0 else l.toInt()
                }
                if(len>0&&len<=data.size-i-head){
                    val text=try{crypto.utf8(data.copyOfRange(i+head,i+head+len))}
                        catch(_:Exception){null}
                    if(text!=null){
                        result.add(text)
                        i+=head+len
                        continue
                    }
                }
            }
            i++
        }
        return result
    }
    private fun ktrPairs(strings:List<String>):LinkedHashMap<String,String?>{
        val pairs=linkedMapOf<String,String?>()
        var pending:String?=null
        for(s in strings) {
            if(s in skipExact||skipPrefix.any{s.startsWith(it)})continue
            val field=javaField.matches(s)
            if(pending!=null) {
                if(field){pairs[pending]=null;pending=s}
                else {pairs[pending]=s;pending=null}
            }else if(field)pending=s
        }
        if(pending!=null)pairs[pending]=null
        return pairs
    }
    private fun ktr(input:ByteArray):String? {
        if(input.size<4||!input.copyOfRange(0,4).contentEquals(byteArrayOf(
                0xac.toByte(),0xed.toByte(),0,5)))return null
        val strings=ktrExtract(input)
        val plain=strings.map{ktrDecrypt(it)?:it}
        val result=ktrPairs(plain)
        val seen=mutableSetOf<String>()
        val extracted=mutableListOf<String>()
        val binary=input.toString(Charsets.ISO_8859_1)
        for(match in javaB64.findAll(binary)){
            val value=match.value
            if(value in seen)continue
            val decoded=try{crypto.b64(value)}catch(_:Exception){continue}
            if(decoded.size<16||decoded.size%16!=0)continue
            val plainText=ktrDecrypt(value)?:continue
            seen.add(value);extracted.add(plainText)
        }
        for((key,value) in ktrPairs(extracted))if(key !in result)result[key]=value
        if(result.isEmpty())return null
        val obj=JsonObject()
        obj.addProperty("mode","java");obj.addProperty("count",result.size)
        val fields=JsonObject()
        for((k,v) in result)if(v==null)fields.add(k,com.google.gson.JsonNull.INSTANCE)
            else fields.addProperty(k,v)
        obj.add("data",fields)
        return sc.gson.toJson(obj)
    }
}

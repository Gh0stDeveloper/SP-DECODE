package com.ghostdeveloper.spdecode

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Text handlers ported from spdecode/handlers/text_protocols.py.
 * Decodes entirely offline. No logs/analytics, speculative keys or fallback
 * between unrelated formats; old Android file ports are reused for TLS/Dark/SSC.
 */
object TextProtocolDecoder {
    const val MAX_CHARS=250_000
    private const val MAX_CLEAR=1024*1024
    private val pretty=GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create()
    private val links=Regex("""(?i)(?<![a-z0-9._-])([a-z0-9._-]+)://([^\s\x60]+)""")
    private val nm=setOf("dns","ssr","vmess","vless","trojan","ssh","xray-json",
        "socks","ss","wireguard","trojan-go")
    private val ar=setOf("dns","vless","vmess","trojan","ssr","socks","trojan-go","ssh","ss")
    private val pb=setOf("ssh","vless","vmess","trojan","socks","ss")
    data class Input(val protocol:String,val app:String,val suffix:String,
        val content:String)

    fun appNameForSuffix(suffix:String):String?=when(suffix.lowercase(Locale.ROOT)){
        "vmess"->"VMess"
        "netmod"->"NetMod"
        "armod"->"ARMod"
        "xraypb"->"XrayPB"
        "howdy"->"Howdy"
        "zivpn"->"ZIVPN"
        "v2box"->"V2Box"
        "decssh"->"SSH"
        "renz"->"RENZ / 7NET"
        "xor"->"XOR VPN"
        "flex"->"FlexNet"
        "npvs"->"NPV Tunnel"
        "izph"->"IZPH VPN Pro"
        "falcon"->"Falcon Tunnel"
        "npvt-ssh","dns","npvs1"->"NPVT / DNS"
        "slipnet","slipnet-plain"->"SlipNet"
        "wyrlite","wyrvpnlite","wyrl"->"WyrLite"
        "wyrvpn"->"WyrVPN"
        "intvpn"->"IntVPN"
        "juanscript","mobi"->"JuanScript"
        "eut-settings"->"EUT"
        "kivuvpn"->"Kivu VPN"
        "httptweak"->"HTTP Tweak"
        "creeb"->"Creeb Bundle"
        else->null
    }

    /**
     * A complete encrypted link can contain pasted line wrapping. Normalize
     * whitespace only for the two well-defined encoded alphabets; never join
     * unrelated chat messages or maintain fragment/part sessions.
     */
    private fun fullPastedPayload(text:String):Input? {
        val marker=text.indexOf("://")
        if(marker<=0 || marker>32)return null
        val scheme=text.substring(0,marker).lowercase(Locale.ROOT)
        val ssc=scheme=="ssc"
        val dark=scheme=="dt" || scheme=="dtunnel" || "dark" in scheme
        if(!ssc && !dark)return null
        val body=text.substring(marker+3).filterNot {
            it.isWhitespace() || it=='\u200b' || it=='\u200c' ||
                it=='\u200d' || it=='\ufeff' || it=='\u0060'
        }
        if(body.isBlank() || body.length>MAX_CHARS)return null
        val allowed=if(ssc)"0123456789abcdefABCDEF"
            else "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_=-"
        if(!body.all { it in allowed })return null
        return if(ssc)Input("ssc","SSC Custom","ssc","ssc://$body")
        else Input("dark","Dark Tunnel","dark","$scheme://$body")
    }

    fun identify(raw:String):Input? {
        if(raw.length>MAX_CHARS)return null
        val clean=raw.trim().replace("\ufeff","").replace("\u200b","")
        if(clean.startsWith("/decssh ",true))return Input("decssh","SSH","decssh",clean)
        TextPhaseGPort.identify(clean)?.let { return it }
        fullPastedPayload(clean)?.let { return it }
        for(match in links.findAll(clean)){
            val scheme=match.groupValues[1].lowercase(Locale.ROOT)
            val body=match.groupValues[2].trim().trimEnd(')',',',';',']')
            if(body.isEmpty())continue
            when {
                scheme=="tls"->return Input("tls","TLS Tunnel","tls","tls://$body")
                scheme=="ssc"->return Input("ssc","SSC Custom","ssc","ssc://$body")
                scheme=="dt"||scheme=="dtunnel"||"dark" in scheme->
                    return Input("dark","Dark Tunnel","dark","$scheme://$body")
                scheme=="vmess"->return Input("vmess","VMess","vmess",body)
                scheme=="zivpn"->return Input("zivpn","ZIVPN","zivpn",body)
                scheme=="howdy"||scheme=="n7pr"||scheme=="mark"->return Input("howdy","Howdy","howdy",body)
                scheme=="v2box"->return Input("v2box","V2Box","v2box","v2box://$body")
                scheme.startsWith("nm-")&&scheme.removePrefix("nm-") in nm->
                    return Input("netmod","NetMod","netmod",body)
                scheme.startsWith("ar-")&&scheme.removePrefix("ar-") in ar->
                    return Input("armod","ARMod","armod",body)
                scheme.startsWith("pb-")&&scheme.removePrefix("pb-") in pb->
                    return Input(if(scheme=="pb-vmess")"xraypb-vmess" else "xraypb",
                        "XrayPB","xraypb",body)
            }
        }
        // The Telegram bot also accepts bare NetMod AES-ECB ciphertext in
        // its fallback handler. Only a valid Base64 token is offered to this
        // single known-key route; decryption must yield genuine JSON.
        if(clean.length in 24..MAX_CHARS &&
            Regex("^[A-Za-z0-9+/_=-]+$").matches(clean))
            return Input("netmod","NetMod","netmod",clean)
        return null
    }

    fun decode(context:Context,input:Input):String? {
        if(input.content.length>MAX_CHARS)return null
        return try {
            val value:JsonElement=when {
                input.protocol.startsWith("g:") -> TextPhaseGPort.decode(context,input)
                else -> decodeLegacy(context,input)
            } ?: return null
            pretty.toJson(value).takeIf{it.toByteArray(Charsets.UTF_8).size<=MAX_CLEAR}
        }catch(_:Exception){null}
    }

    private fun decodeLegacy(context:Context,input:Input):JsonElement? {
        return when(input.protocol){
                "tls","dark","ssc"->{
                    val raw=AndroidOfflineDecoderRouter.decode(context,
                        "text."+input.suffix,input.content.toByteArray(Charsets.UTF_8))
                        ?:return null
                    JsonParser.parseString(ResultJsonDisplay.render(raw,input.suffix))
                }
                "vmess"->json(utf8(b64(input.content)))
                "netmod"->netmod(input.content)
                "armod"->armod(input.content)
                "xraypb","xraypb-vmess"->{
                    val first=cbcZeros(input.content,
                        "4p+ocx+hGTnbDdHOmzQCjVb9KTTSh+A3","android123456789")
                    val second=if(input.protocol=="xraypb-vmess")utf8(b64(first))
                        else first
                    json(second) ?: JsonObject().apply{addProperty("decodedText",second)}
                }
                "howdy"->howdy(input.content)
                "zivpn"->zivpn(input.content)
                "v2box"->v2box(input.content)
                "decssh"->ssh(input.content)
                else->null
            }
    }

    private fun utf8(bytes:ByteArray)=StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()

    private fun b64(value:String):ByteArray {
        val clean=value.trim().replace('-','+').replace('_','/')
            .filterNot{it.isWhitespace()}
        require(clean.isNotEmpty()&&clean.length<=MAX_CHARS)
        require(Regex("^[A-Za-z0-9+/]*={0,2}$").matches(clean))
        val data=Base64.decode(clean.padEnd((clean.length+3)/4*4,'='),Base64.DEFAULT)
        require(data.size<=MAX_CLEAR)
        return data
    }

    private fun json(value:String):JsonElement?=try {
        JsonParser.parseString(value).takeIf{it.isJsonObject||it.isJsonArray}
    }catch(_:Exception){null}

    private fun decrypt(ciphertext:ByteArray,key:ByteArray,mode:String,
        iv:ByteArray?=null):ByteArray {
        require(ciphertext.isNotEmpty()&&ciphertext.size<=MAX_CLEAR)
        val c=Cipher.getInstance(mode)
        if(iv==null)c.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"))
        else c.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        return c.doFinal(ciphertext)
    }
    /** The Telegram NetMod text handler decrypts with this text-specific
     * AES key, NOT the three candidate keys of the .nm file decoder.
     * The bot also accepts valid non-JSON plaintext after successful unpad;
     * such input must not be incorrectly marked as a failed decryption.
     */
    private fun netmod(value:String):JsonElement? {
        val encoded=b64(value)
        for(sourceKey in listOf("<n3t5yn4^n3tm0d>","_netsyna_netmod_","nicetrybuddygoon")){
            val clear=try{
                utf8(decrypt(encoded,sourceKey.toByteArray(Charsets.UTF_8),
                    "AES/ECB/PKCS5Padding"))
            }catch(_:Exception){continue}
            if(clear.isBlank())continue
            // Original standalone text decoder rejects arbitrary-looking
            // unpadded UTF-8, but accepts structured config or account data.
            if(clear.trimStart().startsWith("{")||clear.trimStart().startsWith("[")||
                "://" in clear||"=" in clear||"@" in clear) {
                return json(clear) ?: JsonObject().apply{addProperty("decodedText",clear)}
            }
        }
        return null
    }
    private fun cbcZeros(value:String,key:String,iv:String):String {
        val plain=decrypt(b64(value),key.toByteArray(Charsets.UTF_8),
            "AES/CBC/NoPadding",iv.toByteArray(Charsets.UTF_8))
        return utf8(plain.dropLastWhile{it==0.toByte()}.toByteArray())
    }

    private fun howdy(body:String):JsonObject? {
        val obj=json(utf8(b64(body)))?.takeIf{it.isJsonObject}?.asJsonObject?:return null
        // The original standalone Howdy text handler preserves ALL fields.
        // Unlike the 66.py screen formatting, optional attributes are not lost.
        val out=obj.deepCopy()
        for(key in listOf("server","sni")) {
            val field=out.get(key)
            if(field?.isJsonPrimitive==true && field.asJsonPrimitive.isString &&
                field.asString.isNotEmpty()){
                val original=field.asString
                val decoded=try {
                    val bytes=b64(original)
                    if(bytes.isEmpty()||bytes.size%16!=0)original
                    else {
                        val raw=decrypt(bytes,
                            "poiuytrewqas+=~|".toByteArray(Charsets.UTF_8),
                            "AES/CBC/NoPadding",
                            "r4tgv3b2zcmdW6ZZ".toByteArray(Charsets.UTF_8))
                        // Python tries PKCS7, falling back to trailing zeroes.
                        val pad=raw.last().toInt() and 255
                        val clear=if(pad in 1..16 &&
                            raw.takeLast(pad).all{(it.toInt() and 255)==pad})
                            raw.copyOf(raw.size-pad)
                            else raw.dropLastWhile{it==0.toByte()}.toByteArray()
                        utf8(clear)
                    }
                }catch(_:Exception){original}
                out.addProperty(key,decoded)
            }
        }
        return out
    }

    private fun zivpn(body:String):JsonObject? {
        val password=utf8(b64("dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ="))
        val key=MessageDigest.getInstance("SHA-256")
            .digest(password.toByteArray(Charsets.UTF_8))
        val xml=utf8(decrypt(b64(body),key,"AES/CBC/PKCS5Padding",ByteArray(16)))
        val out=JsonObject()
        val pattern=Regex("""<entry\s+key="([^"]+)"(?:\s*/>|>(.*?)</entry>)""")
        for(entry in pattern.findAll(xml)){
            out.addProperty(entry.groupValues[1],
                entry.groupValues[2].ifEmpty{"***"})
        }
        return out.takeIf{it.size()>0}
    }

    private fun armod(body:String):JsonObject? {
        val raw=utf8(decrypt(b64(body),b64("YXJ0dW5uZWw3ODc5Nzg5eA=="),
            "AES/ECB/PKCS5Padding"))
        val out=JsonObject()
        for(part in raw.split('&')) {
            // Python's parse_qs ignores segments without an equals sign and
            // drops blank values; it decodes '+' and %-escapes once.
            if('=' !in part)continue
            val key=URLDecoder.decode(part.substringBefore('='),"UTF-8")
                .lowercase(Locale.ROOT)
            if(key.isBlank())continue
            val value=URLDecoder.decode(part.substringAfter('='),"UTF-8")
            if(value.isEmpty())continue
            val displayed=if(key=="payload")URLDecoder.decode(value,"UTF-8")
                else value // The bot explicitly unquotes payload a second time.
            val nested=if(key=="profile")json(displayed) else null
            if(nested!=null)out.add(key,nested) else out.addProperty(key,displayed)
        }
        // Python also reports an SSH account embedded in the decrypted body.
        val ssh=Regex("""\S+:\S+@\S+:\d+""").find(raw)?.value
        if(ssh!=null && !out.has("ssh"))out.addProperty("ssh",ssh)
        return out.takeIf{it.size()>0}
    }

    private fun v2box(body:String):JsonObject? {
        val wrapped=Uri.parse(body)
        val locked=wrapped.getQueryParameter("locked")?:return null
        val uri=Uri.parse(utf8(b64(locked)))
        val out=JsonObject()
        for(key in uri.queryParameterNames){
            val values=uri.getQueryParameters(key)
            if(values.isNotEmpty())out.addProperty(key,values.joinToString(", "))
        }
        return out.takeIf{it.size()>0}
    }

    private fun ssh(body:String):JsonObject? {
        val source=body.substringAfter(' ',missingDelimiterValue="").trim()
        val host=source.substringBefore('@',missingDelimiterValue="")
        val auth=source.substringAfter('@',missingDelimiterValue="")
        val user=sshPart(auth.substringBefore(':'))
        val pass=sshPart(auth.substringAfter(':',missingDelimiterValue=""))
        if(host.isBlank()||user==null||pass==null)return null
        return JsonObject().apply {
            addProperty("host",host)
            addProperty("username",user)
            addProperty("password",pass)
            addProperty("ssh","$host@$user:$pass")
        }
    }

    private fun sshPart(raw:String):String? {
        val tokens=raw.split('.')
        if(tokens.size<2||tokens.size%2!=0||tokens.size>4096)return null
        val count=tokens.size/2
        val out=StringBuilder()
        for(i in 0 until count){
            val n=(tokens[i*2].toIntOrNull()?:return null)-count
            val shift=(tokens[i*2+1].toIntOrNull()?:return null)-count
            if(shift !in 0..30)return null
            out.append(((n shr shift)and 255).toChar())
        }
        return out.toString()
    }
}

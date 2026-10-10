package com.ghostdeveloper.spdecode

import android.content.Context
import android.net.Uri
import android.util.Base64
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.RenzPort
import com.ghostdeveloper.spdecode.parity.IndependentF1Port
import com.ghostdeveloper.spdecode.parity.IzphNativePort
import com.ghostdeveloper.spdecode.parity.NpvsPort
import com.ghostdeveloper.spdecode.parity.SpecialE1Port
import com.ghostdeveloper.spdecode.parity.SpecialE2Port
import com.ghostdeveloper.spdecode.parity.SpecialE3Port
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonArray
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.net.URLDecoder
import java.util.Locale

/**
 * Phase G: text-only offline protocol dispatcher. The text scheme is authoritative;
 * a shared file engine is invoked only when Python's text handler uses that SAME
 * source decoder. No key guesses or alternative cross-family fallbacks.
 */
internal object TextPhaseGPort {
    const val MAX = 250_000
    private val renzAliases=linkedMapOf(
        "7net" to "7net","7netvpn" to "7net",
        "tcx" to "tcx","tcxtunnelplus" to "tcx",
        "ihome" to "7net","ihomevpn" to "7net",
        "xhypher" to "xhypher","xhyphertunnelpro" to "xhypher",
        "osp" to "osp","osptunnel" to "osp",
        "actunnelvpn" to "actunnelvpn","actunnel" to "actun",
        "bshieldnet" to "bshield","bshield" to "bshield",
        "safetunnel" to "safetunnel","mhrtunnel" to "mhrtunnel",
        "letsvpngo" to "letsvpngo","aloplusvpn" to "aloplusvpn",
        "cranetunnel" to "cranetunnel","vipsnipherpro" to "vipsnipherpro",
        "deshtunnelvpn" to "deshtunnelvpn","hamotunnelplus" to "hamotunnelplus",
        "gcpvpn" to "gcpvpn"
    )
    val renzSchemes: Set<String> get()=renzAliases.keys.mapTo(linkedSetOf()){"$it://"}
    private val xorAliases=setOf("apnalite","apnatnl","bdnet","hxt","fnf",
        "4ulite","omanova","ursa","hsome","hamaratnl")
    private val wyrlite=setOf("wyrlite","wyrvpnlite","wyrl")
    private val specialAliases=linkedMapOf(
        "falcontunnel://import/" to "falcon",
        "slipnet-enc://" to "slipnet-enc",
        "eut-settings://" to "eut-settings",
        "npvt-ssh://" to "npvt-ssh",
        "izphvpnpro://" to "izph",
        "juanscript://" to "juanscript",
        "wyrvpnlite://" to "wyrvpnlite",
        "falcontunnel://" to "unsupported-falcon-no-import",
        "httptweak://" to "httptweak",
        "kivuvpn://" to "kivuvpn",
        "flexnet://" to "flex",
        "slipnet://" to "slipnet-plain",
        "wyrlite://" to "wyrlite",
        "wyrvpn://" to "wyrvpn",
        "intvpn://" to "intvpn",
        "npvs://" to "npvs",
        "vpvs://" to "npvs",
        "v2box://" to "v2box-export",
        "flex://" to "flex",
        "mobi://" to "mobi",
        "izph://" to "izph",
        "wyrl://" to "wyrl",
        "dns://" to "dns",
        "npvs1:" to "npvs1"
    )
    private val happVersions=setOf("crypt","crypt2","crypt3","crypt4")
    private val specialPrefixes by lazy{
        val result=linkedMapOf<String,String>()
        result.putAll(specialAliases)
        for(s in xorAliases)result["$s://"]="xor:$s"
        for(s in renzAliases.keys)result["$s://"]="renz:$s"
        for(s in happVersions)result["happ://$s/"]="happ:$s"
        result.entries.sortedByDescending{it.key.length}
    }
    /** Code paths are source-derived from the three modular Telegram handlers. */
    fun identify(raw:String):TextProtocolDecoder.Input?{
        if(raw.isBlank() || raw.length>MAX)return null
        val value=raw.trim()
        if(value.startsWith("{")){
            val parsed=try{JsonParser.parseString(value)}catch(_:Exception){null}
            if(parsed?.isJsonObject==true&&
                parsed.asJsonObject.get("type")?.asString=="creeb_profile_bundle")
                return TextProtocolDecoder.Input("g:creeb","Creeb Profile Bundle","creeb",value)
        }
        val prefix=specialPrefixes.firstOrNull{value.startsWith(it.key,ignoreCase=true)}
            ?:return null
        // The preexisting "locked=" V2Box share handler is covered by Phase A;
        // route encrypted export envelopes through their separate G path.
        if(prefix.key=="v2box://" && "locked=" in value.lowercase(Locale.ROOT))return null
        val route=prefix.value
        return TextProtocolDecoder.Input("g:$route",route.substringBefore(':'),
            "text",value)
    }

    private fun json(value:String):JsonElement?=try{JsonParser.parseString(value)}catch(_:Exception){null}
    private fun document(value:String):JsonElement? =
        json(value)?.takeIf{it.isJsonObject||it.isJsonArray}
    private fun text(value:String):JsonElement= document(value)?:JsonObject().apply{
        addProperty("decodedText",value)
    }
    private fun utf8(b:ByteArray):String=Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(b)).toString()
    private fun b64(value:String):ByteArray{
        val compact=value.filterNot{it.isWhitespace()}.replace('-','+').replace('_','/')
        require(compact.length in 1..MAX && compact.length%4!=1)
        require(compact.matches(Regex("[A-Za-z0-9+/]*={0,2}")))
        val data=Base64.decode(compact.padEnd((compact.length+3)/4*4,'='),Base64.DEFAULT)
        require(data.size<=2*1024*1024)
        return data
    }
    private fun payload(source:String)=source.substringAfter("://",missingDelimiterValue="").trim()
    private fun filename(ext:String)="text.$ext"
    private fun file(ctx:Context,ext:String,data:ByteArray):JsonElement?{
        val result=AndroidOfflineDecoderRouter.decode(ctx,filename(ext),data)?:return null
        return text(result)
    }

    fun decode(ctx:Context,input:TextProtocolDecoder.Input):JsonElement?{
        if(input.content.length>MAX || !input.protocol.startsWith("g:"))return null
        val scheme=input.protocol.removePrefix("g:")
        val source=input.content
        return try{
            when{
                scheme=="creeb"->creeb(source)
                scheme.startsWith("renz:")->renz(ctx,source,scheme.substringAfter(":"))
                scheme.startsWith("xor:")->{
                    val alias=scheme.substringAfter(":")
                    val ext=if(alias=="hamaratnl")"apnatnl" else alias
                    val decoded=SpecialE3Port.decode(ext,source.toByteArray(Charsets.UTF_8))
                    decoded?.let{ text(it) }
                }
                scheme.startsWith("happ:")->null // RSA private key not present on device.
                scheme=="falcon"->document(utf8(b64(source.substringAfter("/import/"))))
                scheme=="npvt-ssh"||scheme=="dns"->npvt(source)
                scheme=="npvs1"->npvs1(source)
                scheme=="npvs"->{
                    val bytes=b64(payload(source))
                    if(bytes.size<4 || !bytes.copyOfRange(0,4).contentEquals("NPVS".toByteArray()))
                        null else file(ctx,"npvs",bytes)
                }
                scheme=="flex"->{
                    val value=payload(source)
                    val bytes=if(value.startsWith("FLXCFG"))value.toByteArray(Charsets.UTF_8)
                        else b64(value)
                    if(bytes.size<6 || !bytes.copyOfRange(0,6).contentEquals("FLXCFG".toByteArray()))
                        null else file(ctx,"flex",bytes)
                }
                scheme=="v2box-export"->v2boxExport(source)
                scheme=="slipnet-plain"-> {
                    val clear=utf8(b64(payload(source)))
                    if(clear.isBlank())null else document(clear)?:JsonObject().apply{
                        addProperty("data",clear)
                    }
                }
                scheme=="slipnet-enc"->file(ctx,"slipnet",source.toByteArray(Charsets.UTF_8))
                scheme in wyrlite->file(ctx,"wyrlite",source.toByteArray(Charsets.UTF_8))
                scheme=="wyrvpn"->file(ctx,"wyr",source.toByteArray(Charsets.UTF_8))
                scheme=="intvpn"->file(ctx,"int",source.toByteArray(Charsets.UTF_8))
                scheme=="juanscript"||scheme=="mobi"->file(ctx,"mobi",source.toByteArray(Charsets.UTF_8))
                scheme=="eut-settings"->file(ctx,"eut",source.toByteArray(Charsets.UTF_8))
                scheme=="izph"->file(ctx,"izph",source.toByteArray(Charsets.UTF_8))
                scheme=="httptweak"->file(ctx,"ht",source.toByteArray(Charsets.UTF_8))
                scheme=="kivuvpn"->file(ctx,"dark",source.toByteArray(Charsets.UTF_8))
                else->null
            }
        }catch(_:Exception){null}
    }
    private fun renz(ctx:Context,source:String,alias:String):JsonElement?{
        val extension=renzAliases[alias]?:return null
        val result=RenzPort.decode(ctx,extension,source.toByteArray(Charsets.UTF_8))
            ?:return null
        val container=json(result)?.takeIf{it.isJsonObject}?.asJsonObject?:return null
        val config=container.get("config")?:return null
        val appName= if(alias in setOf("7net","osp"))"RENZ / 7NET"
            else "RENZ / "+(when(extension){
                "actun"->"ACTUNNELVPN"
                "tcx"->"TCXTUNNEL"
                else-> if(alias in setOf("ihome","ihomevpn","7netvpn","osptunnel"))"7NET"
                    else if(alias=="bshieldnet")"BSHIELD"
                    else extension.uppercase(Locale.ROOT)
            })
        return JsonObject().apply {
            addProperty("application",appName)
            addProperty("protocol","$alias://")
            add("config",config)
        }
    }
    private fun npvs1(source:String):JsonElement?{
        val inner=source.trim()
        val obj=nestedNpvs(JsonPrimitive(inner),0)
        return if(obj.isJsonPrimitive&&obj.asString==inner)null
            else if(obj.isJsonPrimitive)JsonObject().apply{addProperty("decodedText",obj.asString)}
            else obj
    }
    private fun nestedNpvs(node:JsonElement,depth:Int):JsonElement{
        if(depth>12)return node
        return when {
            node.isJsonObject->{
                val obj=node.asJsonObject
                for((k,v) in obj.entrySet().toList())obj.add(k,nestedNpvs(v,depth+1))
                obj
            }
            node.isJsonArray->{
                val a=node.asJsonArray
                for(i in 0 until a.size())a.set(i,nestedNpvs(a[i],depth+1))
                a
            }
            node.isJsonPrimitive && node.asJsonPrimitive.isString &&
                node.asString.startsWith("npvs1:")->{
                val value=try{utf8(b64(node.asString.substring(6)))}catch(_:Exception){return node}
                val nested=document(value)
                if(nested!=null)nestedNpvs(nested,depth+1) else JsonPrimitive(value)
            }
            else->node
        }
    }
    private fun npvt(source:String):JsonElement?{
        val clear=utf8(b64(payload(source)))
        val parsed=document(clear)?:return null
        return nestedNpvs(parsed,0)
    }

    private fun v2boxExport(source:String):JsonElement?{
        val value=payload(source)
        val data=if(value.startsWith("{"))document(value) else document(utf8(b64(value)))
        val obj=data?.takeIf{it.isJsonObject}?.asJsonObject?:return null
        if(obj.get("magic")?.asString!="v2box_export")return null
        val normalized=JsonObject()
        for((key,field) in obj.entrySet()){
            if(key in setOf("nonce","tag","ciphertext")){
                if(!field.isJsonPrimitive)return null
                val bytes=b64(field.asString)
                normalized.addProperty(key,Base64.encodeToString(bytes,Base64.NO_WRAP))
            }else normalized.add(key,field)
        }
        if(normalized.get("isPasswordProtected")?.asBoolean==true)
            return JsonObject().apply {
                addProperty("passwordRequired",true)
                addProperty("status","requires_user_password")
            }
        val raw=Base64.encodeToString(normalized.toString().toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP)
        val output=SpecialE1Port.decode("v2box",raw.toByteArray(Charsets.UTF_8))?:return null
        return document(output)?:return null
    }

    private val link=Regex(
        """(?i)(?:vmess|vless|trojan|ss|ssr|hysteria2|hy2|tuic|socks)://[^\s"'<>\\]+""")
    private fun creeb(source:String):JsonElement?{
        val original=document(source)?.takeIf{it.isJsonObject}?.asJsonObject?:return null
        if(original.get("type")?.asString!="creeb_profile_bundle")return null
        val rawProfiles=original.get("profiles")
        val profiles= if(rawProfiles==null||rawProfiles.isJsonNull)JsonArray()
            else rawProfiles.takeIf{it.isJsonArray}?.asJsonArray?:return null
        if(profiles.size()>10_000)return null
        val processed=JsonArray()
        for(row in profiles){
            if(!row.isJsonObject)continue
            val obj=row.asJsonObject
            val seen=linkedSetOf<String>()
            val inputs=mutableListOf<String>()
            val prefs=obj.get("prefs")
            if(prefs?.isJsonObject==true)for((_,v)in prefs.asJsonObject.entrySet())
                if(v.isJsonPrimitive && v.asJsonPrimitive.isString)inputs.add(v.asString)
            inputs.add(obj.toString())
            for(value in inputs)for(match in link.findAll(value))seen.add(match.value)
            val extracted=JsonObject()
            for(field in listOf("name","hostPort","tunnelType")){
                extracted.add(field,obj.get(field)?:JsonPrimitive(""))
            }
            val urls=JsonArray()
            seen.forEach{urls.add(it)}
            extracted.add("links",urls)
            processed.add(extracted)
        }
        return JsonObject().apply {
            addProperty("type","creeb_profile_bundle")
            add("version",original.get("version")?:JsonPrimitive(1))
            add("message",original.get("message")?:JsonPrimitive(""))
            add("security",original.get("security")?:JsonObject())
            add("profiles",processed)
            add("original_bundle",original)
        }
    }
}

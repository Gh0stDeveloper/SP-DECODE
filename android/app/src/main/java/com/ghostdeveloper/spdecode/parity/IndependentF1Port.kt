package com.ghostdeveloper.spdecode.parity

import android.content.Context
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import android.util.Xml
import org.xmlpull.v1.XmlPullParser
import java.io.StringReader

/** F.1 — FlexNet, LTM Tunnel and VN7 independent native source ports. */
internal object IndependentF1Port {
    private val c=IndependentCrypto
    private val s=SpecialCrypto
    const val MAX_INPUT_BYTES=2*1024*1024
    private val magic="FLXCFG".toByteArray(Charsets.US_ASCII)
    private val ltmHex="333a33333232c933cc393d3b3e38383fcbcfc8cbc9cf333f3e3ccb3a32cb3ccf"+
        "3dcb3239c9cfc83c3c3a393f3e3332cf333fce3839cc3d323ec8c8ce32c83333"+
        "898ee1ea8b"
    private val ltmPassword=String(c.hex(ltmHex),Charsets.UTF_8).toByteArray(Charsets.UTF_8)
    private val vn7Keys=listOf(
        "SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5",
        "fubvx788b46v"
    ).map {it.toByteArray()}

    @Volatile private var flexMaterials:Map<String,ByteArray>?=null
    private fun materialProfiles(ctx:Context):Map<String,ByteArray> =
        flexMaterials ?: synchronized(this) {
            flexMaterials ?: loadMaterials(ctx).also {flexMaterials=it}
        }
    private fun loadMaterials(ctx:Context):Map<String,ByteArray> {
        val root=JSONObject(ctx.assets.open("flex_f_profiles.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        require(root.getInt("schemaVersion")==1 && root.getInt("materialCount")==30)
        val doc=root.getJSONObject("materials")
        val result=linkedMapOf<String,ByteArray>()
        val ids=doc.keys()
        while(ids.hasNext()) {
            val id=ids.next()
            require(id.matches(Regex("[1-4],\\d+")))
            val raw=c.hex(doc.getString(id))
            require(raw.size in 1..2048)
            result[id]=raw
        }
        require(result.size==30 && "1,0" in result && "2,0" in result &&
            "3,0" in result && "4,0" in result)
        return result
    }
    private fun flexMaterial(ctx:Context,version:Int,lock:Int):ByteArray {
        val all=materialProfiles(ctx)
        if(version in 1..2)return all["$version,0"]?:error("No Flex material")
        return all["$version,$lock"] ?: all.entries
            .filter{it.key.startsWith("$version,")}
            .minByOrNull{ kotlin.math.abs(it.key.substringAfter(',').toInt()-lock) }
            ?.value ?: error("Unknown Flex version")
    }

    fun decode(ctx:Context,suffix:String,input:ByteArray):String? {
        if(input.isEmpty()||input.size>MAX_INPUT_BYTES)return null
        return try{when(suffix){
            "flex","flexnet"->flex(ctx,input)
            "lt","ltm"->ltm(input)
            "vn7"->vn7(input)
            else->null
        }}catch(_:Exception){null}
    }

    private fun properties(xml:String):Pair<LinkedHashMap<String,String>,String?>{
        require(xml.length<=MAX_INPUT_BYTES)
        val cleaned=Regex("&#([xX]?[0-9a-fA-F]+);").replace(xml){ match->
            val part=match.groupValues[1]
            val value=try{
                if(part.startsWith("x",true))part.substring(1).toInt(16)
                else part.toInt()
            }catch(_:Exception){-1}
            if(value==9||value==10||value==13||
                value in 0x20..0xD7FF || value in 0xE000..0xFFFD ||
                value in 0x10000..0x10FFFF) match.value else ""
        }
        // Android's XML DocumentBuilder does not uniformly support all JAXP
        // external-entity features. Reject DTD/ENTITY outright, then use the
        // platform XmlPullParser with no external entity resolver.
        require(!cleaned.contains("<!DOCTYPE",ignoreCase=true) &&
            !cleaned.contains("<!ENTITY",ignoreCase=true))
        val parser=Xml.newPullParser()
        parser.setInput(StringReader(cleaned))
        val result=linkedMapOf<String,String>()
        var comment:String?=null
        while(parser.eventType!=XmlPullParser.END_DOCUMENT){
            if(parser.eventType==XmlPullParser.START_TAG && parser.depth==2){
                when(parser.name) {
                    "entry" -> {
                        val key=parser.getAttributeValue(null,"key")
                        val value=parser.nextText()
                        if(key!=null)result[key]=value
                    }
                    "comment" -> {
                        val text=parser.nextText()
                        if(comment==null&&text.isNotEmpty())comment=text
                    }
                }
            }
            parser.next()
        }
        return Pair(result,comment)
    }
    private fun flex(ctx:Context,input:ByteArray):String?{
        require(input.size>=18 && input.copyOfRange(0,6).contentEquals(magic))
        val b=ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN)
        b.position(6)
        val version=b.get().toInt() and 255
        require(version in 1..4)
        val lock=if(version>=3) b.int else 0
        if(version>=3)require(lock>0)
        val iterations=b.int
        require(iterations in 10000..500000)
        val originalPos=b.position()
        if(version==4){
            try {
                b.get()
                val keyLength=b.get().toInt() and 255
                if(keyLength in 1..64 && b.remaining()>=keyLength)
                    b.position(b.position()+keyLength)
                else b.position(originalPos)
            }catch(_:Exception){b.position(originalPos)}
        }
        var saltLen=b.get().toInt() and 255
        if(saltLen !in 32..64 && version==4 && b.position()-1!=originalPos) {
            b.position(originalPos)
            saltLen=b.get().toInt() and 255
        }
        require(saltLen in 32..64 && b.remaining()>=saltLen+1+12+4+16)
        val salt=ByteArray(saltLen).also{b.get(it)}
        val nonceLen=b.get().toInt() and 255
        require(nonceLen==12 && b.remaining()>=nonceLen+4+16)
        val nonce=ByteArray(nonceLen).also{b.get(it)}
        val len=b.int
        require(len in 17..0x400000 && len<=b.remaining())
        val payload=ByteArray(len).also{b.get(it)}
        val material=flexMaterial(ctx,version,lock)
        // Python material.decode('latin-1').encode('utf-8') (not raw bytes).
        val password=String(material,Charsets.ISO_8859_1).toByteArray(Charsets.UTF_8)
        val key=c.pbkdfSha512(password,salt,iterations,32)
        val aad=if(version>=3 && lock>0)
            magic+byteArrayOf(version.toByte())+ByteBuffer.allocate(4)
                .order(ByteOrder.BIG_ENDIAN).putInt(lock).array()
            else null
        val clear=c.gcmAad(key,nonce,payload,aad)
        val uncompressed=c.inflateCompressed(clear,
            gzip=clear.size>=2 && (clear[0].toInt() and 255)==31 &&
                (clear[1].toInt() and 255)==139)
        val xml=c.utf8Ignore(uncompressed)
        val props=properties(xml).first
        val result=JsonObject()
        result.addProperty("app","FlexNet")
        val raw=JsonObject()
        for((k,v) in props)raw.addProperty(k,v)
        result.add("rawProperties",raw)
        fun v(key:String)=props[key]?.takeIf{it.isNotEmpty()}
        v("file.validade")?.let{
            try{
                val millis=it.toLong()
                val fmt=SimpleDateFormat("yyyy-MM-dd HH:mm:ss",Locale.US)
                result.addProperty("configExpiry",fmt.format(Date(millis)))
            }catch(_:Exception){}
        }
        val tunnel=JsonObject()
        v("tunnelType")?.let{tunnel.addProperty("type",it.toInt())}
        v("proxyPayload")?.let{tunnel.addProperty("payload",it)}
        v("customSni")?.let{tunnel.addProperty("sni",it)}
        v("sshPortaLocal")?.let{tunnel.addProperty("localPort",it.toInt())}
        v("udpResolver")?.let{tunnel.addProperty("udpResolver",it)}
        v("udpForward")?.let{tunnel.addProperty("udpForward",it.toInt()!=0)}
        v("dnsForward")?.let{tunnel.addProperty("dnsForward",it.toInt()!=0)}
        if(tunnel.size()>0)result.add("tunnel",tunnel)
        v("sshServer")?.let{
            val server=JsonObject()
            for((out,key) in listOf("host" to "sshServer","port" to "sshPort",
                "username" to "sshUser","password" to "sshPass"))
                server.addProperty(out,props[key]?:"")
            result.add("manualServer",server)
        }
        v("remoteServerSnapshot")?.let{
            try{
                val source=JsonParser.parseString(it).asJsonObject
                val obj=JsonObject()
                for((out,key) in listOf("name" to "name","flag" to "flag",
                    "host" to "host","sshPort" to "port","proxyPort" to "proxyPort",
                    "sslPort" to "sslPort","username" to "username",
                    "password" to "password"))
                    obj.add(out,source.get(key)?:JsonNull.INSTANCE)
                result.add("selectedServer",obj)
            }catch(_:Exception){}
        }
        v("remoteServerCache")?.let{
            try {
                val servers=JsonParser.parseString(it).asJsonObject.getAsJsonArray("servers")
                val arr=JsonArray()
                for(element in servers){
                    if(!element.isJsonObject)continue
                    val obj=element.asJsonObject
                    val one=JsonObject()
                    for((out,key) in listOf("id" to "id","name" to "name",
                        "flag" to "flag","modes" to "supportedModes","host" to "host",
                        "sshPort" to "port","proxyPort" to "proxyPort",
                        "sslPort" to "sslPort","username" to "username",
                        "password" to "password"))
                        one.add(out,obj.get(key)?:if(out=="modes")JsonArray() else JsonNull.INSTANCE)
                    arr.add(one)
                }
                if(arr.size()>0){result.addProperty("serverCount",arr.size());result.add("servers",arr)}
            }catch(_:Exception){}
        }
        val lockObj=JsonObject()
        if(v("file.proteger")=="1")lockObj.addProperty("protected",true)
        if(v("file.pedirLogin")=="1")lockObj.addProperty("loginRequired",true)
        if(lockObj.size()>0){
            v("file.renewalLink")?.let{lockObj.addProperty("renewalLink",it)}
            result.add("lock",lockObj)
        }
        v("remoteServerSelection")?.let{result.addProperty("serverSelection",it)}
        val meta=JsonObject()
        for(field in listOf("file.validade","file.msg","file.hwidLock","file.networkLock",
            "file.minAppVersionCode","file.attestLocked","configAttestLock")) {
            v(field)?.let{meta.addProperty(field,it)}
        }
        if(meta.size()>0)result.add("meta",meta)
        return s.gson.toJson(result)
    }

    private fun ltm(input:ByteArray):String?{
        var text=c.stripScheme(c.utf8Ignore(input).trim())
        text=text.filterNot{it.isWhitespace()}
        val parts=text.split(".")
        require(parts.size==3)
        val salt=c.b64(parts[0]);val nonce=c.b64(parts[1]);val raw=c.b64(parts[2])
        require(salt.isNotEmpty() && nonce.size==12 && raw.size>=17)
        val key=s.pbkdf(ltmPassword,salt,1000,16)
        val plain=c.utf8(c.gcmAad(key,nonce,raw,null))
        val (values,comment)=properties(plain)
        val out=JsonObject()
        for((k,v) in values)out.addProperty(k,v)
        if(comment!=null)out.addProperty("_comment",comment)
        return s.gson.toJson(out)
    }

    private fun vn7(input:ByteArray):String? {
        val parts=c.utf8Ignore(input).split(".")
        require(parts.size==3)
        val salt=c.b64(parts[0]);val nonce=c.b64(parts[1]);val enc=c.b64(parts[2])
        require(salt.isNotEmpty() && nonce.size==12 && enc.size>=17)
        for(password in vn7Keys)try {
            val key=s.pbkdf(password,salt,1000,16)
            val out=c.utf8(c.gcmAad(key,nonce,enc,null))
            if(out.isNotBlank())return s.render(out)
        }catch(_:Exception){}
        return null
    }
}

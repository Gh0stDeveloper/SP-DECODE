package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject

/**
 * Native 32-bit TEA-family behavior from decoders/JavaScript/rez.js and stk.js.
 * Int overflow and key words are identical to JavaScript bitwise operations.
 */
internal object LegacyTeaSourcePort {
    private val p=LegacyPortPrimitives
    private const val DELTA = -0x658C6C4C
    private fun words(raw:ByteArray):IntArray {
        require(raw.isNotEmpty() && raw.size<=p.MAX_INPUT)
        return IntArray((raw.size+3)/4) { i ->
            var word=0
            for(j in 0..3)if(i*4+j<raw.size)
                word=word or ((raw[i*4+j].toInt() and 255) shl (j*8))
            word
        }
    }
    fun open(input:ByteArray,password:String):String {
        p.bounded(input)
        val bytes=p.b64(p.utf8(input).trim())
        val blocks=words(bytes)
        require(blocks.size>=2)
        val key=words(password.toByteArray(Charsets.UTF_8).copyOf(16))
        val n=blocks.size
        var sum=(6+52/n)*DELTA
        var y=blocks[0]
        while(sum!=0) {
            val e=(sum ushr 2) and 3
            for(i in n-1 downTo 0) {
                val z=blocks[if(i>0)i-1 else n-1]
                val mx=((((z ushr 5) xor (y shl 2)) +
                    ((y ushr 3) xor (z shl 4))) xor
                    ((sum xor y) + (key[(i and 3) xor e] xor z)))
                y=blocks[i]-mx
                blocks[i]=y
            }
            sum-=DELTA
        }
        val clear=ByteArray(n*4)
        blocks.forEachIndexed{i,v->for(j in 0..3)clear[i*4+j]=(v ushr (j*8)).toByte()}
        return p.utf8(clear.dropLastWhile{it==0.toByte()}.toByteArray())
    }
    private fun str(value:Any?):String=when(value) {
        null,JSONObject.NULL->"undefined"
        is Boolean->if(value)"true" else "false"
        else->value.toString()
    }
    fun renderRez(input:ByteArray):String?=p.safeDecode {
        val clear=open(input,"@technore24 2022")
        val obj=JSONObject(clear.substringBefore("}")+"}")
        val fields=listOf("PSInstall" to "PS Install","DeviceID" to "Device ID",
            "RootBlock" to "Block Root","MobileData" to "Mobile Data",
            "ExpireDate" to "Expire Date","Message" to "Message",
            "Payload" to "Payload","isDirect" to "Is Direct",
            "isSSL" to "Is SSL","isWS" to "Is WS","isDNS" to "Is DNS",
            "Server" to "Server Date")
        val content=fields.mapNotNull{(name,label)->
            if(name in setOf("DeviceID","Server") && (obj.isNull(name) || obj.optString(name).isEmpty())) null
            else "│[۞] "+label+": "+str(obj.opt(name))+"\n"
        }.joinToString("")
        require(obj.has("PSInstall"))
        p.header("(.rez)")+"\n"+content+p.footer()
    }
    fun renderStk(input:ByteArray):String?=p.safeDecode {
        val decrypted=open(input,"Bgw34Nmk")
            .replace("}\"","").replace("\\","").replace("{\"config\":\"","")
        val index=decrypted.lastIndexOf('}')
        require(index>=0)
        val original=decrypted.substring(0,index+1)
        val obj=try {JSONObject(original)} catch (_:Exception) {
            JSONObject(original.replace(Regex("[^\\x20-\\x7E]"),"")
                .replace(Regex(",\\s*\"creator_note\":\".*?\"\\s*}"),"}"))
        }
        val labels=linkedMapOf(
            "connection_mode" to "Connection mode","server_port" to "Server port",
            "use_proxy" to "Use proxy","use_v2ray_mod" to "Use V2Ray mod",
            "proxy_host" to "Proxy host","proxy_port" to "Proxy port",
            "custom_payload" to "Custom payload","custom_host" to "Custom host",
            "custom_sni" to "Custom SNI","custom_resolver" to "Custom resolver",
            "expiry" to "Expiry","lock_hwid" to "Lock HWID",
            "mobile_data" to "Mobile data","block_root" to "Block root",
            "creator_note" to "Creator note")
        val content=labels.entries.filter {obj.has(it.key)}.joinToString("") {
            "│[۞] "+it.value+": "+str(obj.get(it.key))+"\n"
        }
        require(content.isNotEmpty())
        p.header("(.stk)",leadingLine=true)+"\n"+content+p.footer()
    }
}

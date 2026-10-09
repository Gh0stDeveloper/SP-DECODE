package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Source-specific hat.js AES-128-ECB, profile mapping and local nodehat labels. */
object HatPort {
    private val p=LegacyPortPrimitives
    private val modes=listOf("Direct Connection","Custom Payload (TCP)",
        "Custom Host Header (HTTP)","Custom SNI (SSL/TLS)","Imported Config")
    private val configModes=listOf("SSH","SSL + SSH")
    private val countries=mapOf(
        "xx" to "Random Server, Any Location 🌍","us" to "United States, New York 🇺🇸",
        "ca" to "Canada, Montréal 🇨🇦","de" to "Germany, Frankfurt 🇩🇪",
        "uk" to "United Kingdom, London 🇬🇧","nl" to "Netherlands, Amsterdam 🇳🇱",
        "fr" to "France, Paris 🇫🇷","at" to "Vienne, Austria 🇦🇹",
        "au" to "Australia, Tasmania 🇦🇺","br" to "Brazil, Sao-Paulo 🇧🇷",
        "sg" to "Singapore, Simpang 🇸🇬","in" to "India, Bangalore 🇮🇳",
        "gb" to "Game | EU 🎮")
    private fun js(v:Any?):String=when(v) {
        null,JSONObject.NULL->"undefined"
        is Boolean->if(v)"true" else "false"
        else->v.toString()
    }
    private fun truth(v:Any?):Boolean=when(v) {
        null,JSONObject.NULL->false
        is Boolean->v
        is Number->v.toDouble()!=0.0
        else->v.toString().isNotEmpty()
    }
    private fun xorB64(encoded:String):String {
        val raw=p.utf8(p.b64(encoded))
        val key="**rVg7EkL~c2"+96.toChar()+"D[aNn"
        return buildString {raw.forEachIndexed{i,ch->
            append((ch.code xor key[i%key.length].code).toChar())}}
    }
    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val encoded=p.b64(p.utf8(input).trim())
        require(encoded.isNotEmpty()&&encoded.size%16==0)
        val aes=Cipher.getInstance("AES/ECB/PKCS5Padding")
        aes.init(Cipher.DECRYPT_MODE,SecretKeySpec(p.b64("zbNkuNCGSLivpEuep3BcNA=="),"AES"))
        val obj=JSONObject(p.utf8(aes.doFinal(encoded)))
        val layout=JSONObject(context.assets.open("nodehat_original_layout.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        val fields=linkedMapOf<String,String>()
        fun put(key:String,v:Any?){fields[key]=js(v)}
        fun copy(cfg:JSONObject,source:String,dest:String){put(dest,cfg.opt(source))}
        obj.optJSONObject("configuration")?.let{cfg->
            val n=cfg.optInt("connection_mode",-1)
            if(n in configModes.indices)put("connectionMethod",configModes[n])
            for((src,dst)in linkedMapOf(
                "using_http_headers" to "usePayload","http_headers" to "payload",
                "server_group_host" to "aotServerGroup","using_proxy" to "enableHTTPProxy",
                "using_server_hosted_proxy" to "aotUseHostAsProxy",
                "proxy_host" to "proxyAddress","proxy_port" to "proxyPort",
                "aotServerPort" to "aotServerPort","using_advssl" to "useSSL",
                "adv_ssl_spoofhost" to "sniValue","adv_ssl_spoofport" to "serverPort",
                "vpn_udpgw_port" to "udpgwPort","server_host" to "sshServer",
                "server_username" to "sshUser","server_password" to "sshPassword"))
                copy(cfg,src,dst)
        }
        obj.optJSONObject("meta")?.let{copy(it,"meta_vendor_msg","note1")}
        for((profile,description)in listOf("profile" to "description",
            "profilev4" to "descriptionv4","profilev5" to "descriptionv5")){
            obj.optJSONObject(profile)?.let{cfg->
                if(profile=="profilev5"){
                    put("connectionMethod",xorB64(cfg.getString("connection_mode")))
                    for((s,d)in listOf("custom_payload" to "payload",
                        "custom_host" to "hostHeader","custom_sni" to "sniValue"))
                        put(d,xorB64(cfg.getString(s)))
                    copy(cfg,"custom_resolver","customresolver")
                    copy(cfg,"dns_primary_host","dnsprimaryhost")
                }else{
                    val n=cfg.optInt("connection_mode",-1)
                    if(n in modes.indices)put("connectionMethod",modes[n])
                    for((s,d)in listOf("custom_payload" to "payload",
                        "custom_host" to "hostHeader","custom_sni" to "sniValue"))
                        copy(cfg,s,d)
                }
                put("aotRealmHost",if(truth(cfg.opt("use_realm_host")))js(cfg.opt("realm_host")) else "")
                copy(cfg,"realm_host","aotRealmHostValue")
                put("aotOverrideHost",if(truth(cfg.opt("override_primary_host")))js(cfg.opt("primary_host")) else "")
                copy(cfg,"primary_host","aotPrimaryHost")
                put("serverPort",if(truth(cfg.opt("server_port")))js(cfg.opt("server_port"))else"")
                copy(cfg,"primary_node","aotNode")
                copy(cfg,"base_tunnel","aotBaseTunnel")
            }
            if(truth(obj.opt(description)))put("note1",obj.opt(description))
        }
        if(truth(obj.opt("description")))put("note1",obj.opt("description"))
        obj.optJSONObject("protextras")?.let{cfg->
            for((s,d)in linkedMapOf(
                "anti_sniff" to "antiSniff","mobile_data" to "mobileData",
                "block_root" to "blockRoot","password" to "passwordProtected",
                "password_value" to "cryptedPasswordValueMD5",
                "id_lock" to "hwidEnabled","id_lock_value" to "cryptedHwidValueMD5",
                "expiry" to "enableExpire"))if(cfg.has(s))copy(cfg,s,d)
        }
        fields["aotNode"]?.let{ countries[it]?.let{translated->fields["aotNode"]=translated} }
        for(k in p.keys(layout))if(obj.has(k)&&truth(obj.opt(k)))put(k,obj.opt(k))
        require(fields.isNotEmpty())
        val output=fields.entries.joinToString(""){(k,v)->
            "│[۞] "+layout.optString(k,"undefined")+v+"\n"
        }
        p.header("(.hat)",leadingLine=true)+"\n"+output+p.footer()
    }
}

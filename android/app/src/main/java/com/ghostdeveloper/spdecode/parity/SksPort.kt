package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import java.security.MessageDigest

/**
 * Original sks.js only: MD5 configKeys[1] + space + version, ASCII-hex MD5 as
 * AES-256 key, supplied payload IV. No internet and no key fallback.
 */
object SksPort {
    private val p=LegacyPortPrimitives
    private const val CONFIG_KEY="162exe235948e37ws6d057d9d85324e2"
    private fun truth(value:Any?):Boolean=when(value) {
        null,JSONObject.NULL -> false
        is Boolean ->value
        is Number ->value.toDouble()!=0.0
        else->value.toString().isNotEmpty()
    }
    private fun js(value:Any?):String=when(value){
        null,JSONObject.NULL ->"undefined"
        is Boolean->if(value)"true" else "false"
        else->value.toString()
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val profile=JSONObject(p.utf8(input))
        val digest=MessageDigest.getInstance("MD5")
            .digest((CONFIG_KEY+" "+profile.get("v").toString()).toByteArray(Charsets.UTF_8))
        val password=digest.joinToString("") { "%02x".format(it.toInt() and 255) }
            .toByteArray(Charsets.US_ASCII)
        val fields=profile.getString("d").split('.')
        require(fields.size==2)
        val clear=p.utf8(p.cbc(p.b64(fields[0]),password,p.b64(fields[1])))
        val obj=JSONObject(clear)
        val ssh=obj.getJSONObject("profileSshAuth")
        val out=StringBuilder(p.header("(.sks)")).append("\n")
        fun line(label:String,v:Any?) {out.append("│[۞] ").append(label).append(": ").append(js(v)).append('\n')}
        line("SSH Server",obj.opt("sshServer"))
        line("SSH Port",obj.opt("sshPort"))
        line("SSH Username",ssh.opt("sshUser"))
        for ((name,label) in listOf("sshPasswd" to "SSH Password",
            "sshPublicKey" to "SSH PublicKey"))if(truth(ssh.opt(name)))line(label,ssh.opt(name))
        for((name,label) in listOf("enableDataCompression" to "Enable Data Compress",
            "disableTcpDelay" to "Disable TCP Delay"))if(truth(obj.opt(name)))line(label,obj.opt(name))
        val proxyType=obj.optString("proxyType")
        if(proxyType.isEmpty())line("Tunnel Type","SSH DIRECT")
        else line("Tunnel type",when(proxyType){
            "PROXY_HTTP"->"SSH + HTTP"
            "PROXY_SSL"->"SSH + SSL/TLS"
            else->"Undefined"
        })
        obj.optJSONObject("proxyHttp")?.let { part ->
            for((name,label) in listOf("proxyIp" to "Proxy Host","proxyPort" to "Proxy Port",
                "isCustomPayload" to "Use Custom Payload Proxy","customPayload" to "Proxy Payload"))
                if(truth(part.opt(name)))line(label,part.opt(name))
        }
        obj.optJSONObject("proxySsl")?.let { part ->
            for((name,label) in listOf("hostSni" to "SNI Value","versionSSl" to "SSL Version",
                "isSSLCustomPayload" to "Use Custom Payload SSL","customPayloadSSL" to "SSL Payload"))
                if(truth(part.opt(name)))line(label,part.opt(name))
        }
        obj.optJSONObject("proxyDirect")?.let { part ->
            for((name,label) in listOf("isCustomPayload" to "Use Custom Payload",
                "customPayload" to "Payload"))if(truth(part.opt(name)))line(label,part.opt(name))
        }
        if(truth(obj.opt("dnsCustom")))line("Custom DNS Servers",obj.get("dnsCustom").toString())
        if(truth(obj.opt("isUdpgwForward")))line("Forward UDPGW",obj.opt("isUdpgwForward"))
        obj.optJSONObject("configProtect")?.let{ part ->
            for((name,label) in listOf("blockConfig" to "Block config",
                "blockRoot" to "Block Root","blockAuthEdition" to "Only Playstore",
                "onlyMobileData" to "Only Mobile Data","blockByPhoneId" to "HWID Enabled",
                "message" to "Note","phoneId" to "HWID Value",
                "hideMessageServer" to "Hide Server Message"))
                if(truth(part.opt(name)))line(label,part.opt(name))
            out.append(p.footer())
        }
        require(out.length>p.header("(.sks)").length)
        out.toString()
    }
}

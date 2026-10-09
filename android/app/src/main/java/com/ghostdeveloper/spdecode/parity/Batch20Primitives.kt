package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Shared low-level JCA only; no dispatch, key guessing or cross-format fallback. */
internal object Batch20Primitives {
    private val p = LegacyPortPrimitives
    fun ecb(input: ByteArray, key: ByteArray): ByteArray {
        require(input.isNotEmpty() && input.size <= p.MAX_INPUT && input.size % 16 == 0)
        val c = Cipher.getInstance("AES/ECB/PKCS5Padding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(input)
    }
    fun des(input: ByteArray, key: ByteArray): String {
        require(key.size == 8 && input.isNotEmpty() && input.size <= p.MAX_INPUT &&
            input.size % 8 == 0)
        val c = Cipher.getInstance("DES/ECB/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "DES"))
        return String(c.doFinal(input), Charsets.UTF_8).trim()
    }
    private val labels = linkedMapOf(
        "sshServer" to "SSH Server", "sshPort" to "SSH Port", "sshUser" to "SSH User",
        "sshPass" to "SSH Password", "sshPortLocal" to "Local Port",
        "proxyPayload" to "Proxy Payload", "sslHost" to "SSL Host",
        "proxyRemotePort" to "Remote Proxy", "proxyRemote" to "Remote Proxy Port",
        "proxyuser" to "Proxy User", "proxypass" to "Proxy Password",
        "sslProtocol" to "SSL Protocol", "sniHost" to "SNI Host",
        "cUUID" to "UUID", "dnspu" to "PublicKey", "dnsnameserver" to "DNS Name Server",
        "sshAllinOne" to "SSH Field", "nameServer" to "NameServer",
        "publickey" to "PublicKey", "udpserver" to "UDP Server",
        "dnsResolver" to "Primary DNS", "udpResolver" to "UDPGW",
        "up_mbps" to "Upload Mbps", "down_mbps" to "Download Mbps",
        "udpwindow" to "QUIC Windows", "udpauth" to "Authentication",
        "udpobfs" to "Obfuscate", "sshPortaLocal" to "Local Port"
    )
    private val pcx = linkedMapOf(
        "sshServer" to "SSH Server", "sshPort" to "SSH Port",
        "sshUser" to "SSH User", "sshPass" to "SSH Password",
        "sslSNI" to "SSL SNI", "proxyPayload" to "Proxy Payload",
        "up_mbps" to "Upload Mbps", "down_mbps" to "Download Mbps",
        "udpwindow" to "QUIC Window", "udpauth" to "Authentication",
        "udpobfs" to "Obfuscate", "serverNameKey" to "Server Name Key",
        "dnsKey" to "DNS Key", "chaveKey" to "PublicKey",
        "primary_dns" to "Primary DNS", "secondary_dns" to "Secondary DNS",
        "sshPortaLocal" to "Local SSH Port"
    )
    fun labeledDotGcm(input: ByteArray, pass: String, ext: String): String {
        val xml = p.dotGcm(input, pass)
        val extracted = mutableMapOf<String, String>()
        for (source in xml.split('\n')) {
            if (!source.startsWith("<entry")) continue
            val content = source.replace("<entry key=\"", "").replace("</entry", "")
                .split("\">", limit=2)
            if (content.size == 2) extracted[content[0]] = content[1].trim('>')
            else extracted[content[0].trim('"','/','>')] = ""
        }
        val order = if (ext == "pcx") pcx else labels
        val filtered = order.entries.filter { (key,_) ->
            val value = extracted[key]?.trim() ?: ""
            value.isNotEmpty() && value != "0" && value != "*******"
        }.joinToString("") { (key,label) -> "│[۞] $label: " + extracted[key]!!.trim() + "\n" }
        require(filtered.isNotEmpty())
        return p.header("(.$ext)") + "\n" + filtered + p.footer()
    }
    fun pyRepr(value: Any?): String = when(value) {
        null, JSONObject.NULL -> "None"
        is JSONObject -> p.keys(value).joinToString(", ", "{", "}") {
            "'" + it.replace("'", "\\'") + "': " + pyRepr(value.get(it))
        }
        is JSONArray -> (0 until value.length()).joinToString(", ","[","]") { pyRepr(value.get(it)) }
        is String -> "'" + value.replace("\\","\\\\").replace("'","\\'") + "'"
        is Boolean -> if (value) "True" else "False"
        else -> value.toString()
    }
}

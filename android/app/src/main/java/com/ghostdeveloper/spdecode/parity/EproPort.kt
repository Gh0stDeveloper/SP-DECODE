package com.ghostdeveloper.spdecode.parity

import android.content.Context
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * ePro modulepro.js + lib/methods/eProDecryptor.lib.js.
 * Preserves source's SHA1→128-bit AES-ECB candidates, direct raw variant and
 * obfuscated Base64 variant. The renderer uses its bundled English layout.
 */
object EproPort {
    private val p=LegacyPortPrimitives
    private val xorValues="。〃〄々〆〇〈〉《》「」『』【】〒〓〔〕"

    private fun aesEcb(input:ByteArray,key:ByteArray):String {
        require(input.isNotEmpty() && input.size%16==0 && input.size<=p.MAX_INPUT)
        val cipher=Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"))
        return p.utf8(cipher.doFinal(input))
    }
    private fun xorUnwrap(input:String):String {
        val source=input.filterNot { c -> c.code in 0x2000..0x20ef || c=='\n'||c=='\r' }
        return buildString(source.length) {
            source.forEachIndexed { i,ch -> append((ch.code xor xorValues[i%xorValues.length].code).toChar()) }
        }
    }
    private fun key(raw:String):ByteArray=MessageDigest.getInstance("SHA-1")
        .digest(raw.toByteArray(Charsets.UTF_8)).copyOf(16)
    private fun decodeFields(clear:String, delimiter:String):LinkedHashMap<String,String> {
        val parts=clear.split(delimiter)
        require(parts.size >= 3)
        val labels=if(delimiter=="[splitConfig]") listOf(
            "payload","proxyURL","blockedRoot","lockPayloadAndServers","expireDate",
            "containsNotes","note1","sshAddr","mobileData","unlockProxy",
            "openVPNConfig","VPNAddr","sniValue","connectSSH","udpgwPort",
            "lockPayload","hwidEnabled","hwidValue","note2","unlockUserAndPassword",
            "sslPayloadMode","passwordProtected","passwordValue"
        ) else listOf(
            "payload","proxyAddress","proxyPort","autoReplace","route","connectSSH",
            "useTun2Socks","googlePlay","mobileData","customPayload","hwidEnabled",
            "unknown","unknown","hwidValue","note1","bitviseProfileName","sshServer",
            "sshPort","sshUser","sshPassword","bool","autoReconnect","enableCustomDNS",
            "enableHTTPProxy","httpProxy","extraProtection","blockedRoot","unknown",
            "listenPort","useDNS","dnsForward","batterySaver","showLog","expireDate","directSSH"
        )
        val values=linkedMapOf<String,String>()
        labels.forEachIndexed { i,name ->
            if(i<parts.size) values[name]=parts[i]
        }
        return values
    }
    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val json=LegacyModuleText.keys(context).getJSONArray("eproPasswords")
        val keys=json.getJSONArray(0)
        val rawText=p.utf8(input)
        val rawVariants=listOfNotNull(
            input.takeIf {it.size%16==0},
            try { p.b64(xorUnwrap(rawText)) } catch(_:Exception) {null}
        )
        var decoded:LinkedHashMap<String,String>?=null
        for(i in 0 until keys.length()) {
            val cryptoKey=key(keys.getString(i))
            for (raw in rawVariants) {
                val plaintext=try {aesEcb(raw,cryptoKey)} catch(_:Exception){continue}
                if("[splitConfig]" in plaintext){
                    decoded=decodeFields(plaintext,"[splitConfig]")
                    break
                }
                if("[pisahConk]" in plaintext){
                    decoded=decodeFields(plaintext,"[pisahConk]")
                    break
                }
            }
            if(decoded!=null)break
        }
        LegacyModuleText.render(context,decoded ?: error("Unsupported ePro encrypted profile"))
    }
}

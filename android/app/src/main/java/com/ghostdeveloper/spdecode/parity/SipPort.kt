package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Original sockip.py AES-128-ECB envelope and safe data-only Java reader.
 * VER7 is identified and rejected exactly as the original unsupported source.
 */
object SipPort {
    private val p=LegacyPortPrimitives
    private val key=p.hex("192e04080804040905592959385f5417")
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        var encoded=p.utf8(input).removePrefix("\ufeff").trim()
        if(encoded.startsWith("sip://",ignoreCase=true))encoded=encoded.substring(6)
        encoded=encoded.replace('-','+').replace('_','/')
        val bytes=p.b64(encoded)
        require(bytes.size in 16..p.MAX_INPUT&&bytes.size%16==0)
        val cipher=Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"))
        val clear=cipher.doFinal(bytes)
        if(clear.size>=4 && String(clear.copyOfRange(0,4),Charsets.US_ASCII)=="VER7")
            return@safeDecode "SocksIP Tunnel: unsupported profile version\n"+
                "SocksIP VER7 was detected after AES-ECB. "+
                "This inner container is not implemented by the analyzed SocksIP 15.14.4 build."
        val json=SockipObjectReader(clear).read()
        p.prettyJson(json).replace(Regex("(?m)^ +")) {m->
            " ".repeat(m.value.length/2)
        }+"\n"
    }
}

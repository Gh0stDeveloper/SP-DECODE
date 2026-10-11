package com.ghostdeveloper.spdecode.parity

import android.content.Context

import org.json.JSONObject
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** Original sockip.py AES-128-ECB envelope and safe data-only Java reader.
 * An unsupported inner version is never returned as a decoded success.
 */
object SipPort {
    private val p=LegacyPortPrimitives

    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val material=LegacyBatch2Materials.sip(context)
        var encoded=p.utf8(input).removePrefix("\ufeff").trim()
        if(encoded.startsWith("sip://",ignoreCase=true))encoded=encoded.substring(6)
        encoded=encoded.replace('-','+').replace('_','/')
        val bytes=p.b64(encoded)
        require(bytes.size in 16..p.MAX_INPUT&&bytes.size%16==0)
        val cipher=Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(material.aesKey,"AES"))
        val outer=cipher.doFinal(bytes)
        require(!(outer.size>=4 &&
            String(outer.copyOfRange(0,4),Charsets.US_ASCII)=="VER7")) {
            "Unsupported SocksIP inner variant"
        }
        val clear=if(outer.size>=4 &&
            String(outer.copyOfRange(0,4),Charsets.US_ASCII)=="VER8") {
            // Only the authenticated inner data is passed to the Java reader.
            // Failed GCM tags must never fall back to the legacy parser.
            require(outer.size>=4+12+16+4) { "Truncated VER8 payload" }
            val nonce=outer.copyOfRange(4,16)
            val cipherAndTag=outer.copyOfRange(16,outer.size)
            p.gcm(cipherAndTag,material.ver8Key,nonce)
        } else outer
        val json=SockipObjectReader(clear).read()
        p.prettyJson(json).replace(Regex("(?m)^ +")) {m->
            " ".repeat(m.value.length/2)
        }+"\n"
    }
}

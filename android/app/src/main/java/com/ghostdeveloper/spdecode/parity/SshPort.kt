package com.ghostdeveloper.spdecode.parity

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Native Blowfish-CBC/PKCS7 port of ssh.py.
 * CLI golden sets Python random.Random(0) to deterministic 🚀 decoration.
 * Android uses that fixed glyph; no randomness is used for decryption itself.
 */
object SshPort {
    private val p=LegacyPortPrimitives
    private val key="263386285977449155626236830061505221752"
        .toByteArray(Charsets.US_ASCII)
    private val iv=ByteArray(8){it.toByte()}
    private const val GLYPH="🚀"
    private val hidden=listOf("cproxyRemoto","sslProxy","dnsKey","cchaveKey",
        "cserverNameKey","cdnssshUser","cdnssshPass")
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val raw=p.b64(p.utf8(input))
        require(raw.size>=8 && raw.size%8==0)
        val cipher=Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"Blowfish"),IvParameterSpec(iv))
        val xml=p.utf8(cipher.doFinal(raw))
        val regex=Regex("<entry key=\"([^\"]+)\">([^\"]+)</entry>")
        val fields=regex.findAll(xml).mapNotNull{match->
            val (k,v)=match.destructured
            if(k in hidden || "unlockKeys" in k)null
            else "│["+GLYPH+"] "+k+" : "+v
        }.sortedBy {it.substringBefore(':').trim()}.toList()
        require(fields.isNotEmpty())
        val left=fields.take(6).joinToString("\n")
        val right=fields.drop(6).joinToString("\n")
        val secret=hidden.joinToString("\n"){"│["+GLYPH+"] "+it+": ***"}
        p.header("(.ssh)")+"\n"+left+"\n"+"│["+GLYPH+"] unlockKeys 🔽\n"+
            secret+"\n"+right+"\n├───────────────\n"+
            "│["+GLYPH+"] 𝗚𝗥𝗢𝗨𝗣 : CodeBreakersHub\n├───────────────\n"+
            "│["+GLYPH+"] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n\n"
    }
}

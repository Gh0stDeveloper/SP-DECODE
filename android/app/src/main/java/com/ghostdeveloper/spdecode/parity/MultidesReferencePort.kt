package com.ghostdeveloper.spdecode.parity

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Exact historical decoders/Python/multides.py semantics, not an invented
 * per-extension key. Its script tries all distinct keys in original order
 * regardless of suffix: cinbdf66, OUSS, letsmake, agstgfoh.
 * A synthetic fixture for each suffix proves ONLY the first-key route.
 */
internal object MultidesReferencePort {
    private val p=LegacyPortPrimitives
    private val keys=listOf(
        "cinbdf66".toByteArray(Charsets.UTF_8),
        p.b64("4pyF2Y5PU1Q="),
        "letsmake".toByteArray(Charsets.UTF_8),
        "agstgfoh".toByteArray(Charsets.UTF_8)
    )
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        require(input.size%8==0)
        var xml: String?=null
        for (key in keys) {
            try {
                val cipher=Cipher.getInstance("DES/ECB/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"DES"))
                xml=p.utf8(cipher.doFinal(input))
                break
            } catch (_:Exception) { }
        }
        require(xml!=null)
        val fields=xml!!.split('\n').mapNotNull { line ->
            val trimmed=line.trim()
            if(!trimmed.startsWith("<entry")) null else {
                val valAndKey=trimmed.replace("<entry key=\"","")
                    .replace("</entry>","").replace("\"/>","")
                    .split("\">",limit=2)
                if(valAndKey.size>1)
                    "│[۞] [" + valAndKey[0] + "]: " + valAndKey[1] + "\n"
                else "│[۞] [" + valAndKey[0] + "]: ***\n"
            }
        }.joinToString("")
        require(fields.isNotEmpty())
        p.header("")+"\n"+fields+p.footer()+"\n"
    }
}

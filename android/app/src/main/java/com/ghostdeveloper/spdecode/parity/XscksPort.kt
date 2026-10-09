package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
/** XSCKS SHA-256(original Base64-obfuscated text password) + AES-CBC IV=0. */
object XscksPort {
    private const val CHICO_CP = "MTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAxIDExMDAwMSAxMDExMDAgMTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAxIDExMDExMCAxMDExMDAgMTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAwIDExMTAwMSAxMDExMDAgMTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAxIDExMDAxMCAxMDExMDAgMTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAxIDExMDAxMCAxMDExMDAgMTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAxIDExMDAxMSAxMDExMDAgMTEwMTAxIDExMDEwMSAxMDExMDAgMTEwMTAxIDExMDEwMCAxMDExMDAgMTEwMTAxIDExMDEwMSAxMDExMDAgMTEwMTEwIDExMDEwMSAxMDExMDAgMTEwMTAxIDExMDAwMCAxMDExMDAgMTEwMTAwIDExMTAwMCAxMDExMDAgMTEwMDExIDExMDAxMCAxMDExMDAgMTAwMDAwIA=="
    fun decode(input:ByteArray):String?=LegacyPortPrimitives.safeDecode {
        val p=LegacyPortPrimitives
        p.bounded(input)
        val password=p.utf8(p.b64(CHICO_CP))
        val clear=p.utf8(p.cbc(p.b64(p.utf8(input)),
            p.sha256(password.toByteArray(Charsets.UTF_8)),ByteArray(16)))
            .replace("\n","").replace("\r","").replace("\t","")
        val obj=JSONObject(clear)
        require(obj.length()>0)
        val rendered=p.keys(obj).joinToString("\n") {
            "│[۞] $it: " + p.pythonValue(obj.get(it))
        }
        p.header("(.xscks)")+"\n"+rendered+"\n"+p.footer()
    }
}

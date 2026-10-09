package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject

/** .mina: octal-coded password -> SHA-256 key -> AES-256-CBC with zero IV. */
object MinaPort {
    private val octalPassword = "101 156 144 162 157 151 144 126"
        .split(' ').map { it.toInt(8).toByte() }.toByteArray()

    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        p.bounded(input)
        val key = p.sha256(octalPassword)
        val plaintext = p.utf8(p.cbc(p.b64(p.utf8(input)), key, ByteArray(16)))
        val cleaned = plaintext.replace("\n", "").replace("\r", "").replace("\t", "")
        val json = JSONObject(cleaned)
        require(json.length() > 0)
        val fields = p.keys(json).joinToString("\n") { keyName ->
            "│[۞] $keyName: " + p.pythonValue(json.get(keyName))
        }
        p.header("(.mina)") + "\n" + fields + "\n" + p.footer()
    }
}

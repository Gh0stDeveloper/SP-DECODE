package com.ghostdeveloper.spdecode.parity

/** .phc: PBKDF2-HMAC-SHA256 (1000/128) + authenticated AES-GCM + XML entries. */
object PhcPort {
    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        val xml = p.dotGcm(input, "fubvx788b46v")
        val fields = p.simpleEntries(xml, strictStartsWith = true, phcStyle = true)
        require(fields.isNotEmpty())
        p.header("(.phc)") + "\n" + fields + p.footer()
    }
}

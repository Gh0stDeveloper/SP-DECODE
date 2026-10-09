package com.ghostdeveloper.spdecode.parity

/** .fnnetwork: Ed+NUL-01 PBKDF2-SHA256 + AES-GCM and strict entry filtering. */
object FnNetworkPort {
    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        val xml = p.dotGcm(input, "Ed\u0001")
        val fields = p.simpleEntries(xml)
        require(fields.isNotEmpty())
        p.header("", leadingLine = true) + "\n" + fields +
            p.footer(channel = "@GhostDeveloperSpy")
    }
}

package com.ghostdeveloper.spdecode.parity

/** .mij: Ed+NUL-01 PBKDF2-SHA256 + AES-GCM; historical XML multiline render. */
object MijPort {
    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        val xml = p.dotGcm(input, "Ed\u0001")
        val fields = p.simpleEntries(xml)
        require(fields.isNotEmpty())
        // The legacy MIJ header does not contain LF after its separator.
        p.header("", leadingLine = true) + fields +
            p.footer(channel = "@GhostDeveloperSpy")
    }
}

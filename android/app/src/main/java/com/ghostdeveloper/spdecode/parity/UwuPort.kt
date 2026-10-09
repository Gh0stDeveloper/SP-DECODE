package com.ghostdeveloper.spdecode.parity

/** .uwu: PBKDF2-SHA256 password "Ed" + AES-GCM, not the MIJ credential. */
object UwuPort {
    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        val xml = p.dotGcm(input, "Ed")
        val fields = p.simpleEntries(xml)
        require(fields.isNotEmpty())
        // Original script prints a .tnl header for .uwu; golden parity keeps it.
        p.header("(.tnl)", leadingLine = true) + "\n" + fields + p.footer()
    }
}

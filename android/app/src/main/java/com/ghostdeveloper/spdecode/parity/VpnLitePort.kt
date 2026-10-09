package com.ghostdeveloper.spdecode.parity

/** .vpnlite: SHA-256(password UTF-8), Base64(IV[16] + AES-CBC ciphertext). */
object VpnLitePort {
    private const val PASSWORD = "Wasjdeijs@/ÇPãoOf231#$%¨&*()_qqu&iJo>ç"

    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        p.bounded(input)
        val container = p.b64(p.utf8(input))
        require(container.size >= 32)
        val raw = p.utf8(p.cbc(container.copyOfRange(16, container.size),
            p.sha256(PASSWORD.toByteArray(Charsets.UTF_8)), container.copyOfRange(0, 16)))
        // Preserve the historical split-by-comma/colon behavior of vpnlite.py.
        val split = raw.trim().trim('{', '}').split(',')
        val fields = split.mapNotNull { segment ->
            val pair = segment.split(':')
            if (pair.size < 2) null else "│[۞] " + pair[0].trim('"') + ": " +
                pair[1].trim('"') + "\n"
        }.joinToString("")
        require(fields.isNotEmpty())
        p.header("(.vpnlite)") + "\n" + fields + p.footer()
    }
}

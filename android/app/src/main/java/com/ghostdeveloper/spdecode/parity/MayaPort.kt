package com.ghostdeveloper.spdecode.parity

/** Maya Tunnel has its own NoobCrypt AES-CBC outer key and AES-GCM inner fields. */
object MayaPort {
    private const val KEY =
        "360b82639d6fb4642dc69a1e7b9c720644f9227c7c2f1cc6da14ba9a7dcfead0"

    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        NoobCryptPortPrimitives.decode(input, KEY, "maya", "Maya Tunnel")
    }
}

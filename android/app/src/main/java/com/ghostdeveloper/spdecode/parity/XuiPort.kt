package com.ghostdeveloper.spdecode.parity

/** XUI Tunnel has its own NoobCrypt AES-CBC outer key and AES-GCM inner fields. */
object XuiPort {
    private const val KEY =
        "721d60cba2999a7e0f90e848d1ea31b7d06aa6be3654821fc4a5b388e70fc51c"

    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        NoobCryptPortPrimitives.decode(input, KEY, "xui", "XUI Tunnel")
    }
}

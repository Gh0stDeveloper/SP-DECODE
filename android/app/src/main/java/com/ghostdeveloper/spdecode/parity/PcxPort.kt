package com.ghostdeveloper.spdecode.parity

/** PCX: own PBKDF2-HMAC-SHA256 password / AES-GCM and PCX field labels. */
object PcxPort {
    fun decode(input:ByteArray):String?=LegacyPortPrimitives.safeDecode {
        Batch20Primitives.labeledDotGcm(input,"cinbdf665$4","pcx")
    }
}

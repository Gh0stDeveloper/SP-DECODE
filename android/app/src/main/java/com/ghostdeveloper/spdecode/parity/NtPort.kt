package com.ghostdeveloper.spdecode.parity

/** NT: historical lowercase .nt password, PBKDF2-SHA256 and AES-GCM. */
object NtPort {
    fun decode(input:ByteArray):String?=LegacyPortPrimitives.safeDecode {
        Batch20Primitives.labeledDotGcm(input,"0x0","nt")
    }
}

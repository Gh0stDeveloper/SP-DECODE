package com.ghostdeveloper.spdecode.parity

/** PB: dedicated own password + PBKDF2-SHA256 and AES-GCM. */
object PbPort {
    fun decode(input:ByteArray):String?=LegacyPortPrimitives.safeDecode {
        Batch20Primitives.labeledDotGcm(input,"Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e","pb")
    }
}

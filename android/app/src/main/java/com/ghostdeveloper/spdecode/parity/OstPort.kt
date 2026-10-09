package com.ghostdeveloper.spdecode.parity

/** OUSS Tunnel .ost: DES/ECB with original binary Base64-derived key. */
object OstPort {
    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p=LegacyPortPrimitives
        p.bounded(input)
        val clear=Batch20Primitives.des(input,p.b64("4pyF2Y5PU1Q="))
        val fields=p.simpleEntries(clear)
        require(fields.isNotEmpty())
        p.header("(.tnl)",leadingLine=true)+"\n"+fields+p.footer()
    }
}

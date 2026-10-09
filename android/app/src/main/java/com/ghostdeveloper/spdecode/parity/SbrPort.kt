package com.ghostdeveloper.spdecode.parity

/** SBR Injector .sbr: DES/ECB with SBR-specific ASCII key, no cross-key trials. */
object SbrPort {
    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p=LegacyPortPrimitives
        p.bounded(input)
        val clear=Batch20Primitives.des(input,"cinbdf66".toByteArray(Charsets.US_ASCII))
        val fields=p.simpleEntries(clear)
        require(fields.isNotEmpty())
        p.header("(.sbr)",leadingLine=true)+"\n"+fields+p.footer()
    }
}

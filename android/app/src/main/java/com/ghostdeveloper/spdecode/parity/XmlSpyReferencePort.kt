package com.ghostdeveloper.spdecode.parity

/** Renderer shared only by MRC and MTL original family: missing LF after separator. */
internal object XmlSpyReferencePort {
    fun decode(input:ByteArray,password:String):String?=LegacyPortPrimitives.safeDecode {
        val p=LegacyPortPrimitives
        val xml=p.dotGcm(input,password)
        val entries=p.simpleEntries(xml)
        require(entries.isNotEmpty())
        p.header("",leadingLine=true)+entries+p.footer(channel="@GhostDeveloperSpy")
    }
}

package com.ghostdeveloper.spdecode.parity

import android.content.Context

/** .phc: PBKDF2-HMAC-SHA256 (1000/128) + authenticated AES-GCM + XML entries. */
object PhcPort {
    fun decode(context: Context, input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        val key = EmbeddedDecoderMaterials.independentF1(context).vn7Passwords[1]
            .toString(Charsets.UTF_8)
        val xml = p.dotGcm(input, key)
        val fields = p.simpleEntries(xml, strictStartsWith = true, phcStyle = true)
        require(fields.isNotEmpty())
        p.header("(.phc)") + "\n" + fields + p.footer()
    }
}

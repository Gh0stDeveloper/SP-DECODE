package com.ghostdeveloper.spdecode.parity
import org.json.JSONObject
/** Original xtproy.py 16-character nibble alphabet -> Base64 AES-CBC. */
internal object XtpRoyReferencePort {
    private val p=LegacyPortPrimitives
    private val symbols="¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′"
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val encoded=p.utf8(input).trim()
        require(encoded.isNotEmpty() && encoded.length%2==0)
        val raw=ByteArray(encoded.length/2) { i ->
            val x=symbols.indexOf(encoded[i*2])
            val y=symbols.indexOf(encoded[i*2+1])
            require(x in 0..15 && y in 0..15)
            ((x shl 4) or y).toByte()
        }
        val hex="tekidoer".toByteArray(Charsets.UTF_8)
            .joinToString("") { "%02X".format(it.toInt() and 255) }
        val key=p.sha256(hex.toByteArray(Charsets.UTF_8))
        val obj=JSONObject(p.utf8(p.cbc(p.b64(p.utf8(raw)),key,ByteArray(16))))
        require(obj.length()>0)
        val fields=p.keys(obj).joinToString("") {
            "│[۞] "+it+" : "+p.pythonValue(obj.get(it))+"\n"
        }
        p.header("",leadingLine=true)+"\n"+fields+p.footer()
    }
}

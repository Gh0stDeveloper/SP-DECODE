package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import org.json.JSONArray

/** Native port of PHP sksplus.php: JSON signed-int arrays -> AES-256-CBC. */
object SksplusPort {
    private val p=LegacyPortPrimitives
    private val key=p.hex("6237376365303534616164623839653963313064633430656265393735323631")
    private fun octets(arr:JSONArray):ByteArray {
        require(arr.length() in 1..p.MAX_INPUT)
        return ByteArray(arr.length()) { i ->
            val n=arr.getInt(i)
            require(n in -128..255)
            n.toByte()
        }
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val payload=JSONObject(p.utf8(input)).getJSONObject("payload")
        val iv=octets(payload.getJSONArray("iv"))
        val ciphertext=octets(payload.getJSONArray("encoded"))
        val data=JSONObject(p.utf8(p.cbc(ciphertext,key,iv)))
        require(data.length()>0)
        val fields=p.keys(data).joinToString("") { k->
            val value=data.get(k)
            val s=when(value) {
                is JSONArray->(0 until value.length()).joinToString(", ") {
                    p.pythonValue(value.get(it))
                }
                null,JSONObject.NULL -> ""
                is Boolean->if(value)"1" else ""
                else->value.toString()
            }
            "│[۞] "+k+" : "+s+"\n"
        }
        p.header("(sksplus)")+"\n"+fields+p.footer()
    }
}

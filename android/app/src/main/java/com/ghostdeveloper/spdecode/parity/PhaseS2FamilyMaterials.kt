package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject

/**
 * Source-equivalent historical E1/E2/F2 decoder constants recovered from
 * the authenticated SPV1 asset, never from plaintext APK resource files.
 * Public source material still remains recoverable by reverse engineering.
 */
internal object PhaseS2FamilyMaterials {
    @Volatile private var cached: JSONObject? = null
    private fun source(ctx: Context): JSONObject = cached ?: synchronized(this) {
        cached ?: JSONObject(SecureAssetVault.readText(ctx, "embedded_kotlin_profiles.json"))
            .getJSONObject("specialKeyFamilies").also { cached = it }
    }
    private fun hex(s: String, n: Int): ByteArray {
        require(s.length == n * 2 && s.all { it in '0'..'9' || it in 'a'..'f' })
        return ByteArray(n) { i -> s.substring(i*2,i*2+2).toInt(16).toByte() }
    }
    private fun raw(s: String, charset: java.nio.charset.Charset, n: Int): ByteArray =
        s.toByteArray(charset).also { require(it.size == n) }
    private fun strings(o:JSONObject,name:String,count:Int):List<String> {
        val a=o.getJSONArray(name)
        require(a.length() == count)
        return (0 until count).map { a.getString(it).also { s -> require(s.isNotEmpty()) } }
    }

    data class E1(
        val sentinelKey: ByteArray, val v2boxKey: ByteArray,
        val slipKey: ByteArray, val eutKey: ByteArray, val juanPassword: ByteArray
    )
    data class E2(
        val wyrKey: ByteArray, val intKey: ByteArray, val wyrlHard: ByteArray,
        val mainAr: ByteArray, val fieldAr: ByteArray, val fieldIv: ByteArray,
        val ecKey: ByteArray, val wyrlPbkdfPassword: ByteArray,
        val fthpPasswords: List<String>
    )
    data class F2(
        val crevKeys: List<String>, val ktrKey: ByteArray, val ktrIv: ByteArray,
        val devSky: ByteArray, val devPassword: String, val devChars: String,
        val zobaPassword: ByteArray, val n4Password: ByteArray, val n4Seed: ByteArray,
        val table2: String, val table3: String, val table4: String
    )
    fun e1(ctx:Context):E1 {
        val p=source(ctx).getJSONObject("e1")
        return E1(
            raw(p.getString("sentinelAscii"),Charsets.US_ASCII,32),
            hex(p.getString("v2boxKeyHex"),32),
            hex(p.getString("slipnetKeyHex"),32),
            raw(p.getString("eutPasswordLatin1"),Charsets.ISO_8859_1,16),
            raw(p.getString("juanPassword"),Charsets.UTF_8,26),
        )
    }
    fun e2(ctx:Context):E2 {
        val p=source(ctx).getJSONObject("e2")
        return E2(
            raw(p.getString("wyrPassword"),Charsets.UTF_8,16),
            raw(p.getString("intPassword"),Charsets.UTF_8,16),
            hex(p.getString("wyrlChaChaKeyHex"),32),
            hex(p.getString("arMainKeyHex"),32),
            hex(p.getString("arFieldKeyHex"),32),
            hex(p.getString("arFieldIvHex"),16),
            raw(p.getString("ecPassword"),Charsets.US_ASCII,15),
            raw(p.getString("wyrlPbkdfPassword"),Charsets.UTF_8,16),
            strings(p,"fthpPasswords",2),
        )
    }
    fun f2(ctx:Context):F2 {
        val p=source(ctx).getJSONObject("f2")
        val chars=p.getString("devAlphabet")
        val t2=p.getString("n4Table2")
        val t3=p.getString("n4Table3")
        val t4=p.getString("n4Table4")
        require(chars.length == 16 && t2.length == 17 && t3.length == 16 && t4.length == 16)
        return F2(
            strings(p,"crevPasswords",4),
            hex(p.getString("ktrAesHex"),32),
            hex(p.getString("ktrIvHex"),16),
            raw(p.getString("devSeed"),Charsets.UTF_8,9),
            p.getString("devPassword"),
            chars,
            raw(p.getString("zobaPassword"),Charsets.UTF_8,16),
            raw(p.getString("n4Password"),Charsets.UTF_8,6),
            raw(p.getString("n4Seed"),Charsets.UTF_8,3),
            t2,t3,t4,
        )
    }
}

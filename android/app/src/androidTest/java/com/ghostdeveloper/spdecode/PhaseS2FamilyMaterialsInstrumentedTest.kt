package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.PhaseS2FamilyMaterials
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/** E1/E2/F2 source-to-APK AES-GCM vault byte-for-byte reference parity. */
@RunWith(AndroidJUnit4::class)
class PhaseS2FamilyMaterialsInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private val ctx get()=inst.targetContext

    private fun match(items:JSONObject,label:String,bytes:ByteArray) {
        val item=items.getJSONObject(label)
        assertEquals("Source material length: $label",item.getInt("bytes"),bytes.size)
        val hash=MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString(""){(it.toInt()and 255).toString(16).padStart(2,'0')}
        assertEquals("Original Python parity data mismatch: $label",item.getString("sha256"),hash)
    }
    private fun utf8(value:String)=value.toByteArray(Charsets.UTF_8)

    @Test fun allThirtySpecialAndIndependentKeysMatchFrozenSourceHashes() {
        val manifest=JSONObject(inst.context.assets.open("parity/s2-family-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        assertEquals(1,manifest.getInt("schemaVersion"))
        val spec=manifest.getJSONObject("materials")
        val e1=PhaseS2FamilyMaterials.e1(ctx)
        match(spec,"e1Sentinel",e1.sentinelKey)
        match(spec,"e1V2Box",e1.v2boxKey)
        match(spec,"e1Slipnet",e1.slipKey)
        match(spec,"e1Eut",e1.eutKey)
        match(spec,"e1Juan",e1.juanPassword)
        val e2=PhaseS2FamilyMaterials.e2(ctx)
        match(spec,"e2Wyr",e2.wyrKey)
        match(spec,"e2Int",e2.intKey)
        match(spec,"e2WyrlChaCha",e2.wyrlHard)
        match(spec,"e2ArMain",e2.mainAr)
        match(spec,"e2ArField",e2.fieldAr)
        match(spec,"e2ArIv",e2.fieldIv)
        match(spec,"e2Ec",e2.ecKey)
        match(spec,"e2WyrlPbkdf",e2.wyrlPbkdfPassword)
        e2.fthpPasswords.forEachIndexed{i,v->match(spec,"e2Fthp${i+1}",utf8(v))}
        val f2=PhaseS2FamilyMaterials.f2(ctx)
        f2.crevKeys.forEachIndexed{i,v->match(spec,"f2Crev${i+1}",utf8(v))}
        match(spec,"f2KtrKey",f2.ktrKey)
        match(spec,"f2KtrIv",f2.ktrIv)
        match(spec,"f2DevSeed",f2.devSky)
        match(spec,"f2DevPassword",utf8(f2.devPassword))
        match(spec,"f2DevAlphabet",utf8(f2.devChars))
        match(spec,"f2Zoba",f2.zobaPassword)
        match(spec,"f2N4Password",f2.n4Password)
        match(spec,"f2N4Seed",f2.n4Seed)
        match(spec,"f2N4Table2",utf8(f2.table2))
        match(spec,"f2N4Table3",utf8(f2.table3))
        match(spec,"f2N4Table4",utf8(f2.table4))
        assertEquals(30,spec.length())
        assertFalse(ctx.assets.list("")?.contains("embedded_kotlin_profiles.json")==true)
    }
}

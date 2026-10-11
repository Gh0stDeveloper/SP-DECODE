package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AdditionalDecoderMaterials
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/** Check TLS 8.5.0 / EHI / Dark Tunnel runtime bytes without bundled plaintext. */
@RunWith(AndroidJUnit4::class)
class PhaseS2AdvancedMaterialsInstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = inst.targetContext
    private fun expect(fixture:JSONObject,name:String,value:ByteArray) {
        val descriptor=fixture.getJSONObject(name)
        assertEquals("Material length: $name",descriptor.getInt("bytes"),value.size)
        val digest=MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString(""){ (it.toInt() and 255).toString(16).padStart(2,'0') }
        assertEquals("Source SHA-256 mismatch: $name",descriptor.getString("sha256"),digest)
    }

    @Test fun encryptedAssetProvidesExactSixTlsEhiAndDarkMaterials() {
        val manifest=JSONObject(inst.context.assets.open("parity/s2-extra-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        assertEquals(1,manifest.getInt("schemaVersion"))
        val fixture=manifest.getJSONObject("materials")
        val tls=AdditionalDecoderMaterials.tls(target)
        assertEquals(6,tls.size)
        tls.forEachIndexed{ i,key->expect(fixture,"tlsProfile${i+1}",key)}
        val ehi=AdditionalDecoderMaterials.ehi(target)
        expect(fixture,"ehiFirst",ehi.firstKey)
        expect(fixture,"ehiSecond",ehi.secondKey)
        expect(fixture,"ehiXxtea",ehi.xxteaKey)
        ehi.bypassIvs.forEachIndexed{ i,iv->expect(fixture,"ehiBypassIv${i+1}",iv)}
        ehi.standardIvs.forEachIndexed{ i,iv->expect(fixture,"ehiStandardIv${i+1}",iv)}
        val dark=AdditionalDecoderMaterials.dark(target)
        expect(fixture,"darkOuter",dark.outerKey)
        expect(fixture,"darkNested",dark.nestedKey)
        expect(fixture,"darkIv",dark.iv)
        val ehil=AdditionalDecoderMaterials.ehil(target)
        assertEquals(3,ehil.firstKeys.size)
        assertEquals(2,ehil.secondKeys.size)
        assertEquals(7,ehil.ivs.size)
        ehil.firstKeys.forEachIndexed{ i,key->expect(fixture,"ehilFirst${i+1}",key)}
        ehil.secondKeys.forEachIndexed{ i,key->expect(fixture,"ehilSecond${i+1}",key)}
        ehil.ivs.forEachIndexed{ i,key->expect(fixture,"ehilIv${i+1}",key)}
        assertEquals(30,fixture.length())
        assertFalse(target.assets.list("")?.contains("embedded_kotlin_profiles.json") == true)
    }
}

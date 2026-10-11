package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.EmbeddedDecoderMaterials
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/**
 * Phase S.2: Android runtime materials are byte-exact copies of the historical
 * source. No passwords or source constants are repeated in test bytecode.
 */
@RunWith(AndroidJUnit4::class)
class PhaseS2DexMaterialsInstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrumentation.targetContext

    private fun verify(fixture: JSONObject, name: String, actual: ByteArray) {
        val entry = fixture.getJSONObject(name)
        assertEquals("Source byte length differs: $name", entry.getInt("bytes"), actual.size)
        val digest = MessageDigest.getInstance("SHA-256").digest(actual)
            .joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
        assertEquals("Source digest mismatch: $name", entry.getString("sha256"), digest)
    }

    @Test fun migratedEngineMaterialMatchesOriginalSourceByteForByte() {
        val expected = JSONObject(instrumentation.context.assets
            .open("parity/s2-constants-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
        assertEquals(1, expected.getInt("schemaVersion"))
        val fixtures = expected.getJSONObject("materials")
        val hat = EmbeddedDecoderMaterials.hat(target)
        val f1 = EmbeddedDecoderMaterials.independentF1(target)
        verify(fixtures, "hatAes", hat.aesKey)
        verify(fixtures, "hatXor", hat.xorPassword.toByteArray(Charsets.UTF_8))
        verify(fixtures, "hcOuterXor", EmbeddedDecoderMaterials.httpCustomXor(target))
        verify(fixtures, "ltmPassword", f1.ltmPassword)
        verify(fixtures, "vn7One", f1.vn7Passwords[0])
        verify(fixtures, "vn7Two", f1.vn7Passwords[1])
        assertEquals(6, fixtures.length())
        assertFalse(target.assets.list("")?.contains("embedded_kotlin_profiles.json") == true)
    }
}

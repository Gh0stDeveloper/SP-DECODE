package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.GenericVpnPort
import com.google.gson.JsonParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Independent Python-generated encrypted corpus, created before CI Android build.
 * All 81 suffixes: 74 AES-GCM and 26 DES variants, including six dual profiles.
 */
@RunWith(AndroidJUnit4::class)
class PhaseBGenericInstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = inst.targetContext
    private val evidence by lazy {
        JSONObject(inst.context.assets.open("parity/generic-b-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
    }
    private val formats by lazy { AndroidDecoderCatalog.read(context) }
    private val suffixes by lazy {
        val vectors = evidence.getJSONArray("vectors")
        (0 until vectors.length()).map { vectors.getJSONObject(it).getString("suffix") }
            .toSet().sorted()
    }

    private fun testLot(index: Int) {
        assertEquals(81, suffixes.size)
        val wanted = if (index < 7) suffixes.subList(index * 10, (index + 1) * 10).toSet()
            else suffixes.subList(70, 81).toSet()
        val visited = mutableSetOf<String>()
        val vectors = evidence.getJSONArray("vectors")
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            val suffix = v.getString("suffix")
            if (suffix !in wanted) continue
            visited.add(suffix)
            val encrypted = Base64.decode(v.getString("inputBase64"), Base64.NO_WRAP)
            val name = "CONFIG." + suffix.uppercase(java.util.Locale.ROOT)
            val decrypted = AndroidOfflineDecoderRouter.decode(context, name, encrypted)
            assertNotNull("Golden failed: " + suffix + " " + v.getString("engine"), decrypted)
            assertEquals("Full structure for ." + suffix,
                JsonParser.parseString(v.getString("expected")),
                JsonParser.parseString(decrypted!!))
            assertTrue(AndroidDecoderCatalog.detect(name, formats)?.hasNativeDecoder == true)
        }
        assertEquals(wanted, visited)
    }

    @Test fun B1Ten() = testLot(0)
    @Test fun B2Ten() = testLot(1)
    @Test fun B3Ten() = testLot(2)
    @Test fun B4Ten() = testLot(3)
    @Test fun B5Ten() = testLot(4)
    @Test fun B6Ten() = testLot(5)
    @Test fun B7Ten() = testLot(6)
    @Test fun B8Eleven() = testLot(7)

    @Test fun catalogMatchesCorpus() {
        assertEquals(81, evidence.getInt("profileCount"))
        assertEquals(74, evidence.getInt("aesVectors"))
        assertEquals(26, evidence.getInt("desVectors"))
        assertEquals(100, evidence.getJSONArray("vectors").length())
        assertEquals(81, suffixes.size)
        assertEquals(239, formats.size)
        assertEquals(61, formats.count { it.migrationPhase == "legacy" && it.hasNativeDecoder })
        assertEquals(81, formats.count { it.migrationPhase == "B" && it.hasNativeDecoder })
        assertEquals(40, formats.count { it.isPending })
    }

    @Test fun everyGcmTagMutationFailsClosed() {
        val vectors = evidence.getJSONArray("vectors")
        var checked = 0
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            if (v.getString("engine") != "aes") continue
            val packet = Base64.decode(v.getString("inputBase64"), Base64.NO_WRAP)
            val parts = String(packet, Charsets.UTF_8).split(".")
            assertEquals(3, parts.size)
            val sealed = Base64.decode(parts[2], Base64.NO_WRAP)
            sealed[sealed.lastIndex] = (sealed.last().toInt() xor 1).toByte()
            val tampered = (parts[0] + "." + parts[1] + "." +
                Base64.encodeToString(sealed, Base64.NO_WRAP)).toByteArray()
            assertNull("Invalid GCM tag accepted for " + v.getString("suffix"),
                AndroidOfflineDecoderRouter.decode(context, "tampered." + v.getString("suffix"), tampered))
            checked++
        }
        assertEquals(74, checked)
    }

    @Test fun keysMustNotCrossUnrelatedFormats() {
        val vectors = evidence.getJSONArray("vectors")
        val ace = (0 until vectors.length()).map { vectors.getJSONObject(it) }
            .first { it.getString("suffix") == "ace" && it.getString("engine") == "aes" }
        val data = Base64.decode(ace.getString("inputBase64"), Base64.NO_WRAP)
        assertNotNull(AndroidOfflineDecoderRouter.decode(context, "test.ace", data))
        assertNull(AndroidOfflineDecoderRouter.decode(context, "test.cks", data))
        assertNull(AndroidOfflineDecoderRouter.decode(context, "test.ultra", data))
        assertNull(AndroidOfflineDecoderRouter.decode(context, "test.7net", data))
    }

    @Test fun invalidInputsAndOversizedDataFailClosed() {
        val inputs = listOf(byteArrayOf(), "invalid".toByteArray(), ByteArray(64),
            ByteArray(128) { 0xff.toByte() }, ByteArray(GenericVpnPort.MAX_INPUT_BYTES + 1))
        for (suffix in listOf("clay","vpc","dak","acm","ace")) {
            for (data in inputs) {
                assertNull(AndroidOfflineDecoderRouter.decode(context, "invalid." + suffix, data))
            }
        }
    }

    @Test fun rawPasswordPbkdf2MatchesJcaForHistoricalControlByte() {
        val password = "Ed\u0001"
        val salt = ByteArray(16) { it.toByte() }
        val native = GenericVpnPort.pbkdf2Sha256(password.toByteArray(), salt, 1000, 16)
        val standard = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(javax.crypto.spec.PBEKeySpec(
                password.toCharArray(), salt, 1000, 128)).encoded
        assertArrayEquals(standard, native)
    }
}

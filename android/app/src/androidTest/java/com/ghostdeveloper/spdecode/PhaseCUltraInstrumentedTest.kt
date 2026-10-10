package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.google.gson.JsonParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real Android API35 Argon2id+AES256-GCM parity, no simulated native results.
 * CI generates 83 encrypted cases by the original Python Ultra/Sandok module:
 * all 41 aliases with AAD, without AAD, plus profile-fallback.
 */
@RunWith(AndroidJUnit4::class)
class PhaseCUltraInstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = inst.targetContext
    private val evidence by lazy {
        JSONObject(inst.context.assets.open("parity/ultra-c-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
    }
    private val catalog by lazy { AndroidDecoderCatalog.read(context) }
    private val suffixes by lazy {
        val vectors = evidence.getJSONArray("vectors")
        (0 until vectors.length())
            .map { vectors.getJSONObject(it).getString("suffix") }.toSet().sorted()
    }

    private fun verifyLot(part: Int) {
        assertEquals(41,suffixes.size)
        val lot = suffixes.subList(part * 10,
            if (part == 3) 41 else (part + 1) * 10).toSet()
        val records = evidence.getJSONArray("vectors")
        val visited = mutableMapOf<String,MutableSet<String>>()
        for (i in 0 until records.length()) {
            val row = records.getJSONObject(i)
            val suffix = row.getString("suffix")
            if (suffix !in lot) continue
            visited.getOrPut(suffix) { mutableSetOf() }.add(row.getString("mode"))
            val bytes = Base64.decode(row.getString("encodedInput"), Base64.NO_WRAP)
            val filename = "PROFILE." + suffix.uppercase(java.util.Locale.ROOT)
            val actual = AndroidOfflineDecoderRouter.decode(context,filename,bytes)
            assertNotNull("Ultra/Sandok native failed: ." + suffix +
                " profile=" + row.getString("profile") +
                " mode=" + row.getString("mode"),actual)
            assertEquals("Complete config fields for ." + suffix,
                JsonParser.parseString(row.getString("expected")),
                JsonParser.parseString(actual!!))
            assertEquals("C",AndroidDecoderCatalog.detect(filename,catalog)?.migrationPhase)
            assertTrue(AndroidDecoderCatalog.detect(filename,catalog)!!.hasNativeDecoder)
        }
        assertEquals(lot, visited.keys)
        for (alias in lot) {
            assertTrue(visited[alias]!!.contains("aad"))
            assertTrue(visited[alias]!!.contains("no_aad"))
        }
    }

    @Test fun C1TenSuffixes() = verifyLot(0)
    @Test fun C2TenSuffixes() = verifyLot(1)
    @Test fun C3TenSuffixes() = verifyLot(2)
    @Test fun C4ElevenSuffixes() = verifyLot(3)

    @Test fun phaseCInventoryAndLegacyOstIsolation() {
        assertEquals(83,evidence.getInt("caseCount"))
        assertEquals(41,evidence.getInt("suffixCount"))
        assertEquals(41,evidence.getInt("aadVectors"))
        assertEquals(41,evidence.getInt("noAadVectors"))
        assertEquals(1,evidence.getInt("fallbackVectors"))
        assertEquals(239,catalog.size)
        assertEquals(199,catalog.count { it.hasNativeDecoder })
        assertEquals(40,catalog.count { it.isPending })
        assertEquals(61,catalog.count { it.migrationPhase=="legacy" && it.hasNativeDecoder })
        assertEquals(81,catalog.count { it.migrationPhase=="B" && it.hasNativeDecoder })
        assertEquals(41,catalog.count { it.migrationPhase=="C" && it.hasNativeDecoder })
        val ost = AndroidDecoderCatalog.detect("old.ost",catalog)
        assertNotNull(ost)
        assertEquals("legacy",ost!!.migrationPhase)
        assertTrue(ost.hasNativeDecoder)
    }

    @Test fun ostCollisionPreservesDesAndAuthenticatedUltraVariants() {
        assertEquals(2, evidence.getInt("legacyOstCaseCount"))
        // The first .ost route must keep the exact legacy golden byte-for-byte.
        val old = inst.context.assets.open("parity/batch4-ost.ost").use { it.readBytes() }
        val expectedDes = inst.context.assets.open("parity/batch4-ost.txt").use { it.readBytes() }
        assertArrayEquals(expectedDes, AndroidOfflineDecoderRouter.decode(
            context, "legacy.ost", old)?.toByteArray(Charsets.UTF_8))

        val samples = evidence.getJSONArray("legacyOstVectors")
        assertEquals(2, samples.length())
        for (i in 0 until samples.length()) {
            val item = samples.getJSONObject(i)
            val data = Base64.decode(item.getString("encodedInput"), Base64.NO_WRAP)
            val result = AndroidOfflineDecoderRouter.decode(context, "ultra.ost", data)
            assertNotNull("Authenticated .ost Ultra fallback: " + item.getString("mode"), result)
            assertEquals(JsonParser.parseString(item.getString("expected")),
                JsonParser.parseString(result!!))
        }

        // AES-GCM must reject a modified tag even after the failed DES route.
        val data = Base64.decode(samples.getJSONObject(0).getString("encodedInput"),
            Base64.NO_WRAP)
        val encrypted = Base64.decode(String(data, Charsets.UTF_8), Base64.NO_WRAP)
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()
        assertNull(AndroidOfflineDecoderRouter.decode(context, "corrupt.ost",
            Base64.encodeToString(encrypted, Base64.NO_WRAP).toByteArray(Charsets.UTF_8)))
    }

    @Test fun corruptedGcmTagAndMalformedInputCannotProduceValidConfig() {
        val cases = evidence.getJSONArray("vectors")
        var failed = 0
        for (i in 0 until cases.length()) {
            val item = cases.getJSONObject(i)
            if (item.getString("mode") != "aad" ||
                item.getString("suffix") !in listOf("ultra","mmt","t20","flynet")) continue
            val bytes = Base64.decode(item.getString("encodedInput"), Base64.NO_WRAP)
            val asText = String(bytes,Charsets.UTF_8).substringAfter("://")
            val encrypted = Base64.decode(asText,Base64.NO_WRAP)
            encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()
            val tampered = Base64.encodeToString(encrypted,Base64.NO_WRAP).toByteArray()
            assertNull("Modified tag must not authenticate for " + item.getString("suffix"),
                AndroidOfflineDecoderRouter.decode(context,"bad."+item.getString("suffix"),tampered))
            failed++
        }
        assertEquals(4,failed)
        for (name in listOf("bad.ultra","bad.flynet","bad.t20")) {
            assertNull(AndroidOfflineDecoderRouter.decode(context,name,"not-base64".toByteArray()))
            assertNull(AndroidOfflineDecoderRouter.decode(context,name,byteArrayOf()))
        }
    }

    @Test fun wrongFamilyMustNeverTryUltraSecrets() {
        val item = (0 until evidence.getJSONArray("vectors").length())
            .map { evidence.getJSONArray("vectors").getJSONObject(it) }
            .first { it.getString("suffix") == "ultra" && it.getString("mode") == "aad" }
        val payload=Base64.decode(item.getString("encodedInput"),Base64.NO_WRAP)
        assertNull(AndroidOfflineDecoderRouter.decode(context,"unknown.7net",payload))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"unknown.ace",payload))
    }
}

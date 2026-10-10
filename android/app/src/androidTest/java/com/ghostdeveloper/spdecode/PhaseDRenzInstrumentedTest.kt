package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.RenzPort
import com.google.gson.JsonParser
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** File-based parity against 22 independently encrypted Python RENZ examples. */
@RunWith(AndroidJUnit4::class)
class PhaseDRenzInstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = inst.targetContext
    private val catalog by lazy { AndroidDecoderCatalog.read(context) }
    private val evidence by lazy {
        JSONObject(inst.context.assets.open("parity/renz-d-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use { it.readText() })
    }
    private val records by lazy { evidence.getJSONArray("vectors") }
    private val aliases by lazy {
        (0 until records.length()).map { records.getJSONObject(it) }
            .filter { it.getString("mode") == "outer" }
            .map { it.getString("suffix") }.sorted()
    }

    private fun assertReference(row: JSONObject) {
        val suffix = row.getString("suffix")
        val input = Base64.decode(row.getString("encodedInput"),Base64.NO_WRAP)
        val decoded = AndroidOfflineDecoderRouter.decode(
            context,"TEST." + suffix.uppercase(java.util.Locale.ROOT),input)
        assertNotNull("RENZ native failure: ." + suffix + " mode=" + row.getString("mode"),decoded)
        assertEquals("Python and Android must match complete JSON for ." + suffix +
            " mode=" + row.getString("mode"),
            JsonParser.parseString(row.getString("expected")),
            JsonParser.parseString(decoded!!))
    }

    private fun verifyLot(lot: Int) {
        assertEquals(16,aliases.size)
        val subset = aliases.subList(lot*8,(lot+1)*8).toSet()
        val visited = mutableSetOf<String>()
        for (i in 0 until records.length()) {
            val row = records.getJSONObject(i)
            if (row.getString("mode") != "outer" || row.getString("suffix") !in subset) continue
            assertReference(row)
            visited.add(row.getString("suffix"))
        }
        assertEquals(subset,visited)
    }

    @Test fun D1EightSourceProfiles() = verifyLot(0)
    @Test fun D2EightSourceProfiles() = verifyLot(1)

    @Test fun D3HistoricalTypesAndNestedFields() {
        val modes = mutableSetOf<String>()
        for (i in 0 until records.length()) {
            val row = records.getJSONObject(i)
            if (row.getString("mode") == "outer") continue
            assertReference(row)
            modes.add(row.getString("mode"))
        }
        assertEquals(setOf("nested_host","nested_username",
            "type0","type1","type2","type3"),modes)
    }

    @Test fun inventoryIsExactAndPriorFamiliesArePreserved() {
        assertEquals(16,evidence.getInt("suffixCount"))
        assertEquals(22,evidence.getInt("caseCount"))
        assertEquals(239,catalog.size)
        assertEquals(199,catalog.count { it.hasNativeDecoder })
        assertEquals(40,catalog.count { it.isPending })
        assertEquals(16,catalog.count { it.hasNativeDecoder && it.migrationPhase == "D" })
        assertEquals(41,catalog.count { it.hasNativeDecoder && it.migrationPhase == "C" })
        assertEquals(81,catalog.count { it.hasNativeDecoder && it.migrationPhase == "B" })
        assertEquals("C",AndroidDecoderCatalog.detect("profile.vlx",catalog)?.migrationPhase)
        assertEquals("F",AndroidDecoderCatalog.detect("profile.izph",catalog)?.migrationPhase)
        assertFalse(AndroidDecoderCatalog.detect("profile.izph",catalog)!!.hasNativeDecoder)
        assertEquals("D",AndroidDecoderCatalog.detect("config.osp",catalog)?.migrationPhase)
        assertEquals("D",AndroidDecoderCatalog.detect("config.actun",catalog)?.migrationPhase)
        assertNull(AndroidOfflineDecoderRouter.decode(context,"invalid.7net",
            "not-real-ciphertext".toByteArray()))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"invalid.vlx",
            "not-real-ciphertext".toByteArray()))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"invalid.izph",
            "not-real-ciphertext".toByteArray()))
        assertNull(RenzPort.decode(context,"7net",ByteArray(0)))
        assertNull(RenzPort.decode(context,"7net",ByteArray(RenzPort.MAX_INPUT_BYTES+1)))
    }

    @Test fun wrongAliasAndCorruptCiphertextMustFailClosed() {
        // 7net route may only accept text prefixes belonging to the same profile.
        val row = (0 until records.length()).map { records.getJSONObject(it) }
            .first { it.getString("suffix") == "7net" && it.getString("mode") == "outer" }
        val input = Base64.decode(row.getString("encodedInput"),Base64.NO_WRAP)
        assertNull(AndroidOfflineDecoderRouter.decode(context,"profile.7net",
            "tcx://".toByteArray() + input))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"profile.7net",
            "izph://".toByteArray() + input))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"profile.7net",
            "not a valid RENZ export".toByteArray()))
        // CBC alone has no authentication: reject damage that prevents valid JSON,
        // without claiming arbitrary ciphertext edits are always detected.
        val altered = String(input,Charsets.UTF_8).toCharArray()
        altered[altered.size/2] = '#'
        assertNull(AndroidOfflineDecoderRouter.decode(context,"profile.7net",
            String(altered).toByteArray(Charsets.UTF_8)))
    }
}

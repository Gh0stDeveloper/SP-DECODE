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

/** Source-independent encrypted fixtures are produced by all 9 Python modules in CI. */
@RunWith(AndroidJUnit4::class)
class PhaseFIndependentInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private val context get()=inst.targetContext
    private val catalog by lazy{AndroidDecoderCatalog.read(context)}
    private val source by lazy{JSONObject(inst.context.assets.open("parity/f-independent-fixtures.json")
        .bufferedReader(Charsets.UTF_8).use{it.readText()})}
    private val vectors by lazy{source.getJSONArray("vectors")}

    private fun checkVector(row:JSONObject){
        val suffix=row.getString("suffix")
        val mode=row.getString("mode")
        val input=Base64.decode(row.getString("encodedInput"),Base64.DEFAULT)
        val result=AndroidOfflineDecoderRouter.decode(context,"configuration.$suffix",input)
        assertNotNull("Python→Android F $suffix mode=$mode",result)
        val expected=row.getString("expected")
        val parsed=try{JsonParser.parseString(expected)}catch(_:Exception){null}
        if(parsed!=null && !parsed.isJsonPrimitive)
            assertEquals("Full Python JSON for $suffix $mode",parsed,
                JsonParser.parseString(result!!))
        else assertEquals("Original Python text for $suffix $mode",expected,result)
    }
    private fun checkLot(aliases:Set<String>,size:Int){
        val seen=mutableSetOf<String>()
        for(i in 0 until vectors.length()){
            val row=vectors.getJSONObject(i)
            if(row.getString("mode")!="outer" || row.getString("suffix") !in aliases)continue
            checkVector(row)
            seen.add(row.getString("suffix"))
        }
        assertEquals(size,seen.size)
        assertEquals(aliases,seen)
        for(name in aliases){
            val row=AndroidDecoderCatalog.detect("test.$name",catalog)
            assertEquals("F",row?.migrationPhase)
            assertTrue(row!!.hasNativeDecoder)
        }
    }

    @Test fun F1SixSpecializedFileExtensions(){
        checkLot(setOf("flexnet","flex","izph","ltm","lt","vn7"),6)
    }
    @Test fun F2SevenIndependentFileExtensions(){
        checkLot(setOf("crev","cer","cerv","ktr","zoba","dev","n4"),7)
    }
    @Test fun optionalVariantsAndHistoricCryptoTypes(){
        val modes=mutableSetOf<String>()
        for(i in 0 until vectors.length()){
            val row=vectors.getJSONObject(i)
            if(row.getString("mode")=="outer")continue
            checkVector(row)
            modes.add(row.getString("mode"))
        }
        assertEquals(setOf("version2","version3","version4","version4_optional_header",
            "type1_threefish","type2_pbkdf2","type3_hkdf","type3_nested_base64",
            "secondary_key","long_string","raw_binary","alternative_key"),modes)
    }
    @Test fun fullCatalogHasNoUnimplementedSuffixes(){
        assertEquals(13,source.getInt("suffixCount"))
        assertEquals(9,source.getInt("moduleCount"))
        assertEquals(25,source.getInt("caseCount"))
        assertEquals(239,catalog.size)
        assertEquals(239,catalog.count{it.hasNativeDecoder})
        assertEquals(0,catalog.count{it.isPending})
        assertEquals(13,catalog.count{it.migrationPhase=="F"&&it.hasNativeDecoder})
        assertEquals(27,catalog.count{it.migrationPhase=="E"&&it.hasNativeDecoder})
        assertEquals(16,catalog.count{it.migrationPhase=="D"&&it.hasNativeDecoder})
        assertEquals(41,catalog.count{it.migrationPhase=="C"&&it.hasNativeDecoder})
        assertEquals(81,catalog.count{it.migrationPhase=="B"&&it.hasNativeDecoder})
        assertEquals(61,catalog.count{it.migrationPhase=="legacy"&&it.hasNativeDecoder})
        assertEquals(0,catalog.count{it.androidVerified})
    }
    @Test fun malformedAndCrossFamilyPayloadsFailSafely(){
        for(name in listOf("izph","flex","flexnet","ltm","lt","vn7",
            "n4","crev","cer","cerv","zoba","dev","ktr")){
            val actual=AndroidOfflineDecoderRouter.decode(context,"broken.$name",
                byteArrayOf(0,1,2,3,4,5,6,7))
            assertNull("Malformed F sample .$name cannot decode",actual)
        }
        assertNull(AndroidOfflineDecoderRouter.decode(context,"unknown.nope",
            "not a valid export".toByteArray()))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"bad.flex",
            ByteArray(0)))
    }
}

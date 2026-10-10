package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonParser
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** G: source-reproducible text golden corpus, not reused file extension tests. */
@RunWith(AndroidJUnit4::class)
class PhaseGTextInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private val context get()=inst.targetContext
    private val corpus by lazy {
        JSONObject(inst.context.assets.open("parity/g-text-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
    }
    private val vectors by lazy{corpus.getJSONArray("vectors")}

    private fun compareGroup(group:String):Int{
        var count=0
        for(i in 0 until vectors.length()){
            val row=vectors.getJSONObject(i)
            if(row.getString("group")!=group)continue
            val link=row.getString("input")
            val label=row.getString("scheme")
            val identified=TextProtocolDecoder.identify(link)
            assertNotNull("G identify "+label,identified)
            val actual=TextProtocolDecoder.decode(context,identified!!)
            assertNotNull("G decode "+label,actual)
            val expected=JsonParser.parseString(row.get("expected").toString())
            assertEquals("Python exact output "+label,expected,
                JsonParser.parseString(actual!!))
            count++
        }
        assertTrue("Source group "+group+" must have positive tests",count>0)
        return count
    }
    @Test fun all23RenzTextSchemesAndTypedCrypto(){
        assertEquals(23,corpus.getInt("renzCount"))
        assertEquals(23,compareGroup("renz"))
    }
    @Test fun all10XorTextSchemesIncludingHamaratnl(){
        assertEquals(10,corpus.getInt("xorCount"))
        assertEquals(10,compareGroup("xor"))
    }
    @Test fun plainAndStructuredTextSources(){
        assertTrue(compareGroup("structured")>=5)
    }
    @Test fun configBatchSourcesWithoutFileFallback(){
        assertTrue(compareGroup("batch")>=10)
    }
    @Test fun legacyAlternateKeysAndPBVmessDoubleBase64(){
        assertTrue(compareGroup("legacy")>=5)
    }
    @Test fun completeCatalogAndDeliberateUnsupportedCases(){
        assertEquals(1,corpus.getInt("schemaVersion"))
        assertTrue(corpus.getInt("vectorCount")>=55)
        assertEquals(corpus.getInt("vectorCount"),vectors.length())
        assertEquals(239,AndroidDecoderCatalog.read(context).count{it.hasNativeDecoder})
        assertNull(TextProtocolDecoder.identify("regular chat without known protocol"))
        assertNull(TextProtocolDecoder.identify("x".repeat(TextProtocolDecoder.MAX_CHARS+1)))
        assertNull(TextProtocolDecoder.decode(context,
            TextProtocolDecoder.identify("happ://crypt/AAAA")!!))
        assertNull(TextProtocolDecoder.decode(context,
            TextProtocolDecoder.identify("happ://crypt4/AAAA")!!))
        assertNull(TextProtocolDecoder.decode(context,
            TextProtocolDecoder.identify("izphvpnpro://AAAA")!!))
        assertNull(TextProtocolDecoder.decode(context,
            TextProtocolDecoder.identify("flex://AAAA")!!))
        assertNull(TextProtocolDecoder.decode(context,
            TextProtocolDecoder.identify("falcontunnel://import/AAAA")!!))
    }
}

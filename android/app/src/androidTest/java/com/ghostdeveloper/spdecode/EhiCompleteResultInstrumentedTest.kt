package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.EhiPort
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Source-authenticated fixture from Python HTTPINJECTOR.py, not real accounts. */
@RunWith(AndroidJUnit4::class)
class EhiCompleteResultInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private fun file(name:String)=inst.context.assets.open("parity/"+name).use{it.readBytes()}
    @Test fun originalPythonAndAndroidEhiTextStillMatchExactly(){
        val encrypted=file("ehi-complete-fields.ehi")
        val expected=file("ehi-complete-fields.txt")
        assertArrayEquals(expected,EhiPort.decode(encrypted)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"mixed.EHI",encrypted)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun UIResultContainsCompleteTypedJSONFromEhiFile(){
        val encrypted=file("ehi-complete-fields.ehi")
        val raw=EhiPort.decode(encrypted)
        assertNotNull(raw)
        val expected=JsonParser.parseString(String(file("ehi-complete-fields.json"),Charsets.UTF_8))
        val presentation=DecodeView("mixed.ehi","ehi",raw!!,encrypted.size)
        val document=presentation.document
        val parsed=JsonParser.parseString(document.json)
        assertEquals("Complete EHI JSON fields",expected,parsed)
        val screen=JsonParser.parseString(ResultJsonDisplay.render(raw,"ehi"))
        assertEquals("Visible EHI JSON must contain ALL fields",expected,screen)
        assertTrue(document.fields.any{
            it.path=="finalField"&&it.value=="LAST_FIELD_MUST_SURVIVE"})
        assertTrue(document.fields.any{
            it.path=="overwriteServerData › servers [2] › port"&&it.value=="8443"})
        assertEquals(raw,ResultPresentation.formatted(document,ResultExport.ORIGINAL))
    }
    @Test fun multilineEhiPreservesHttpBlankLinesAndLastResultField(){
        val raw="┌───────────────\n"+
            "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ehi)\n"+
            "├───────────────\n"+
            "│[۞] httpPayload: CONNECT example.invalid:443 HTTP/1.1\n"+
            "Host: example.invalid\n"+
            "\n"+
            "Proxy-Connection: Keep-Alive\n"+
            "│[۞] lastField: visible\n"+
            "\n├───────────────\n"+
            "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n"+
            "└───────────────\n"
        val json=JsonParser.parseString(ResultJsonDisplay.render(raw,"ehi")).asJsonObject
        assertEquals("CONNECT example.invalid:443 HTTP/1.1\nHost: example.invalid\n\n"+
            "Proxy-Connection: Keep-Alive",json.get("httpPayload").asString)
        assertEquals("visible",json.get("lastField").asString)
        assertEquals(raw,ResultPresentation.parse(raw,"ehi").original)
    }
}

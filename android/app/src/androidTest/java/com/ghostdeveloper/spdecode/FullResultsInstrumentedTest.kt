package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import com.google.gson.JsonParser

/** Regression: ALL decoded fields, originals untouched, human-friendly view.
 * Test data is fictional, not extracted from private user configurations.
 */
@RunWith(AndroidJUnit4::class)
class FullResultsInstrumentedTest {
    private val header="┌───────────────\n│SP-DECODE (.xui)\n│[۞] Aplicación: XUI Tunnel\n├───────────────\n"
    @Test fun xuiShowsAllFieldsOriginalOrderTypesAndLongValues(){
        val payload=buildString{
            append("{\n")
            for(i in 0 until 46){
                append("  \"field").append(i).append("\": ")
                when(i){
                    0->append("false")
                    1->append("80")
                    2->append("\"line one\\nline two\"")
                    3->append("{\"proxy\":\"example.test\",\"TLS\":true,\"ports\":[80,443]}")
                    45->append("\"FINAL_FIELD_NOT_CUT\"")
                    else->append("\"value").append(i).append("\"")
                }
                if(i<45)append(",")
                append('\n')
            }
            append("}\n└───────────────")
        }
        val original=header+payload
        val doc=ResultPresentation.parse(original,"xui")
        assertTrue(doc.jsonParsed)
        assertTrue(doc.fields.size>46)
        assertEquals("field0",doc.fields[0].path)
        assertEquals("false",doc.fields[0].value)
        assertTrue(doc.fields.any{it.path=="field45" && it.value=="FINAL_FIELD_NOT_CUT"})
        assertTrue(doc.fields.any{it.path=="field3 › ports [2]" && it.value=="443"})
        assertTrue(doc.fields.any{it.path=="field2" && it.value.contains("line two")})
        val json=JsonParser.parseString(doc.json).asJsonObject
        assertFalse(json.get("field0").asBoolean)
        assertEquals(80,json.get("field1").asInt)
        assertEquals("line one\nline two",json.get("field2").asString)
        assertEquals(original,doc.original)
        assertTrue(doc.structured.contains("field45: FINAL_FIELD_NOT_CUT"))
    }
    @Test fun orderedCopyExportCreditsIdentifySpDecodeAndDeveloperWithoutChangingJson() {
        val raw="{\n  \"Username\": \"sample\",\n  \"Password\": \"dummy\",\n  \"Enabled\": true\n}"
        val document=ResultPresentation.parse(raw,"lnk")
        val ordered=ResultPresentation.formatted(document,ResultExport.ORDERED)
        assertTrue(ordered.contains("Decodificado por: SP-DECODE"))
        assertTrue(ordered.contains("Desarrollado por: Ghost Developer"))
        assertTrue(ordered.contains("Grupo: https://t.me/CodeBreakersHub"))
        assertTrue(ordered.contains("Canal: https://t.me/GhostDeve"))
        assertTrue(ordered.indexOf("Desarrollado por: Ghost Developer") <
            ordered.indexOf("│[۞] Username: sample"))
        assertTrue(ordered.indexOf("│[۞] Password: dummy") <
            ordered.indexOf("Grupo: https://t.me/CodeBreakersHub"))
        assertTrue(ordered.contains("│[۞] Enabled: true"))
        assertEquals(1,ordered.split("Desarrollado por: Ghost Developer").size-1)
        val json=ResultPresentation.formatted(document,ResultExport.JSON)
        val decoded=JsonParser.parseString(json).asJsonObject
        assertEquals("sample",decoded.get("Username").asString)
        assertEquals("dummy",decoded.get("Password").asString)
        assertTrue(decoded.get("Enabled").asBoolean)
        assertFalse(json.contains("Ghost Developer"))
        assertFalse(json.contains("CodeBreakersHub"))
        assertEquals(raw,ResultPresentation.formatted(document,ResultExport.ORIGINAL))
    }

    @Test fun httpCustomNestedJsonMustBeExpandedRatherThanOneHugeRow(){
        val original="┌─\n│[۞] Protections: {}\n│[۞] Config: "+
            "{\"proxy\":\"vpn.example.org\",\"isEncrypted\":false,"+
            "\"advanced\":{\"host\":\"my.test\",\"port\":443,"+
            "\"payload\":\"GET /hello HTTP/1.1\\r\\nHost: test\"}}\n└─"
        val doc=ResultPresentation.parse(original,"hc")
        assertFalse(doc.jsonParsed)
        assertTrue(doc.fields.any{it.path=="Config › proxy" && it.value=="vpn.example.org"})
        assertTrue(doc.fields.any{it.path=="Config › advanced › port" && it.value=="443"})
        assertTrue(doc.fields.any{it.path=="Config › advanced › payload" &&
            it.value.contains("\r\nHost:")})
        assertTrue(JsonParser.parseString(doc.json).asJsonObject.get("Config").isJsonObject)
        assertEquals(original,ResultPresentation.formatted(doc,ResultExport.ORIGINAL))
    }
    @Test fun repeatedSourceFieldsAreNotSilentlyDiscarded(){
        val raw="│[۞] DNS: primary.example\n│[۞] DNS: secondary.example"
        val parsed=ResultPresentation.parse(raw,"tls")
        assertEquals(2,parsed.fields.size)
        assertEquals("DNS",parsed.fields[0].path)
        assertEquals("DNS (2)",parsed.fields[1].path)
        assertTrue(parsed.json.contains("secondary.example"))
        assertTrue(parsed.structured.contains("secondary.example"))
    }
    @Test fun falsePositivesLikePayloadPublicKeyAndConfigAreNotPasswords(){
        assertFalse(ResultPresentation.isCredential("Config"))
        assertFalse(ResultPresentation.isCredential("Payload"))
        assertFalse(ResultPresentation.isCredential("PublicKey"))
        assertFalse(ResultPresentation.isCredential("serverDnsMode"))
        assertTrue(ResultPresentation.isCredential("sshPassword"))
        assertTrue(ResultPresentation.isCredential("MyPass"))
        val raw="│[۞] Payload: GET / HTTP/1.1\n│[۞] Password: test"
        assertTrue(RedactionPolicy.mask(raw).contains("Payload: GET / HTTP/1.1"))
        assertFalse(RedactionPolicy.mask(raw).contains("Password: test"))
    }
}

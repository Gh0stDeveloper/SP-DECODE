package com.ghostdeveloper.spdecode

import com.google.gson.JsonParser
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class JsonOnlyPreviewInstrumentedTest {
    @Test fun legacyBotDecorationsBecomeJsonOnlyWithoutLosingFields() {
        val raw="┌───────────────\n│SP-DECODE (.ehi)\n├───────────────\n"+
            "│[۞] Host: vpn.example.test\n"+
            "│[۞] overwriteServerData: {\"nested\":{\"port\":443,\"tls\":true}}\n"+
            "│[۞] Host: backup.example.test\n└───────────────"
        val result=ResultJsonDisplay.render(raw,"ehi")
        assertFalse(result.contains("┌"))
        assertFalse(result.contains("│"))
        val obj=JsonParser.parseString(result).asJsonObject
        assertEquals("vpn.example.test",obj.get("Host").asString)
        assertEquals("backup.example.test",obj.get("Host (2)").asString)
        assertEquals(443,obj.getAsJsonObject("overwriteServerData")
            .getAsJsonObject("nested").get("port").asInt)
        assertEquals(raw,ResultPresentation.formatted(
            ResultPresentation.parse(raw,"ehi"),ResultExport.ORIGINAL))
    }

    @Test fun pureTypedJsonArraysAndJsonStringsBecomeExpandedObjects() {
        val raw="[\"text\",{\"config\":\"{\\\"host\\\":\\\"my.test\\\",\\\"active\\\":true}\",\"port\":443}]"
        val doc=JsonParser.parseString(ResultJsonDisplay.render(raw,"json")).asJsonArray
        assertEquals("text",doc[0].asString)
        assertEquals(443,doc[1].asJsonObject.get("port").asInt)
        assertTrue(doc[1].asJsonObject.getAsJsonObject("config").get("active").asBoolean)
    }

    @Test fun maskingInsideJsonLeavesImmutableSourceUntouched() {
        val raw="{\"host\":\"sample\",\"sshPassword\":\"example-sensitive\",\"details\":{\"token\":\"visible-string\",\"password\":\"nested-secret\"}}"
        val shown=ResultJsonDisplay.render(raw,"ehi",true)
        assertFalse(shown.contains("example-sensitive"))
        assertFalse(shown.contains("nested-secret"))
        assertTrue(shown.contains("visible-string"))
        assertTrue(shown.contains("••••••••"))
        assertEquals("example-sensitive",JsonParser.parseString(raw).asJsonObject
            .get("sshPassword").asString)
    }

    @Test fun undecodableStructuredTextPreservesContentWithoutBorders() {
        val raw="┌────\n│SP-DECODE (.txt)\n├────\nserver.example.org\nport=8443\n└────"
        val displayed=JsonParser.parseString(ResultJsonDisplay.render(raw,"txt")).asJsonObject
        val content=displayed.getAsJsonArray("content")
        assertTrue(content.any{it.asString=="server.example.org"})
        assertTrue(content.any{it.asString=="port=8443"})
        assertFalse(displayed.toString().contains("└"))
    }
}

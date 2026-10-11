package com.ghostdeveloper.spdecode

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Telegram clipboard attribution and transient Home behavior (API 35). */
@RunWith(AndroidJUnit4::class)
class TelegramResultCopyInstrumentedTest {
    @get:Rule val ui=createComposeRule()
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext
    private val sample=DecodeView(
        "test.npvs","npvs",
        """{"metadata":{"policy":{"expiresAt":null}},"document":{"configs":[{"sshConfig":{"sshPassword":"test123","payload":"GET / HTTP/1.1\\nHost: example.org"}}]}}""",
        256,
    )

    @Test fun jsonClipboardMatchesUnmaskedDisplayWithPlaintextCreditsAndCodeFence() {
        val pasted=TelegramResultCopy.clipboard(sample,ResultExport.JSON,"Oct 10, 2026")
        assertTrue(pasted.startsWith("// Decoded by SP-DECODE\n// Date: Oct 10, 2026\n"))
        assertTrue(pasted.contains("// Powered by Ghost Developer\n"))
        assertTrue(pasted.contains("// Credits: @AES224 and @Gh0stDeveloper\n\n"))
        assertTrue(pasted.contains("\n```json\n"))
        assertTrue(pasted.endsWith("\n```"))
        val json=pasted.substringAfter("```json\n").substringBeforeLast("\n```")
        assertEquals(ResultJsonDisplay.render(sample.rawText,sample.extension,false),json)
        val node=JsonParser.parseString(json).asJsonObject
        assertEquals("test123",node.getAsJsonObject("document")
            .getAsJsonArray("configs")[0].asJsonObject
            .getAsJsonObject("sshConfig").get("sshPassword").asString)
        // Export remains machine-parseable JSON, without a Telegram caption.
        val exported=ResultPresentation.formatted(sample.document,ResultExport.JSON)
        assertTrue(JsonParser.parseString(exported).isJsonObject)
        assertFalse(exported.contains("```"))
    }

    @Test fun originalClipboardHasCreditsWithoutChangingUnderlyingDecoderText() {
        val copied=TelegramResultCopy.clipboard(sample,ResultExport.ORIGINAL,"Oct 10")
        assertTrue(copied.startsWith("// Decoded by SP-DECODE\n"))
        assertTrue(copied.contains("// Credits: @AES224 and @Gh0stDeveloper"))
        assertTrue(copied.endsWith("\n\n"+sample.rawText))
        assertEquals(sample.rawText,ResultPresentation.formatted(sample.document,ResultExport.ORIGINAL))
        assertEquals(sample.rawText, sample.document.original)
    }

    @Test fun clearingHomeResultDoesNotDeleteHistoryOrChangeCurrentTab() {
        val old=DecodeView("old.ehi","ehi","{\"saved\":true}",12)
        val saved=listOf(sample,old)
        var visible by mutableStateOf<DecodeView?>(sample)
        var cleared=0
        var deleteCalls=0
        ui.setContent {
            SpDecodeApp(
                activeTab=0,current=visible,session=saved,busy=false,error=null,
                progressStage=0,progressFilename=null,progressPosition=1,
                progressTotal=1,reveal=false,
                onTab={},onImport={},onImportMultiple={},onCancel={},onReveal={},
                onCopy={},onExport={},selectedLanguage="system",
                hideCredentials=false,onLanguage={},onMaskCredentials={},
                onExternalLink={},onSelect={},
                onClear={deleteCalls++},onClearResult={visible=null;cleared++},
                onDeleteSelected={deleteCalls++},onFavorite={_,_->},
                retentionDays=0,onRetention={},onDismissError={},
            )
        }
        ui.onNodeWithContentDescription(ctx.getString(R.string.clear_current_result))
            .performClick()
        ui.onNodeWithText(ctx.getString(R.string.no_result)).assertExists()
        ui.onNodeWithText(old.filename).assertExists() // still in Recent
        ui.runOnIdle {
            assertEquals(1,cleared)
            assertEquals(0,deleteCalls)
            assertEquals(2,saved.size)
        }
    }
}

package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.hasSetTextAction
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** The first real UI must launch, match its accepted layout elements and
 * maintain explicit prototype state; no synthetic sample counts as decoded. */
class FunctionalUiInstrumentedTest {
    @get:Rule val ui=createAndroidComposeRule<MainActivity>()

    private fun awaitStartup() {
        val ctx=ui.activity
        ui.waitUntil(10000) {
            ui.onAllNodesWithContentDescription(ctx.getString(R.string.home))
                .fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test fun mainScreenContainsScreenshotLayoutAndFourTabs(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithText("SP-DECODE").assertExists()
        // The last tab is intentionally persistent; navigate explicitly.
        ui.onNodeWithContentDescription(ctx.getString(R.string.home)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.import_title)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.select_file)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.illustrative)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.home)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.history)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.formats)).assertExists()
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).assertExists()
    }

    @Test fun formatsTabExposesExperimentalSuffixesNotCertified(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithContentDescription(ctx.getString(R.string.formats)).performClick()
        ui.onNode(hasSetTextAction()).performTextInput("sksrv.png")
        ui.onNodeWithText(".sksrv.png").assertExists()
        ui.onNodeWithText("SKS Server").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.catalog_note)).assertExists()
    }

    @Test fun settingsTabClarifiesLocalEncryptedPersistentHistory(){
        awaitStartup()
        val ctx=ui.activity
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.privacy_text)).assertExists()
    }

    @Test fun redactionNeverMutatesOriginalDecoderOutput(){
        val raw="│[۞] Server: example.org\n│[۞] Password: dummy-private\n│[۞] Port: 443"
        val masked=RedactionPolicy.mask(raw)
        assertFalse(masked.contains("dummy-private"))
        assertTrue(masked.contains("Server: example.org"))
        assertTrue(masked.contains("Port: 443"))
        assertEquals(raw,"│[۞] Server: example.org\n│[۞] Password: dummy-private\n│[۞] Port: 443")
    }
}

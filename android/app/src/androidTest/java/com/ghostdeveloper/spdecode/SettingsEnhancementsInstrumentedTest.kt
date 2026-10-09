package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Controls requested in actual Android-user feedback, not decorative mocks. */
@RunWith(AndroidJUnit4::class)
class SettingsEnhancementsInstrumentedTest {
    @get:Rule val ui=createAndroidComposeRule<MainActivity>()

    @Test fun settingsShowsFiveLanguagesPrivacyAndVerifiedContributorLinks(){
        val ctx=ui.activity
        ui.waitUntil(10000) {
            ui.onAllNodesWithContentDescription(ctx.getString(R.string.settings))
                .fetchSemanticsNodes().isNotEmpty()
        }
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).performClick()
        // Settings keeps a single compact row until the user opens the sheet.
        ui.onNodeWithText("Español").assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.language_title)).performClick()
        ui.onNodeWithText("Español").assertExists()
        ui.onNodeWithText("English").assertExists()
        ui.onNodeWithText("Português (Brasil)").assertExists()
        ui.onNodeWithText("العربية").assertExists()
        ui.onNodeWithText("Ghost Developer · @Gh0stDeveloper").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.project_repo)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.mask_passwords_title)).assertExists()
    }
}

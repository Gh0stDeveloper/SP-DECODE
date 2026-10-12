package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.onAllNodesWithText
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

    @Test fun settingsShowsLanguagesPrivacyVersionAndTelegramOnlyLinks(){
        val ctx=ui.activity
        ui.waitUntil(10000) {
            ui.onAllNodesWithContentDescription(ctx.getString(R.string.settings))
                .fetchSemanticsNodes().isNotEmpty()
        }
        if(ui.onAllNodesWithText(ctx.getString(R.string.whats_new_continue)).fetchSemanticsNodes().isNotEmpty())
            ui.onNodeWithText(ctx.getString(R.string.whats_new_continue)).performClick()
        ui.onNodeWithContentDescription(ctx.getString(R.string.settings)).performClick()
        // Settings keeps a single compact row until the user opens the sheet.
        ui.onNodeWithText("Español").assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.language_title)).performClick()
        ui.onNodeWithText("Español").assertExists()
        ui.onNodeWithText("English").assertExists()
        ui.onNodeWithText("Português (Brasil)").assertExists()
        ui.onNodeWithText("العربية").assertExists()
        ui.onNodeWithText("فارسی").assertExists()
        ui.onNodeWithText("Français").assertExists()
        ui.onNodeWithText("Bahasa Indonesia").assertExists()
        ui.onNodeWithText("Русский").assertExists()
        ui.onNodeWithText("Deutsch").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.mask_passwords_title)).assertExists()
        // Telegram is the sole contact surface. No repository/source links.
        ui.onNodeWithText(ctx.getString(R.string.contact_developer)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.telegram_group)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.telegram_channel)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.settings_version,BuildConfig.VERSION_NAME))
            .assertExists()
        ui.onNodeWithText(ctx.getString(R.string.guide_replay)).assertExists()
    }
}

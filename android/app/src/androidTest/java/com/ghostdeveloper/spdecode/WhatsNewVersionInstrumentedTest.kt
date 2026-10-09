package com.ghostdeveloper.spdecode

import android.content.Context
import android.os.Build
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real MainActivity version-gated news dialog, not a permanent splash overlay. */
@RunWith(AndroidJUnit4::class)
class WhatsNewVersionInstrumentedTest {
    @get:Rule val ui=createAndroidComposeRule<MainActivity>()

    @Test fun newsShowsOnlyOncePerInstalledVersionAndSurvivesRecreate(){
        val ctx=ui.activity
        val prefs=ctx.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
        @Suppress("DEPRECATION")
        val info=ctx.packageManager.getPackageInfo(ctx.packageName,0)
        @Suppress("DEPRECATION")
        val version=if(Build.VERSION.SDK_INT>=28)info.longVersionCode else info.versionCode.toLong()
        val previous=prefs.getLong("last_seen_whats_new_version",0L)
        try {
            prefs.edit().remove("last_seen_whats_new_version").commit()
            ui.activityRule.scenario.recreate()
            ui.waitUntil(12000){
                ui.onAllNodesWithText(ui.activity.getString(R.string.whats_new_continue))
                    .fetchSemanticsNodes().isNotEmpty()
            }
            ui.onNodeWithText(ui.activity.getString(R.string.whats_new_title)).assertExists()
            ui.onNodeWithText(ui.activity.getString(R.string.whats_new_linklayer)).assertExists()
            ui.onNodeWithText(ui.activity.getString(R.string.whats_new_continue)).performClick()
            assertEquals(version,prefs.getLong("last_seen_whats_new_version",0L))
            ui.activityRule.scenario.recreate()
            ui.waitUntil(12000){
                ui.onAllNodesWithText(ui.activity.getString(R.string.home))
                    .fetchSemanticsNodes().isNotEmpty() ||
                ui.onAllNodesWithText(ui.activity.getString(R.string.subtitle))
                    .fetchSemanticsNodes().isNotEmpty()
            }
            ui.onNodeWithText(ui.activity.getString(R.string.whats_new_title)).assertDoesNotExist()
        } finally {
            prefs.edit().putLong("last_seen_whats_new_version",previous).commit()
        }
    }
}

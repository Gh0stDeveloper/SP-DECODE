package com.ghostdeveloper.spdecode

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertDoesNotExist
import androidx.compose.ui.test.assertExists
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Modal UX is tested independently of SAF, so no user file is required. */
@RunWith(AndroidJUnit4::class)
class ImportFeedbackInstrumentedTest {
    @get:Rule val ui=createComposeRule()
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext

    private fun render(busy:()->Boolean, stage:()->Int, error:()->String?,
        onCancel:()->Unit, onDismiss:()->Unit) {
        ui.setContent {
            SpDecodeApp(
                activeTab=0,current=null,session=emptyList(),
                busy=busy(),error=error(),progressStage=stage(),
                progressFilename=if(busy())"sample.ehi" else null,
                reveal=false,onTab={},onImport={},onImportMultiple={},
                onCancel=onCancel,onReveal={},onCopy={},onExport={},
                selectedLanguage="system",hideCredentials=false,
                onLanguage={},onMaskCredentials={},onExternalLink={},
                onSelect={},onClear={},onDeleteSelected={},
                onDismissError=onDismiss,
            )
        }
    }

    @Test fun failedDecoderIsExplainedInDismissibleDialog() {
        var error by mutableStateOf(ctx.getString(R.string.unsupported_variant_message))
        render({false},{0},{error},{},{error=null})
        ui.onNodeWithText(ctx.getString(R.string.decode_notice_title)).assertExists()
        ui.onNodeWithText(error!!).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.close)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.decode_notice_title)).assertDoesNotExist()
    }

    @Test fun progressDialogShowsStagesAndProvidesCancellation() {
        var busy by mutableStateOf(true)
        var stage by mutableIntStateOf(0)
        render({busy},{stage},{null},{busy=false},{})
        ui.onNodeWithText(ctx.getString(R.string.decode_progress_title)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.decode_progress_reading)).assertExists()
        ui.onNodeWithText("sample.ehi").assertExists()
        ui.runOnIdle { stage=1 }
        ui.onNodeWithText(ctx.getString(R.string.decode_progress_decoding)).assertExists()
        ui.runOnIdle { stage=2 }
        ui.onNodeWithText(ctx.getString(R.string.decode_progress_saving)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.processing_cancel)).performClick()
        ui.onNodeWithText(ctx.getString(R.string.decode_progress_title)).assertDoesNotExist()
    }
}

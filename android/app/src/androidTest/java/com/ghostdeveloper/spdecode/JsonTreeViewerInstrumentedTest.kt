package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.onAllNodes
import androidx.compose.ui.test.performScrollTo
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.Modifier
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Phase U: syntax-only visual changes; no decoded data is discarded. */
@RunWith(AndroidJUnit4::class)
class JsonTreeViewerInstrumentedTest {
    @get:Rule val compose = createComposeRule()
    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun nestedObjectsExpandAndCollapseWithoutChangingJson() {
        val raw = """{"host":"vpn.test","nested":{"city":"LA","port":443,"active":true}}"""
        val original = ResultJsonDisplay.render(raw, "hc")
        val root = JsonParser.parseString(raw)
        val initial = JsonTreeProjection.project(root)
        assertTrue(initial.any { it.key == "city" && it.kind == JsonTreeProjection.Kind.VALUE })
        assertTrue(initial.any { it.key == "active" && it.value?.asBoolean == true })

        val collapsed = JsonTreeProjection.project(root, mapOf("root/1" to false))
        assertFalse(collapsed.any { it.key == "city" })
        assertTrue(collapsed.any {
            it.key == "nested" && it.kind == JsonTreeProjection.Kind.NODE && !it.expanded
        })
        val expanded = JsonTreeProjection.project(root, mapOf("root/1" to true))
        assertTrue(expanded.any { it.key == "city" })
        assertEquals(original, ResultJsonDisplay.render(raw, "hc"))
    }

    @Test fun largeArraysShowEveryValueWithoutPaginationOrRowCutoff() {
        val text = buildString {
            append("[")
            for (i in 0 until 12500) {
                if (i > 0) append(",")
                append(i)
            }
            append("]")
        }
        val root = JsonParser.parseString(text)
        val first = JsonTreeProjection.project(root)
        assertEquals(12500, first.count { it.kind == JsonTreeProjection.Kind.VALUE })
        assertEquals(12499, first.last { it.kind == JsonTreeProjection.Kind.VALUE }.value!!.asInt)
        assertEquals(12502, first.size)
        assertEquals(12500, root.asJsonArray.size())
    }

    @Test fun fullNestedJsonAndLongValuesUseOnlyTheOuterScroll() {
        val longValue="x".repeat(1800)+"END_OF_COMPLETE_VALUE"
        val raw="""{"profiles":[{"options":{"payload":"$longValue"}}],"items":${(0..99).toList()}}"""
        compose.setContent {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                CompleteResultCard(
                    current=DecodeView("complete.hc","hc",raw,raw.length),
                    reveal=false,hideCredentials=false,onReveal={},onCopy={},onExport={}
                )
            }
        }
        compose.waitUntil(timeoutMillis=20000) {
            compose.onAllNodesWithText("END_OF_COMPLETE_VALUE",substring=true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText("\"payload\": \"$longValue\"",substring=true).assertExists()
        assertEquals(1,compose.onAllNodes(hasScrollAction()).fetchSemanticsNodes().size)
        compose.onNodeWithText("99",substring=false).performScrollTo().assertExists()
        compose.onNodeWithText(ctx.getString(R.string.export)).performScrollTo().assertExists()
        assertEquals(raw,DecodeView("complete.hc","hc",raw,raw.length).rawText)
    }

    @Test fun strangeObjectFieldNamesCannotCollideAndMaskingIsPreserved() {
        val raw = """{"a/b":{"x":1},"a":{"b":{"x":2}},"password":"TEST_ONLY_SECRET"}"""
        val doc = ResultJsonDisplay.element(raw, "ehi", true)
        val rows = JsonTreeProjection.project(doc)
        val paths = rows.map { it.path + ":" + it.kind.name }
        assertEquals(paths.size, paths.distinct().size)
        assertFalse(rows.any { it.value?.isJsonPrimitive == true &&
            it.value.asString == "TEST_ONLY_SECRET" })
        assertTrue(rows.any { it.key == "password" &&
            it.value?.asString == "••••••••" })
        assertEquals("TEST_ONLY_SECRET",JsonParser.parseString(raw)
            .asJsonObject.get("password").asString)
    }

    @Test fun existingResultCardKeepsControlsAndShowsNestedColorReadyJson() {
        val raw = """{"host":"vpn.test","nested":{"city":"LA","port":443,"active":true}}"""
        compose.setContent {
            CompleteResultCard(
                current = DecodeView("sample.hc", "hc", raw, raw.length),
                reveal = false, hideCredentials = false,
                onReveal = {}, onCopy = {}, onExport = {}
            )
        }
        compose.waitUntil(timeoutMillis = 20000) {
            compose.onAllNodesWithText("\"city\": \"LA\"", substring = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText("\"city\": \"LA\"", substring = true).assertExists()
        compose.onNodeWithText("\"port\": 443", substring = true).assertExists()
        compose.onNodeWithText("sample.hc").assertExists()
        compose.onNodeWithText(ctx.getString(R.string.copy)).assertExists()
        compose.onNodeWithText(ctx.getString(R.string.export)).assertExists()
    }
}

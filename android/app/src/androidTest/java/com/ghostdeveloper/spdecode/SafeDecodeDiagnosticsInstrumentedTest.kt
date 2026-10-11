package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Runtime S.3 contract: diagnostics contain only fixed event names and counts. */
@RunWith(AndroidJUnit4::class)
class SafeDecodeDiagnosticsInstrumentedTest {
    @Test fun noContentCanEnterDiagnosticSummary() {
        val before = SafeDecodeDiagnostics.snapshot()
        val fixedEvents = SafeDecodeDiagnostics.Event.entries
        assertEquals(6, fixedEvents.size)
        assertTrue(before.startsWith("SP-DECODE S.3 diagnostic counters"))
        for (event in fixedEvents) {
            SafeDecodeDiagnostics.record(event)
        }
        val after = SafeDecodeDiagnostics.snapshot()
        for (event in fixedEvents) {
            assertTrue(after.contains(event.name + "="))
        }
        val diagnosticLines = after.trim().lines()
        assertEquals(fixedEvents.size + 1, diagnosticLines.size)
        assertTrue(diagnosticLines.drop(1).all { it.matches(Regex("[A-Z_]+=[0-9]{1,4}")) })
        assertFalse(after.contains("password"))
        assertFalse(after.contains("filename"))
        assertFalse(after.contains("file://"))
        assertFalse(after.contains("stacktrace"))
        assertFalse(after.contains("http://"))
        assertFalse(after.contains("https://"))
    }
}

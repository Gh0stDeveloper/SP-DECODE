package com.ghostdeveloper.spdecode

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Real AndroidKeyStore and private filesystem integration, no mocked encryption. */
@RunWith(AndroidJUnit4::class)
class PersistentHistoryInstrumentedTest {
    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun encryptedHistorySurvivesNewStoreInstanceWithoutPlaintextLeaks() {
        val text = "Host: example.org\\nPassword: unique-test-credential"
        val entry = DecodeView("sample.ht", "ht", text, 80)
        val store = SecureDecodeHistory(context)
        try {
            store.save(entry)
            val disk = File(context.noBackupFilesDir, "decode-history/${entry.id}.bin")
            assertTrue(disk.isFile)
            assertFalse(disk.readBytes().toString(Charsets.UTF_8).contains("unique-test-credential"))
            val restored = SecureDecodeHistory(context).load().single { it.id == entry.id }
            assertEquals(entry.filename, restored.filename)
            assertEquals(entry.extension, restored.extension)
            assertEquals(entry.fileBytes, restored.fileBytes)
            assertEquals(entry.rawText, restored.rawText)
            assertEquals(entry.savedAtMillis, restored.savedAtMillis)
        } finally {
            store.delete(setOf(entry.id))
        }
    }

    @Test fun duplicateFileNamesAreIndependentAndMultipleRemovalPreservesUnselected() {
        val store = SecureDecodeHistory(context)
        val a = DecodeView("same.ht", "ht", "first", 2)
        val b = DecodeView("same.ht", "ht", "second", 2)
        val c = DecodeView("other.npvt", "npvt", "third", 3)
        try {
            listOf(a, b, c).forEach(store::save)
            assertTrue(SecureDecodeHistory(context).load().map { it.id }.containsAll(
                listOf(a.id, b.id, c.id)))
            store.delete(setOf(a.id, c.id))
            val remain = SecureDecodeHistory(context).load().map { it.id }
            assertFalse(a.id in remain)
            assertTrue(b.id in remain)
            assertFalse(c.id in remain)
        } finally {
            store.delete(setOf(a.id, b.id, c.id))
        }
    }

    @Test fun decoderCatalogRetainsMultipleExtensionsPerRealApplication() {
        val catalog = AndroidDecoderCatalog.read(context)
        fun suffixes(name: String) = catalog.filter { it.appName == name }.map { it.suffix }.toSet()
        assertEquals(setOf("ht", "htb"), suffixes("HTTP Tweak"))
        assertEquals(setOf("npv4", "npvt"), suffixes("NPV Tunnel v4"))
        assertEquals(setOf("sksrv", "sksrv.png"), suffixes("SKS Server"))
        assertEquals(61, catalog.size)
    }
}

package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.SecureAssetVault
import java.security.MessageDigest
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Phase S source→encrypted APK→runtime byte-for-byte parity with tamper tests. */
@RunWith(AndroidJUnit4::class)
class SecureAssetVaultInstrumentedTest {
    private val instrument get() = InstrumentationRegistry.getInstrumentation()
    private val target get() = instrument.targetContext

    @Test fun allProtectedResourcesMatchOriginalPythonSourceDigests() {
        val fixture = instrument.context.assets.open("parity/s-vault-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use { JSONObject(it.readText()) }
        assertEquals(1, fixture.getInt("schemaVersion"))
        val files = fixture.getJSONObject("files")
        val names = files.keys().asSequence().toList()
        assertTrue(names.size >= 8)
        for (name in names) {
            val original = files.getJSONObject(name)
            val bytes = SecureAssetVault.read(target, name)
            assertEquals("Length differs: $name", original.getInt("bytes"), bytes.size)
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { (it.toInt() and 255).toString(16).padStart(2,'0') }
            assertEquals("Source parity differs: $name", original.getString("sha256"), digest)
            // Source filenames must not also be bundled as readable JSON/Base85.
            assertFalse("Unprotected asset present: $name",
                target.assets.list("")?.contains(name) == true)
        }
    }

    @Test fun corruptedAndSwappedResourcesFailClosed() {
        val name = "generic_b_profiles.json"
        val blob = target.assets.open("$name.spv").use { it.readBytes() }
        assertEquals("SPV1", blob.copyOfRange(0,4).toString(Charsets.US_ASCII))
        val altered = blob.copyOf()
        altered[altered.lastIndex] = (altered.last().toInt() xor 1).toByte()
        try {
            SecureAssetVault.decrypt(name, altered)
            fail("Altered GCM ciphertext accepted")
        } catch (_: SecurityException) {
            // expected: GCM authentication failed
        }
        try {
            SecureAssetVault.decrypt("ultra_c_profiles.json", blob)
            fail("Vault asset re-used under another name")
        } catch (_: SecurityException) {
            // expected: per-filename authenticated associated data
        }
    }

    @Test fun unknownNamesCannotBeUsedAsVaultPaths() {
        try {
            SecureAssetVault.read(target, "../decoder_catalog.json")
            fail("Path traversal accepted")
        } catch (_: IllegalArgumentException) {
            // expected
        }
    }
}

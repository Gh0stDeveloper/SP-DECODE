package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID
import javax.crypto.SecretKey

/**
 * S.4.2: non-destructive on emulator AND real handsets.
 * Every case uses its own debug-only Android Keystore alias and noBackup dir.
 * Never manipulates the real spdecode.private-credentials.v1 alias.
 */
@RunWith(AndroidJUnit4::class)
class DevicePrivateCredentialLifecycleInstrumentedTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private fun namespace() = "s4-" + UUID.randomUUID().toString().replace("-", "").take(20)
    private fun vault(namespace: String) = DevicePrivateCredentialVault(context, namespace)
    private fun alias(namespace: String) = "spdecode.private-credentials.test.$namespace"
    private fun file(namespace: String, id: String) = File(context.noBackupFilesDir,
        "private-credentials-s4-tests/$namespace/$id.s4k")
    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Test fun encryptionSurvivesNewVaultInstanceAndKeepsKeyNonExportable() {
        val namespace = namespace()
        val initial = vault(namespace)
        val material = "synthetic-local-test-only".toByteArray(Charsets.UTF_8)
        val expected = material.copyOf()
        try {
            val record = initial.provision("Session A", material)
            material.fill(0)
            val raw = file(namespace,record.id).readBytes()
            try {
                assertFalse(raw.toString(Charsets.ISO_8859_1)
                    .contains("synthetic-local-test-only"))
                assertEquals("S4K1",raw.copyOfRange(0,4).toString(Charsets.US_ASCII))
            } finally { raw.fill(0) }
            val keystore = keyStore()
            assertTrue(keystore.containsAlias(alias(namespace)))
            assertNull((keystore.getKey(alias(namespace),null) as SecretKey).encoded)

            // Reopen the provider as happens after navigating away and relaunching.
            val reopened = vault(namespace)
            assertEquals(record.id,reopened.inventory().entries.single().id)
            reopened.use(record.id) { bytes -> assertArrayEquals(expected,bytes) }
        } finally {
            material.fill(0)
            expected.fill(0)
            initial.clearAll()
        }
    }

    @Test fun deletingOneCredentialDoesNotRevokeOtherCredentials() {
        val namespace = namespace()
        val store = vault(namespace)
        val first = byteArrayOf(1,2,3,4)
        val second = byteArrayOf(9,8,7,6)
        try {
            val removed = store.provision("Delete this",first)
            val kept = store.provision("Keep this",second)
            store.delete(removed.id)
            assertFalse(file(namespace,removed.id).exists())
            assertThrows(Exception::class.java) { store.use(removed.id) { } }
            assertEquals(listOf(kept.id),store.inventory().entries.map { it.id })
            store.use(kept.id) { bytes -> assertArrayEquals(second,bytes) }
        } finally {
            first.fill(0)
            second.fill(0)
            store.clearAll()
        }
    }

    @Test fun lostKeyNeverSilentlyRecreatesOldSecretsOrDeletesUnreadableRecords() {
        val namespace = namespace()
        val store = vault(namespace)
        val sample = "synthetic-rotation-test".toByteArray(Charsets.UTF_8)
        try {
            val old = store.provision("Before loss",sample)
            assertTrue(file(namespace,old.id).isFile)

            // Simulate Keystore alias deletion ONLY for the isolated test alias.
            keyStore().deleteEntry(alias(namespace))
            assertFalse(keyStore().containsAlias(alias(namespace)))
            val inventoryAfterLoss = store.inventory()
            assertTrue(inventoryAfterLoss.entries.isEmpty())
            assertEquals(1,inventoryAfterLoss.unreadable)
            assertTrue(file(namespace,old.id).isFile)
            assertThrows(Exception::class.java) { store.use(old.id) { } }

            // Provisioning generates a fresh alias; it must not decrypt the old
            // AES-GCM ciphertext or destroy the unreadable record automatically.
            val replacement = store.provision("After loss",sample)
            val reopened = vault(namespace)
            val mixedInventory = reopened.inventory()
            assertEquals(listOf(replacement.id),mixedInventory.entries.map { it.id })
            assertEquals(1,mixedInventory.unreadable)
            assertThrows(Exception::class.java) { reopened.use(old.id) { } }
            reopened.use(replacement.id) { bytes -> assertArrayEquals(sample,bytes) }
            reopened.delete(old.id)
            assertEquals(0,reopened.inventory().unreadable)
            assertEquals(replacement.id,reopened.inventory().entries.single().id)
        } finally {
            sample.fill(0)
            store.clearAll()
        }
    }

    @Test fun corruptCiphertextDoesNotBecomeReadableAfterProviderRecreation() {
        val namespace=namespace()
        val store=vault(namespace)
        try {
            val entry=store.provision("Integrity",byteArrayOf(1,2,3))
            val path=file(namespace,entry.id)
            val original=path.readBytes()
            try {
                original[original.lastIndex]=(original.last().toInt() xor 1).toByte()
                path.writeBytes(original)
            } finally { original.fill(0) }
            val reopened=vault(namespace)
            assertEquals(1,reopened.inventory().unreadable)
            assertThrows(Exception::class.java){reopened.use(entry.id){}}
            assertTrue(path.isFile)
        } finally { store.clearAll() }
    }
}

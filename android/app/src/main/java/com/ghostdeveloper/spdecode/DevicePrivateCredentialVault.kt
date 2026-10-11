package com.ghostdeveloper.spdecode

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Phase S.4: on-device provisioning for secrets supplied by the owner.
 *
 * No credentials are shipped in the APK or sourced from SecureAssetVault.
 * Each record is encrypted with a non-exportable AndroidKeyStore AES-256 key,
 * with a fresh GCM nonce and an authenticated, opaque UUID filename.
 * The credential body is never logged, backed up, stored in preferences/Room
 * or returned to diagnostic/reporting code.
 *
 * Hardware-backed key protection depends on the device; it is not guaranteed.
 * Secrets cannot be recovered after the AndroidKeyStore alias is lost.
 *
 * This is independent of legacy decoder keys: only an explicitly integrated
 * per-format opt-in caller may consume a provisioned secret.
 */
internal class DevicePrivateCredentialVault(context: Context) {
    private val directory = File(context.applicationContext.noBackupFilesDir, "private-credentials")
    private val alias = "spdecode.private-credentials.v1"

    internal data class Metadata(val id: String, val label: String)
    internal data class Inventory(val entries: List<Metadata>, val unreadable: Int)

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    private fun validateId(id: String) {
        require(runCatching { UUID.fromString(id).toString() == id }.getOrDefault(false)) {
            "Invalid credential identifier"
        }
    }

    private fun file(id: String): File {
        validateId(id)
        return File(directory, "$id.s4k")
    }

    /** Caller owns [secret] and must zero it after returning. Never log it. */
    fun provision(label: String, secret: ByteArray): Metadata {
        val value = label.trim()
        val title = value.toByteArray(Charsets.UTF_8)
        require(title.size in 1..MAX_LABEL_BYTES && value.none { it.isISOControl() }) {
            "Invalid credential label"
        }
        require(secret.size in 1..MAX_SECRET_BYTES) { "Invalid credential length" }
        val id = UUID.randomUUID().toString()
        val payload = ByteBuffer.allocate(2 + 4 + title.size + secret.size)
            .putShort(title.size.toShort()).putInt(secret.size)
            .put(title).put(secret).array()
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(aad(id))
            val nonce = cipher.iv.also { require(it.size == NONCE_BYTES) }
            val encrypted = cipher.doFinal(payload)
            if (!directory.isDirectory && !directory.mkdirs()) {
                error("Unable to create private credential directory")
            }
            val record = MAGIC + nonce + encrypted
            val atomic = AtomicFile(file(id))
            var output: java.io.FileOutputStream? = null
            try {
                output = atomic.startWrite()
                output.write(record)
                atomic.finishWrite(output)
            } catch (failure: Exception) {
                output?.let { atomic.failWrite(it) }
                throw failure
            } finally {
                record.fill(0)
                encrypted.fill(0)
            }
            return Metadata(id, value)
        } finally {
            payload.fill(0)
            title.fill(0)
        }
    }

    private fun readRecord(id: String, action: (String, ByteArray) -> Unit) {
        val atomic = AtomicFile(file(id))
        val bytes = atomic.openRead().use { stream ->
            require(atomic.baseFile.length() in MIN_RECORD_BYTES.toLong()..MAX_RECORD_BYTES.toLong()) {
                "Invalid credential record size"
            }
            stream.readBytes()
        }
        try {
            require(bytes.size in MIN_RECORD_BYTES..MAX_RECORD_BYTES)
            require(bytes.copyOfRange(0, 4).contentEquals(MAGIC)) {
                "Unsupported credential record version"
            }
            val nonce = bytes.copyOfRange(4, 4 + NONCE_BYTES)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad(id))
            val clear = cipher.doFinal(bytes, 4 + NONCE_BYTES, bytes.size - 4 - NONCE_BYTES)
            try {
                val input = ByteBuffer.wrap(clear)
                require(input.remaining() >= 6)
                val labelSize = input.short.toInt() and 0xFFFF
                val secretSize = input.int
                require(labelSize in 1..MAX_LABEL_BYTES && secretSize in 1..MAX_SECRET_BYTES)
                require(input.remaining() == labelSize + secretSize)
                val labelBytes = ByteArray(labelSize)
                input.get(labelBytes)
                val label = labelBytes.toString(Charsets.UTF_8)
                labelBytes.fill(0)
                require(label.isNotBlank() && label.none { it.isISOControl() })
                val secretBytes = ByteArray(secretSize)
                input.get(secretBytes)
                try {
                    action(label, secretBytes)
                } finally {
                    secretBytes.fill(0)
                }
            } finally {
                clear.fill(0)
            }
        } finally {
            bytes.fill(0)
        }
    }

    /** Lists ONLY display names; decryption failures are counted, never deleted. */
    fun inventory(): Inventory {
        val files = directory.listFiles().orEmpty()
            .filter { it.isFile && (it.name.endsWith(".s4k") || it.name.endsWith(".s4k.bak")) }
            .map { it.name.removeSuffix(".bak").removeSuffix(".s4k") }.distinct()
        val entries = mutableListOf<Metadata>()
        var unreadable = 0
        for (id in files) {
            if (runCatching { validateId(id) }.isFailure) {
                unreadable++
                continue
            }
            try {
                readRecord(id) { label, _ -> entries += Metadata(id, label) }
            } catch (_: Exception) {
                unreadable++
            }
        }
        return Inventory(entries.sortedBy { it.label.lowercase() }, unreadable)
    }

    /**
     * No general public accessor. Authorized in-process callers receive bytes
     * only inside [consumer]; they are zeroed immediately when it returns.
     */
    fun <T> use(id: String, consumer: (ByteArray) -> T): T {
        var result: Any? = null
        readRecord(id) { _, secret -> result = consumer(secret) }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }

    fun delete(id: String) {
        val target = file(id)
        val atomic = AtomicFile(target)
        if (!target.exists() && !File(target.path + ".bak").exists()) return
        atomic.delete()
        check(!target.exists() && !File(target.path + ".bak").exists()) {
            "Private credential deletion was not completed"
        }
    }

    /** Explicit destructive wipe, never tied to ordinary history deletion. */
    fun clearAll() {
        if (directory.exists()) check(directory.deleteRecursively()) {
            "Private credentials could not be cleared"
        }
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(alias)) deleteEntry(alias)
        }
    }

    private fun aad(id: String): ByteArray =
        "spdecode:s4:private-credential:$id".toByteArray(Charsets.US_ASCII)

    private companion object {
        val MAGIC = byteArrayOf(0x53, 0x34, 0x4B, 0x31) // S4K1
        const val NONCE_BYTES = 12
        const val MAX_LABEL_BYTES = 96
        const val MAX_SECRET_BYTES = 4096
        const val MIN_RECORD_BYTES = 4 + NONCE_BYTES + 16 + 2 + 4 + 1 + 1
        const val MAX_RECORD_BYTES = 4 + NONCE_BYTES + 16 + 2 + 4 + MAX_LABEL_BYTES + MAX_SECRET_BYTES
    }
}

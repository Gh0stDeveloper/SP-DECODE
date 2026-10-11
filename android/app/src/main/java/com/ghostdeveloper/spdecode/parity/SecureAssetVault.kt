package com.ghostdeveloper.spdecode.parity

import android.content.Context
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Phase S encrypted offline resource reader.
 *
 * No sensitive source JSON or NPVS tables are present as readable APK assets.
 * AES-256-GCM authenticates the header/payload and binds each blob to its
 * expected filename with AAD; swapped or corrupted resources fail closed.
 *
 * SECURITY LIMIT: the generated unwrap key travels inside the APK so a
 * determined analyst can reconstruct it. Do not use this to hold newly private
 * credentials or claim that public legacy decoder constants become secret.
 */
internal object SecureAssetVault {
    internal val names = setOf(
        "embedded_kotlin_profiles.json",
        "flex_f_profiles.json",
        "generic_b_profiles.json",
        "hc_source_keys.json",
        "http_tweak_source_tables.json",
        "legacy_epro_npv2_keys.json",
        "npvs_v5_tables.b85",
        "npv_whitebox.bin",
        "renz_d_profiles.json",
        "ultra_c_profiles.json",
    )
    private val magic = byteArrayOf(0x53, 0x50, 0x56, 0x31) // SPV1
    private const val MAX_ASSET_BYTES = 8 * 1024 * 1024

    fun open(context: Context, name: String): InputStream =
        ByteArrayInputStream(read(context, name))

    fun readText(context: Context, name: String): String =
        read(context, name).toString(Charsets.UTF_8)

    fun read(context: Context, name: String): ByteArray {
        require(name in names) { "Resource is not registered in protected vault" }
        val blob = context.assets.open("$name.spv").use { stream ->
            val bytes = stream.readBytes()
            require(bytes.size <= MAX_ASSET_BYTES + 32) { "Vault asset exceeds size cap" }
            bytes
        }
        return decrypt(name, blob)
    }

    /** Accessible by Android instrumentation to reject tampered test blobs. */
    internal fun decrypt(name: String, blob: ByteArray): ByteArray {
        require(name in names) { "Unregistered resource" }
        require(blob.size in 33..(MAX_ASSET_BYTES + 32)) { "Bad protected resource size" }
        require(blob.copyOfRange(0, 4).contentEquals(magic)) { "Bad protected resource version" }
        val nonce = blob.copyOfRange(4, 16)
        val key = VaultBuildKey.material()
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD("spdecode:s1:$name".toByteArray(Charsets.UTF_8))
            cipher.doFinal(blob, 16, blob.size - 16)
        } catch (_: GeneralSecurityException) {
            throw SecurityException("Protected resource authentication failed")
        } finally {
            key.fill(0)
        }
    }
}

package com.ghostdeveloper.spdecode.parity

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * NPVS v5 authenticated decrypt primitive, equivalent to npvs.py _open().
 * The JCA ChaCha20-Poly1305 provider verifies the final 16-byte Poly1305 tag.
 * Never return unauthenticated plaintext.
 */
internal object NpvsV5Crypto {
    fun open(key: ByteArray, nonce: ByteArray, ciphertextAndTag: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == 32) { "Invalid ChaCha20 key length" }
        require(nonce.size == 12) { "Invalid ChaCha20 nonce length" }
        require(ciphertextAndTag.size >= 16) { "Truncated authenticated ciphertext" }
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertextAndTag)
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}

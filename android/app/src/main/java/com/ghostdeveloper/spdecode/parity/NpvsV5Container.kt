package com.ghostdeveloper.spdecode.parity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * NPVS v5 binary container parser. This is deliberately NOT registered as a
 * decoder until the Python-compatible authenticated cryptographic pipeline
 * and golden fixture parity have been implemented.
 *
 * Reference: decoders/Python/npvs.py (analysis/npvs-v5).
 * Do not route NPVS to legacy .npv2, .npv4 or .npvt implementations.
 */
internal object NpvsV5Container {
    private const val MAX_BYTES = 4 * 1024 * 1024
    private val MAGIC = byteArrayOf(0x4e, 0x50, 0x56, 0x53)

    data class Envelope(
        val header: ByteArray,
        val nonce: ByteArray,
        val body: ByteArray,
        val signature: ByteArray,
        val signedBytes: ByteArray,
    )

    fun parse(input: ByteArray): Envelope {
        require(input.size <= MAX_BYTES) { "NPVS file too large" }
        require(input.size >= 4 + 1 + 4 + 12 + 4 + 64) { "Truncated NPVS" }
        require(input.copyOfRange(0, 4).contentEquals(MAGIC)) { "Not NPVS" }
        require(input[4].toInt() and 255 == 5) { "Unsupported NPVS version" }
        val b = ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN)
        b.position(5)
        val headerSize = b.int
        require(headerSize > 0 && headerSize <= b.remaining() - 12 - 4 - 64) {
            "Invalid NPVS header size"
        }
        val header = ByteArray(headerSize).also { b.get(it) }
        val nonce = ByteArray(12).also { b.get(it) }
        val bodySize = b.int
        require(bodySize >= 0 && bodySize.toLong() + 64L == b.remaining().toLong()) {
            "Invalid NPVS body size"
        }
        val body = ByteArray(bodySize).also { b.get(it) }
        val signature = ByteArray(64).also { b.get(it) }
        require(!b.hasRemaining()) { "Trailing NPVS data" }
        return Envelope(header, nonce, body, signature, input.copyOfRange(0, input.size - 64))
    }
}

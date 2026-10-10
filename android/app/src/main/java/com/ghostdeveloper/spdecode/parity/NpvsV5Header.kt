package com.ghostdeveloper.spdecode.parity

/**
 * NPVS v5 compact app-key header layout, matching npvs.py decode_npvs().
 * Parsing is strict and does not silently accept other exporter modes.
 */
internal object NpvsV5Header {
    data class AppKey(
        val configId: ByteArray,
        val publicKeyCompressed: ByteArray,
        val salt: ByteArray,
        val wrappedDek: ByteArray,
        val encryptedMetadata: ByteArray,
        val metadataAad: ByteArray,
    )

    fun parse(header: ByteArray): AppKey {
        require(header.size in 135..262144) { "Invalid NPVS header length" }
        require((header[0].toInt() and 255) == 1) { "Unsupported compact header version" }
        require((header[50].toInt() and 255) == 2) { "Unsupported NPVS key mode" }
        val recipients = ((header[51].toInt() and 255) shl 8) or (header[52].toInt() and 255)
        require(recipients <= 1024) { "Too many recipients" }
        val offset = 53 + recipients * 125
        require(offset + 82 <= header.size) { "Truncated app-key descriptor" }
        require(header[offset] == 0.toByte() && header[offset + 1] == 2.toByte()) {
            "Unsupported app-key descriptor"
        }
        val prefixEnd = offset + 78
        val metadataSize = ((header[prefixEnd].toLong() and 255L) shl 24) or
            ((header[prefixEnd + 1].toLong() and 255L) shl 16) or
            ((header[prefixEnd + 2].toLong() and 255L) shl 8) or
            (header[prefixEnd + 3].toLong() and 255L)
        require(metadataSize >= 16 && prefixEnd.toLong() + 4 + metadataSize == header.size.toLong()) {
            "Invalid metadata size"
        }
        return AppKey(
            configId = header.copyOfRange(1,17),
            publicKeyCompressed = header.copyOfRange(17,50),
            salt = header.copyOfRange(offset+2,offset+18),
            wrappedDek = header.copyOfRange(offset+18,offset+78),
            encryptedMetadata = header.copyOfRange(prefixEnd+4,header.size),
            metadataAad = header.copyOfRange(0,prefixEnd),
        )
    }
}

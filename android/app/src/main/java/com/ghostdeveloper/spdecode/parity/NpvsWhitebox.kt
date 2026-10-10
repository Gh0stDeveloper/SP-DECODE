package com.ghostdeveloper.spdecode.parity

import android.content.Context
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.zip.Inflater

/** NPVS v5 white-box tables are stored as a data-only asset. */
internal object NpvsWhitebox {
    private const val ASSET = "npvs_v5_tables.b85"
    private const val LENGTH = 749569
    private const val SHA = "35717e8267a115fbf474e3cd622066783feea21305457c840cabd57a73086f7d"
    private val alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_" +
        96.toChar() + "{|}~"
    private fun decode85(text: String): ByteArray {
        val inverse = IntArray(128) { -1 }
        for (i in alphabet.indices) inverse[alphabet[i].code] = i
        val out = ByteArrayOutputStream(text.length * 4 / 5 + 4)
        var start = 0
        while (start < text.length) {
            val n = minOf(5, text.length - start)
            require(n >= 2)
            var word = 0L
            for (i in 0 until 5) {
                val digit = if (i < n) {
                    val ch = text[start + i].code
                    require(ch < 128 && inverse[ch] >= 0)
                    inverse[ch]
                } else 84
                word = word * 85L + digit
            }
            require(word <= 0xffffffffL)
            for (i in 0 until n - 1) out.write((word ushr (24 - 8 * i)).toInt() and 255)
            start += n
        }
        return out.toByteArray()
    }
    private fun bytes(context: Context): ByteArray {
        val encoded = context.assets.open(ASSET).bufferedReader(Charsets.US_ASCII)
            .use { it.readText().trim() }
        val zlib = decode85(encoded)
        val inflater = Inflater()
        val out = ByteArrayOutputStream(LENGTH)
        try {
            inflater.setInput(zlib)
            val buffer = ByteArray(8192)
            while (!inflater.finished()) {
                val count = inflater.inflate(buffer)
                require(count > 0 && out.size() + count <= LENGTH)
                out.write(buffer, 0, count)
            }
            require(inflater.remaining == 0)
        } finally { inflater.end() }
        return out.toByteArray().also { table ->
            require(table.size == LENGTH)
            val digest = MessageDigest.getInstance("SHA-256").digest(table)
                .joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
            require(digest == SHA)
        }
    }
    @Volatile private var cached: ByteArray? = null
    fun tables(context: Context): ByteArray =
        cached ?: synchronized(this) { cached ?: bytes(context).also { cached = it } }
}

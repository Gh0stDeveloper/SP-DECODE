package com.ghostdeveloper.spdecode

import java.util.concurrent.atomic.AtomicIntegerArray

/**
 * Phase S.3 — deliberately content-free, in-memory diagnostic counters.
 *
 * Never accepts Throwable, user text, decrypted output, filenames, URIs,
 * passwords, raw input or JSON. No Logcat, disk, analytics, network or
 * exported Intent sink. A manually requested support summary can contain
 * ONLY public event codes with bounded counts.
 *
 * These counters vanish when the process ends and do not change decoder
 * behavior, encrypted history, sharing or full-result presentation.
 */
internal object SafeDecodeDiagnostics {
    enum class Event {
        TEXT_UNSUPPORTED,
        TEXT_FAILURE,
        FILE_IMPORT_FAILURE,
        HISTORY_READ_FAILURE,
        HISTORY_WRITE_FAILURE,
        EXPORT_FAILURE,
    }

    private const val LIMIT = 9999
    private val totals = AtomicIntegerArray(Event.entries.size)

    fun record(event: Event) {
        val i = event.ordinal
        while (true) {
            val previous = totals.get(i)
            if (previous >= LIMIT) return
            if (totals.compareAndSet(i, previous, previous + 1)) return
        }
    }

    /** No hidden raw data: deterministic, bounded, safe for manual issue reports. */
    fun snapshot(): String = buildString {
        append("SP-DECODE S.3 diagnostic counters (local, no user data)\n")
        for (event in Event.entries) {
            append(event.name)
            append('=')
            append(totals.get(event.ordinal))
            append('\n')
        }
    }
}

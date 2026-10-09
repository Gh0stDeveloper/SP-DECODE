package com.ghostdeveloper.spdecode

import android.app.Activity
import android.os.Bundle
import android.widget.TextView

/**
 * Test-only Android host, NOT a production decoder UI or finished application.
 * Full Compose / SAF / persistence belongs to Phase B and later.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "SP-DECODE · Android parity test host. No user-facing decoders enabled."
            textSize = 16f
            setPadding(28, 28, 28, 28)
        })
    }
}

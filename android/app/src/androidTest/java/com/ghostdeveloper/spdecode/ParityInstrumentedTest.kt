package com.ghostdeveloper.spdecode

import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.V2RayReferencePort
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Executes on an actual Android runtime. CI may only mark parity verified
 * once the emulator job itself succeeds; a JVM compile is not equivalent.
 */
@RunWith(AndroidJUnit4::class)
class ParityInstrumentedTest {
    private val assets get() = InstrumentationRegistry.getInstrumentation().context.assets

    private fun fixture(name: String): ByteArray =
        assets.open("parity/$name").use { it.readBytes() }

    @Test
    fun syntheticPlainV2MatchesLinuxRawUtf8() {
        assertArrayEquals(
            fixture("ev2ray-plain.txt"),
            V2RayReferencePort.decode(fixture("ev2ray-plain.v2"))?.toByteArray(Charsets.UTF_8)
        )
    }

    @Test
    fun syntheticAesV2MatchesLinuxRawUtf8() {
        assertArrayEquals(
            fixture("ev2ray-aes128.txt"),
            V2RayReferencePort.decode(fixture("ev2ray-aes128.v2"))?.toByteArray(Charsets.UTF_8)
        )
    }

    @Test
    fun malformedProfileAndOversizedDataAreNotSuccessful() {
        assertNull(V2RayReferencePort.decode(byteArrayOf()))
        assertNull(V2RayReferencePort.decode("bad-profile".toByteArray()))
        assertNull(V2RayReferencePort.decode(ByteArray(1024 * 1024 + 1)))
        val damaged = fixture("ev2ray-aes128.v2").clone()
        damaged[damaged.size / 2] = (damaged[damaged.size / 2].toInt() xor 1).toByte()
        assertNull(V2RayReferencePort.decode(damaged))
    }

    @Test
    fun registryHas59SuffixesButNeverClaims59WorkingAndroidDecoders() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val formats = com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog.read(context)
        val resolver = com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
        assertEquals(59, formats.size)
        assertEquals("sksrv.png", resolver.detect("MYCONFIG.SKSRV.PNG", formats)?.suffix)
        assertEquals("fɴ", resolver.detect("MYCONFIG.Fɴ", formats)?.suffix)
        assertEquals("v2", resolver.detect("test.v2", formats)?.suffix)
        assertEquals("prototype_two_synthetic_cases", resolver.detect("test.v2", formats)?.portStatus)
        assertEquals(0, formats.count { it.androidVerified })
        assertEquals(58, formats.count { it.portStatus == "not_implemented" })
        assertNull(resolver.detect("unrecognized.unknown", formats))
    }

    @Test
    fun mergedManifestHasNoInternetAndNoStoragePermissions() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions.orEmpty().toSet()
        for (forbidden in listOf(
            "android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
        )) {
            assertFalse("Forbidden permission $forbidden", requested.contains(forbidden))
        }
    }
}

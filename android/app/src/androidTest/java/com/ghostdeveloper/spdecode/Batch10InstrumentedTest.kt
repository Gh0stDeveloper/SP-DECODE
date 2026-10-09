package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import com.ghostdeveloper.spdecode.parity.*

/**
 * One Linux SHA-256-pinned synthetic fixture per independent Android decoder.
 * Passing in emulator proves these exact vectors only, not current exports.
 */
@RunWith(AndroidJUnit4::class)
class Batch10InstrumentedTest {
    private val assets get() = InstrumentationRegistry.getInstrumentation().context.assets
    private fun asset(filename: String): ByteArray =
        assets.open("parity/$filename").use { it.readBytes() }

    @Test
    fun phcMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch4-phc.txt"),
            PhcPort.decode(asset("batch4-phc.phc"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun minaMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch5-mina.txt"),
            MinaPort.decode(asset("batch5-mina.mina"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun vpnLiteMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch6-vpnlite.txt"),
            VpnLitePort.decode(asset("batch6-vpnlite.vpnlite"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun cloudyMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch4-cloudy.txt"),
            CloudyPort.decode(asset("batch4-cloudy.cloudy"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun mijMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch4-mij.txt"),
            MijPort.decode(asset("batch4-mij.mij"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun fnNetworkMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch4-fnnetwork.txt"),
            FnNetworkPort.decode(asset("batch4-fnnetwork.fnnetwork"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun uwuMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch4-uwu.txt"),
            UwuPort.decode(asset("batch4-uwu.uwu"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun sksrvMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("sksrv-sksrv.txt"),
            SksrvPort.decode(asset("sksrv-sksrv.sksrv"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun mayaMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch5-maya.txt"),
            MayaPort.decode(asset("batch5-maya.maya"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun xuiMatchesOriginalLinuxGolden() {
        assertArrayEquals(asset("batch5-xui.txt"),
            XuiPort.decode(asset("batch5-xui.xui"))?.toByteArray(Charsets.UTF_8))
    }

    @Test
    fun batch10FailClosedOnEmptyMalformedAndOversizeInputs() {
        assertNull("Phc empty", PhcPort.decode(byteArrayOf()))
        assertNull("Phc malformed", PhcPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Phc oversized", PhcPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Mina empty", MinaPort.decode(byteArrayOf()))
        assertNull("Mina malformed", MinaPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Mina oversized", MinaPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("VpnLite empty", VpnLitePort.decode(byteArrayOf()))
        assertNull("VpnLite malformed", VpnLitePort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("VpnLite oversized", VpnLitePort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Cloudy empty", CloudyPort.decode(byteArrayOf()))
        assertNull("Cloudy malformed", CloudyPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Cloudy oversized", CloudyPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Mij empty", MijPort.decode(byteArrayOf()))
        assertNull("Mij malformed", MijPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Mij oversized", MijPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("FnNetwork empty", FnNetworkPort.decode(byteArrayOf()))
        assertNull("FnNetwork malformed", FnNetworkPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("FnNetwork oversized", FnNetworkPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Uwu empty", UwuPort.decode(byteArrayOf()))
        assertNull("Uwu malformed", UwuPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Uwu oversized", UwuPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Sksrv empty", SksrvPort.decode(byteArrayOf()))
        assertNull("Sksrv malformed", SksrvPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Sksrv oversized", SksrvPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Maya empty", MayaPort.decode(byteArrayOf()))
        assertNull("Maya malformed", MayaPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Maya oversized", MayaPort.decode(ByteArray(1024 * 1024 + 1)))
        assertNull("Xui empty", XuiPort.decode(byteArrayOf()))
        assertNull("Xui malformed", XuiPort.decode("NOT_A_PROFILE".toByteArray()))
        assertNull("Xui oversized", XuiPort.decode(ByteArray(1024 * 1024 + 1)))
    }
}

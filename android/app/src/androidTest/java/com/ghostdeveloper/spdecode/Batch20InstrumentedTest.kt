package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exact 10 new goldens; each routes to exactly its original native decoder. */
@RunWith(AndroidJUnit4::class)
class Batch20InstrumentedTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private fun asset(filename: String): ByteArray =
        instrumentation.context.assets.open("parity/$filename").use { it.readBytes() }

    @Test fun atMatchesLinuxAndStrictDispatch() {
        val source=asset("batch6-at.at")
        val gold=asset("batch6-at.txt")
        assertArrayEquals(gold,AtPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.AT",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun nmMatchesLinuxAndStrictDispatch() {
        val source=asset("batch6-nm.nm")
        val gold=asset("batch6-nm.txt")
        assertArrayEquals(gold,NmPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.NM",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun ostMatchesLinuxAndStrictDispatch() {
        val source=asset("batch4-ost.ost")
        val gold=asset("batch4-ost.txt")
        assertArrayEquals(gold,OstPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.OST",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun sbrMatchesLinuxAndStrictDispatch() {
        val source=asset("batch4-sbr.sbr")
        val gold=asset("batch4-sbr.txt")
        assertArrayEquals(gold,SbrPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.SBR",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun pcxMatchesLinuxAndStrictDispatch() {
        val source=asset("batch6-pcx.pcx")
        val gold=asset("batch6-pcx.txt")
        assertArrayEquals(gold,PcxPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.PCX",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun ntMatchesLinuxAndStrictDispatch() {
        val source=asset("batch6-nt.nt")
        val gold=asset("batch6-nt.txt")
        assertArrayEquals(gold,NtPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.NT",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun pbMatchesLinuxAndStrictDispatch() {
        val source=asset("batch6-pb.pb")
        val gold=asset("batch6-pb.txt")
        assertArrayEquals(gold,PbPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.PB",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun aroMatchesLinuxAndStrictDispatch() {
        val source=asset("aro-minus18.aro")
        val gold=asset("aro-minus18.txt")
        assertArrayEquals(gold,AroPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.ARO",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun iptMatchesLinuxAndStrictDispatch() {
        val source=asset("batch6-ipt.ipt")
        val gold=asset("batch6-ipt.txt")
        assertArrayEquals(gold,IptPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.IPT",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun goldMatchesLinuxAndStrictDispatch() {
        val source=asset("batch7-gold.gold")
        val gold=asset("batch7-gold.txt")
        assertArrayEquals(gold,GoldPort.decode(source)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(gold,AndroidOfflineDecoderRouter.decode(
            instrumentation.targetContext,"test.GOLD",source)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun unsupportedOrMalformedFilesNeverReturnDecodedProfile() {
        val context=instrumentation.targetContext
        assertNull(AndroidOfflineDecoderRouter.decode(context,"unsupported.xzz",asset("batch6-at.at")))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"sample.at",asset("batch6-nm.nm")))
        assertNull("at empty",AtPort.decode(byteArrayOf()))
        assertNull("at random",AtPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("at oversized",AtPort.decode(ByteArray(1024*1024+1)))
        assertNull("nm empty",NmPort.decode(byteArrayOf()))
        assertNull("nm random",NmPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("nm oversized",NmPort.decode(ByteArray(1024*1024+1)))
        assertNull("ost empty",OstPort.decode(byteArrayOf()))
        assertNull("ost random",OstPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("ost oversized",OstPort.decode(ByteArray(1024*1024+1)))
        assertNull("sbr empty",SbrPort.decode(byteArrayOf()))
        assertNull("sbr random",SbrPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("sbr oversized",SbrPort.decode(ByteArray(1024*1024+1)))
        assertNull("pcx empty",PcxPort.decode(byteArrayOf()))
        assertNull("pcx random",PcxPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("pcx oversized",PcxPort.decode(ByteArray(1024*1024+1)))
        assertNull("nt empty",NtPort.decode(byteArrayOf()))
        assertNull("nt random",NtPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("nt oversized",NtPort.decode(ByteArray(1024*1024+1)))
        assertNull("pb empty",PbPort.decode(byteArrayOf()))
        assertNull("pb random",PbPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("pb oversized",PbPort.decode(ByteArray(1024*1024+1)))
        assertNull("aro empty",AroPort.decode(byteArrayOf()))
        assertNull("aro random",AroPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("aro oversized",AroPort.decode(ByteArray(1024*1024+1)))
        assertNull("ipt empty",IptPort.decode(byteArrayOf()))
        assertNull("ipt random",IptPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("ipt oversized",IptPort.decode(ByteArray(1024*1024+1)))
        assertNull("gold empty",GoldPort.decode(byteArrayOf()))
        assertNull("gold random",GoldPort.decode("INVALID PROFILE".toByteArray()))
        assertNull("gold oversized",GoldPort.decode(ByteArray(1024*1024+1)))
    }
}

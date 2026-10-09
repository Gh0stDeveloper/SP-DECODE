package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Each golden comes from the original standalone Linux decoder. */
@RunWith(AndroidJUnit4::class)
class Final11InstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private fun asset(name:String):ByteArray=
        inst.context.assets.open("parity/$name").use {it.readBytes()}

    @Test fun rezMatchesExactGoldenAndRouter() {
        val raw=asset("batch5-rez.rez")
        val expected=asset("batch5-rez.txt")
        assertArrayEquals(expected,RezPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.REZ",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun rezlMatchesExactGoldenAndRouter() {
        val raw=asset("batch5-rezl.rezl")
        val expected=asset("batch5-rezl.txt")
        assertArrayEquals(expected,RezlPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.REZL",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun tvtMatchesExactGoldenAndRouter() {
        val raw=asset("batch7-tvt.tvt")
        val expected=asset("batch7-tvt.txt")
        assertArrayEquals(expected,TvtPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.TVT",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun stkMatchesExactGoldenAndRouter() {
        val raw=asset("batch6-stk.stk")
        val expected=asset("batch6-stk.txt")
        assertArrayEquals(expected,StkPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.STK",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun xtpMatchesExactGoldenAndRouter() {
        val raw=asset("batch7-xtp.xtp")
        val expected=asset("batch7-xtp.txt")
        assertArrayEquals(expected,XtpPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.XTP",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun royMatchesExactGoldenAndRouter() {
        val raw=asset("batch7-roy.roy")
        val expected=asset("batch7-roy.txt")
        assertArrayEquals(expected,RoyPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.ROY",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sksplusMatchesExactGoldenAndRouter() {
        val raw=asset("batch4-sksplus.sksplus")
        val expected=asset("batch4-sksplus.txt")
        assertArrayEquals(expected,SksplusPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.SKSPLUS",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sksMatchesExactGoldenAndRouter() {
        val raw=asset("batch4-sks.sks")
        val expected=asset("batch4-sks.txt")
        assertArrayEquals(expected,SksPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.SKS",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sutMatchesExactGoldenAndRouter() {
        val raw=asset("batch7-sut.sut")
        val expected=asset("batch7-sut.txt")
        assertArrayEquals(expected,SutPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.SUT",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun tnlMatchesExactGoldenAndRouter() {
        val raw=asset("batch5-tnl.tnl")
        val expected=asset("batch5-tnl.txt")
        assertArrayEquals(expected,TnlPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.TNL",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sshMatchesExactGoldenAndRouter() {
        val raw=asset("batch8-ssh.ssh")
        val expected=asset("batch8-ssh.txt")
        assertArrayEquals(expected,SshPort.decode(raw)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.SSH",raw)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun rejectAll11MalformedAndOversized() {
        val ctx=inst.targetContext
        assertNull(AndroidOfflineDecoderRouter.decode(ctx,"not_registered.mock",asset("batch5-rez.rez")))
        assertNull(AndroidOfflineDecoderRouter.decode(ctx,"wrong.ssh",asset("batch5-rez.rez")))
        assertNull("rez empty",RezPort.decode(byteArrayOf()))
        assertNull("rez bogus",RezPort.decode("bad profile".toByteArray()))
        assertNull("rez too large",RezPort.decode(ByteArray(1024*1024+1)))
        assertNull("rezl empty",RezlPort.decode(byteArrayOf()))
        assertNull("rezl bogus",RezlPort.decode("bad profile".toByteArray()))
        assertNull("rezl too large",RezlPort.decode(ByteArray(1024*1024+1)))
        assertNull("tvt empty",TvtPort.decode(byteArrayOf()))
        assertNull("tvt bogus",TvtPort.decode("bad profile".toByteArray()))
        assertNull("tvt too large",TvtPort.decode(ByteArray(1024*1024+1)))
        assertNull("stk empty",StkPort.decode(byteArrayOf()))
        assertNull("stk bogus",StkPort.decode("bad profile".toByteArray()))
        assertNull("stk too large",StkPort.decode(ByteArray(1024*1024+1)))
        assertNull("xtp empty",XtpPort.decode(byteArrayOf()))
        assertNull("xtp bogus",XtpPort.decode("bad profile".toByteArray()))
        assertNull("xtp too large",XtpPort.decode(ByteArray(1024*1024+1)))
        assertNull("roy empty",RoyPort.decode(byteArrayOf()))
        assertNull("roy bogus",RoyPort.decode("bad profile".toByteArray()))
        assertNull("roy too large",RoyPort.decode(ByteArray(1024*1024+1)))
        assertNull("sksplus empty",SksplusPort.decode(byteArrayOf()))
        assertNull("sksplus bogus",SksplusPort.decode("bad profile".toByteArray()))
        assertNull("sksplus too large",SksplusPort.decode(ByteArray(1024*1024+1)))
        assertNull("sks empty",SksPort.decode(byteArrayOf()))
        assertNull("sks bogus",SksPort.decode("bad profile".toByteArray()))
        assertNull("sks too large",SksPort.decode(ByteArray(1024*1024+1)))
        assertNull("sut empty",SutPort.decode(byteArrayOf()))
        assertNull("sut bogus",SutPort.decode("bad profile".toByteArray()))
        assertNull("sut too large",SutPort.decode(ByteArray(1024*1024+1)))
        assertNull("tnl empty",TnlPort.decode(byteArrayOf()))
        assertNull("tnl bogus",TnlPort.decode("bad profile".toByteArray()))
        assertNull("tnl too large",TnlPort.decode(ByteArray(1024*1024+1)))
        assertNull("ssh empty",SshPort.decode(byteArrayOf()))
        assertNull("ssh bogus",SshPort.decode("bad profile".toByteArray()))
        assertNull("ssh too large",SshPort.decode(ByteArray(1024*1024+1)))
    }
}

package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exact synthetic Linux outputs, Android runtime and strict per-suffix routing. */
@RunWith(AndroidJUnit4::class)
class Batch15InstrumentedTest {
    private val instrumentation get()=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private fun fixture(name:String):ByteArray =
        instrumentation.context.assets.open("parity/$name").use {it.readBytes()}


    @Test fun agnMatchesLinuxAndDispatch() {
        val input=fixture("multides-agn.agn")
        val golden=fixture("multides-agn.txt")
        assertArrayEquals(golden,AgnPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.AGN",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun clyMatchesLinuxAndDispatch() {
        val input=fixture("multides-cly.cly")
        val golden=fixture("multides-cly.txt")
        assertArrayEquals(golden,ClyPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.CLY",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun f274MatchesLinuxAndDispatch() {
        val input=fixture("multides-fɴ.fɴ")
        val golden=fixture("multides-fɴ.txt")
        assertArrayEquals(golden,FnLegacyPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.Fɴ",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun jvcMatchesLinuxAndDispatch() {
        val input=fixture("multides-jvc.jvc")
        val golden=fixture("multides-jvc.txt")
        assertArrayEquals(golden,JvcPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.JVC",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun jviMatchesLinuxAndDispatch() {
        val input=fixture("multides-jvi.jvi")
        val golden=fixture("multides-jvi.txt")
        assertArrayEquals(golden,JviPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.JVI",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun v2iMatchesLinuxAndDispatch() {
        val input=fixture("multides-v2i.v2i")
        val golden=fixture("multides-v2i.txt")
        assertArrayEquals(golden,V2iPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.V2I",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sksrv2epngMatchesLinuxAndDispatch() {
        val input=fixture("sksrv-sksrv-png.sksrv.png")
        val golden=fixture("sksrv-sksrv-png.txt")
        assertArrayEquals(golden,SksrvPngPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.SKSRV.PNG",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun xscksMatchesLinuxAndDispatch() {
        val input=fixture("xscks-aescbc.xscks")
        val golden=fixture("xscks-aescbc.txt")
        assertArrayEquals(golden,XscksPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.XSCKS",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun mrcMatchesLinuxAndDispatch() {
        val input=fixture("batch5-mrc.mrc")
        val golden=fixture("batch5-mrc.txt")
        assertArrayEquals(golden,MrcPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.MRC",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun mtlMatchesLinuxAndDispatch() {
        val input=fixture("batch5-mtl.mtl")
        val golden=fixture("batch5-mtl.txt")
        assertArrayEquals(golden,MtlPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.MTL",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun jezMatchesLinuxAndDispatch() {
        val input=fixture("batch5-jez.jez")
        val golden=fixture("batch5-jez.txt")
        assertArrayEquals(golden,JezPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.JEZ",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun hrtMatchesLinuxAndDispatch() {
        val input=fixture("batch5-hrt.hrt")
        val golden=fixture("batch5-hrt.txt")
        assertArrayEquals(golden,HrtPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.HRT",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun zivMatchesLinuxAndDispatch() {
        val input=fixture("batch6-ziv.ziv")
        val golden=fixture("batch6-ziv.txt")
        assertArrayEquals(golden,ZivPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.ZIV",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun eproMatchesLinuxAndDispatch() {
        val input=fixture("batch7-epro.epro")
        val golden=fixture("batch7-epro.txt")
        assertArrayEquals(golden,EproPort.decode(context,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.EPRO",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun npv2MatchesLinuxAndDispatch() {
        val input=fixture("batch7-npv2.npv2")
        val golden=fixture("batch7-npv2.txt")
        assertArrayEquals(golden,Npv2Port.decode(context,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(golden,AndroidOfflineDecoderRouter.decode(context,"CASE.NPV2",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun all15FailClosedOnMalformedAndOversizedFiles() {
        assertNull(AndroidOfflineDecoderRouter.decode(context,"a.missing",fixture("multides-agn.agn")))
        assertNull(AndroidOfflineDecoderRouter.decode(context,"a.jez",fixture("xscks-aescbc.xscks")))
        assertNull("agn empty",AgnPort.decode(byteArrayOf()))
        assertNull("agn malformed",AgnPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("agn oversized",AgnPort.decode(ByteArray(1024*1024+1)))
        assertNull("cly empty",ClyPort.decode(byteArrayOf()))
        assertNull("cly malformed",ClyPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("cly oversized",ClyPort.decode(ByteArray(1024*1024+1)))
        assertNull("fɴ empty",FnLegacyPort.decode(byteArrayOf()))
        assertNull("fɴ malformed",FnLegacyPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("fɴ oversized",FnLegacyPort.decode(ByteArray(1024*1024+1)))
        assertNull("jvc empty",JvcPort.decode(byteArrayOf()))
        assertNull("jvc malformed",JvcPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("jvc oversized",JvcPort.decode(ByteArray(1024*1024+1)))
        assertNull("jvi empty",JviPort.decode(byteArrayOf()))
        assertNull("jvi malformed",JviPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("jvi oversized",JviPort.decode(ByteArray(1024*1024+1)))
        assertNull("v2i empty",V2iPort.decode(byteArrayOf()))
        assertNull("v2i malformed",V2iPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("v2i oversized",V2iPort.decode(ByteArray(1024*1024+1)))
        assertNull("sksrv.png empty",SksrvPngPort.decode(byteArrayOf()))
        assertNull("sksrv.png malformed",SksrvPngPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("sksrv.png oversized",SksrvPngPort.decode(ByteArray(1024*1024+1)))
        assertNull("xscks empty",XscksPort.decode(byteArrayOf()))
        assertNull("xscks malformed",XscksPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("xscks oversized",XscksPort.decode(ByteArray(1024*1024+1)))
        assertNull("mrc empty",MrcPort.decode(byteArrayOf()))
        assertNull("mrc malformed",MrcPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("mrc oversized",MrcPort.decode(ByteArray(1024*1024+1)))
        assertNull("mtl empty",MtlPort.decode(byteArrayOf()))
        assertNull("mtl malformed",MtlPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("mtl oversized",MtlPort.decode(ByteArray(1024*1024+1)))
        assertNull("jez empty",JezPort.decode(byteArrayOf()))
        assertNull("jez malformed",JezPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("jez oversized",JezPort.decode(ByteArray(1024*1024+1)))
        assertNull("hrt empty",HrtPort.decode(byteArrayOf()))
        assertNull("hrt malformed",HrtPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("hrt oversized",HrtPort.decode(ByteArray(1024*1024+1)))
        assertNull("ziv empty",ZivPort.decode(byteArrayOf()))
        assertNull("ziv malformed",ZivPort.decode("NOT A PROFILE".toByteArray()))
        assertNull("ziv oversized",ZivPort.decode(ByteArray(1024*1024+1)))
        assertNull("epro empty",EproPort.decode(context,byteArrayOf()))
        assertNull("epro malformed",EproPort.decode(context,"NOT A PROFILE".toByteArray()))
        assertNull("epro oversized",EproPort.decode(context,ByteArray(1024*1024+1)))
        assertNull("npv2 empty",Npv2Port.decode(context,byteArrayOf()))
        assertNull("npv2 malformed",Npv2Port.decode(context,"NOT A PROFILE".toByteArray()))
        assertNull("npv2 oversized",Npv2Port.decode(context,ByteArray(1024*1024+1)))
    }
}

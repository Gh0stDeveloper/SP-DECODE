package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Original vendor-specific synthetic Linux golden comparisons in Android. */
@RunWith(AndroidJUnit4::class)
class FinalExtra4InstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private fun fixture(name:String):ByteArray=
        inst.context.assets.open("parity/$name").use{it.readBytes()}

    @Test fun htOriginalGoldenAndStrictRouting() {
        val input=fixture("httptweak-v1-ht.ht")
        val expected=fixture("httptweak-v1-ht.txt")
        assertArrayEquals(expected,HtPort.decode(inst.targetContext,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"test.HT",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun htbOriginalGoldenAndStrictRouting() {
        val input=fixture("httptweak-v2-htb.htb")
        val expected=fixture("httptweak-v2-htb.txt")
        assertArrayEquals(expected,HtbPort.decode(inst.targetContext,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"test.HTB",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun hatOriginalGoldenAndStrictRouting() {
        val input=fixture("batch4-hat.hat")
        val expected=fixture("batch4-hat.txt")
        assertArrayEquals(expected,HatPort.decode(inst.targetContext,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"test.HAT",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun ehilOriginalGoldenAndStrictRouting() {
        val input=fixture("ehil-aescbc-double.ehil")
        val expected=fixture("ehil-aescbc-double.txt")
        assertArrayEquals(expected,EhilPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"test.EHIL",input)?.toByteArray(Charsets.UTF_8))
    }
    @Test fun allFourFailClosed() {
        assertNull(AndroidOfflineDecoderRouter.decode(inst.targetContext,"foo.unknown",fixture("httptweak-v1-ht.ht")))
        assertNull("ht empty",HtPort.decode(inst.targetContext,byteArrayOf()))
        assertNull("ht invalid",HtPort.decode(inst.targetContext,"INVALID".toByteArray()))
        assertNull("ht oversized",HtPort.decode(inst.targetContext,ByteArray(1024*1024+1)))
        assertNull("htb empty",HtbPort.decode(inst.targetContext,byteArrayOf()))
        assertNull("htb invalid",HtbPort.decode(inst.targetContext,"INVALID".toByteArray()))
        assertNull("htb oversized",HtbPort.decode(inst.targetContext,ByteArray(1024*1024+1)))
        assertNull("hat empty",HatPort.decode(inst.targetContext,byteArrayOf()))
        assertNull("hat invalid",HatPort.decode(inst.targetContext,"INVALID".toByteArray()))
        assertNull("hat oversized",HatPort.decode(inst.targetContext,ByteArray(1024*1024+1)))
        assertNull("ehil empty",EhilPort.decode(byteArrayOf()))
        assertNull("ehil invalid",EhilPort.decode("INVALID".toByteArray()))
        assertNull("ehil oversized",EhilPort.decode(ByteArray(1024*1024+1)))
    }
}

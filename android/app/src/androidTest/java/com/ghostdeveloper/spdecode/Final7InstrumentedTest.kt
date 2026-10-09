package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** A.2.4: strictly original last seven suffixes; never substitute formats.
 * Every test compares complete UTF-8 output with frozen synthetic Linux text.
 */
@RunWith(AndroidJUnit4::class)
class Final7InstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private val app get() = inst.targetContext
    private fun source(name:String):ByteArray =
        inst.context.assets.open("parity/$name").use { it.readBytes() }

    @Test fun darkExactGoldenAndRouting() {
        val input=source("dark-aescfb-msgpack.dark")
        val expected=source("dark-aescfb-msgpack.txt")
        assertArrayEquals(expected,DarkPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.DARK",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun ehiExactGoldenAndRouting() {
        val input=source("batch7-ehi.ehi")
        val expected=source("batch7-ehi.txt")
        assertArrayEquals(expected,EhiPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.EHI",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun npv4ExactGoldenAndRouting() {
        val input=source("batch7-npv4.npv4")
        val expected=source("batch7-npv4.txt")
        assertArrayEquals(expected,Npv4Port.decode(app,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.NPV4",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun npvtExactGoldenAndRouting() {
        val input=source("batch7-npvt.npvt")
        val expected=source("batch7-npvt.txt")
        assertArrayEquals(expected,NpvtPort.decode(app,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.NPVT",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sipExactGoldenAndRouting() {
        val input=source("batch6-sip.sip")
        val expected=source("batch6-sip.txt")
        assertArrayEquals(expected,SipPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.SIP",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun sscExactGoldenAndRouting() {
        val input=source("ssc-chacha20.ssc")
        val expected=source("ssc-chacha20.txt")
        assertArrayEquals(expected,SscPort.decode(input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.SSC",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun hcExactGoldenAndRouting() {
        val input=source("httpcustom-chacha-rst.hc")
        val expected=source("httpcustom-chacha-rst.txt")
        assertArrayEquals(expected,HcPort.decode(app,input)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            app,"case.HC",input)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun strictFailuresAreNeverMisclassified() {
        assertNull(AndroidOfflineDecoderRouter.decode(app,"unknown.zzz",source("batch7-ehi.ehi")))
        assertNull(AndroidOfflineDecoderRouter.decode(app,"wrong.ssc",source("batch6-sip.sip")))
        assertNull("dark empty",DarkPort.decode(byteArrayOf()))
        assertNull("dark malformed",DarkPort.decode("INVALID CONFIG".toByteArray()))
        assertNull("dark too large",DarkPort.decode(ByteArray(1024*1024+1)))
        assertNull("ehi empty",EhiPort.decode(byteArrayOf()))
        assertNull("ehi malformed",EhiPort.decode("INVALID CONFIG".toByteArray()))
        assertNull("ehi too large",EhiPort.decode(ByteArray(1024*1024+1)))
        assertNull("npv4 empty",Npv4Port.decode(app,byteArrayOf()))
        assertNull("npv4 malformed",Npv4Port.decode(app,"INVALID CONFIG".toByteArray()))
        assertNull("npv4 too large",Npv4Port.decode(app,ByteArray(1024*1024+1)))
        assertNull("npvt empty",NpvtPort.decode(app,byteArrayOf()))
        assertNull("npvt malformed",NpvtPort.decode(app,"INVALID CONFIG".toByteArray()))
        assertNull("npvt too large",NpvtPort.decode(app,ByteArray(1024*1024+1)))
        assertNull("sip empty",SipPort.decode(byteArrayOf()))
        assertNull("sip malformed",SipPort.decode("INVALID CONFIG".toByteArray()))
        assertNull("sip too large",SipPort.decode(ByteArray(1024*1024+1)))
        assertNull("ssc empty",SscPort.decode(byteArrayOf()))
        assertNull("ssc malformed",SscPort.decode("INVALID CONFIG".toByteArray()))
        assertNull("ssc too large",SscPort.decode(ByteArray(1024*1024+1)))
        assertNull("hc empty",HcPort.decode(app,byteArrayOf()))
        assertNull("hc malformed",HcPort.decode(app,"INVALID CONFIG".toByteArray()))
        assertNull("hc too large",HcPort.decode(app,ByteArray(1024*1024+1)))
    }
}

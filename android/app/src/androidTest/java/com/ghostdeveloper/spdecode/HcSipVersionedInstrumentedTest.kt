package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Signed-APK source compatibility (synthetic only). The same .hc/.sip suffix
 * must select old or new engines by container, not by filename or user guess.
 */
@RunWith(AndroidJUnit4::class)
class HcSipVersionedInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private val app get()=inst.targetContext
    private fun sample(filename:String):ByteArray=
        inst.context.assets.open("parity/$filename").use{it.readBytes()}
    private fun decode(file:String):String?=
        AndroidOfflineDecoderRouter.decode(app,file,sample("variant-$file"))

    @Test fun hcHccfgV1ReturnsFullProfileAndProtections(){
        val data=decode("hc-hccfg.hc")?:error("HCCFG v1 failed")
        val root=JSONObject(data)
        assertEquals("7.11.8 (864)",root.getString("app_version"))
        val conf=root.getJSONArray("config").getJSONObject(0)
        assertEquals("example.org",conf.getString("host"))
        assertEquals("dummy",conf.getString("password"))
        assertEquals("example.org",conf.getString("sni"))
        assertEquals("free",root.getJSONObject("protections").getString("accessMode"))
    }

    @Test fun hcHccfgN7HasSeparateAuthenticatedSchedule(){
        val data=decode("hc-hccfg-n7.hc")?:error("HCCFG n7 failed")
        assertEquals(443,JSONObject(data).getJSONArray("config")
            .getJSONObject(0).getInt("port"))
    }

    @Test fun originalHcAndSipStillDecode(){
        assertNotNull(decode("hc-legacy.hc"))
        assertEquals("example.org",JSONObject(decode("sip-legacy.sip")!!)
            .getString("server"))
    }

    @Test fun sipVer8AuthenticatesAndReadsJavaObject(){
        val root=JSONObject(decode("sip-ver8.sip")?:error("VER8 decode failed"))
        assertEquals("example.org",root.getString("server"))
    }

    @Test fun tamperedAeadTagsNeverBecomeSuccess(){
        assertNull(decode("sip-ver8-bad-tag.sip"))
        assertNull(decode("hc-hccfg-bad-tag.hc"))
    }
}

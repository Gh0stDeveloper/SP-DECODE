package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.LinkLayerPort
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Python-exported authorized synthetic LinkLayer 3.11.2 VER6 parity.
 * Original real .lnk was tested only in Python; no third-party data in CI.
 */
@RunWith(AndroidJUnit4::class)
class LinkLayerVer6InstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private fun asset(name:String):ByteArray=inst.context.assets.open("parity/$name").use{it.readBytes()}
    private fun route(name:String,input:ByteArray):String?=
        AndroidOfflineDecoderRouter.decode(inst.targetContext,name,input)

    private fun flatten(source:JSONObject,prefix:String="",out:MutableMap<String,String> = mutableMapOf()):Map<String,String>{
        for(field in source.keys()) {
            val value=source.get(field)
            val path=if(prefix.isEmpty())field else "$prefix.$field"
            if(value is JSONObject) flatten(value,path,out)
            else out[path]=value.toString()
        }
        return out
    }

    @Test fun syntheticVer6Full60FieldParityAgainstPython() {
        for(filename in listOf("linklayer-ver6.lnk","linklayer-ver6-reordered.lnk")){
            val bytes=asset(filename)
            val expected=JSONObject(String(asset(filename.removeSuffix(".lnk")+".json")))
            // Distinguish cipher-layer incompatibility from Go gob parser drift.
            val payload=try { LinkLayerPort.decryptGob(bytes) }
                catch(e:Exception){throw AssertionError("LinkLayer crypt stage: ${e.message}",e)}
            try { LinkLayerPort.decodeGob(payload) }
                catch(e:Exception){throw AssertionError("LinkLayer gob stage: ${e.message} (size=${payload.size})",e)}
            val actual=JSONObject(route(filename,bytes) ?: error("Kotlin failed: $filename"))
            assertEquals(60,flatten(actual).size)
            assertEquals(flatten(expected),flatten(actual))
            assertEquals("synthetic-user",actual.getString("Username"))
            assertEquals("synthetic-password",actual.getString("Password"))
            assertEquals("Prueba 日本語 🇲🇽\nSecond line",actual.getString("MessageConfig"))
            assertEquals(-1L,actual.getLong("ExpireTimeConfig"))
            assertEquals("example.invalid:22",actual.getJSONObject("SSH").getString("SSHServer"))
            assertEquals(false,actual.getBoolean("BlockSniffer"))
        }
    }

    @Test fun corruptTruncatedUnknownAreNeverReportedAsSuccess(){
        assertNull(route("invalid.lnk",asset("linklayer-ver6-truncated.lnk")))
        assertNull(route("invalid.lnk",asset("linklayer-ver6-unknown.lnk")))
        assertNull(LinkLayerPort.decode(ByteArray(0)))
        assertNull(LinkLayerPort.decode(ByteArray(355)))
        assertNull(route("notalink.txt",asset("linklayer-ver6.lnk")))
    }

    @Test fun noCrossFormatFallbackAndOversizeRejected(){
        val good=asset("linklayer-ver6.lnk")
        assertNull(route("wrong.sip",good))
        assertNull(route("wrong.hc",good))
        assertNull(LinkLayerPort.decode(ByteArray(LinkLayerPort.MAX_INPUT+1)))
    }
}

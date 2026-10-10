package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Authenticated end-to-end parity with Python-produced, signed synthetic NPVS v5. */
@RunWith(AndroidJUnit4::class)
class NpvsSignedFixtureInstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private fun asset(name:String)=inst.context.assets.open("parity/$name").use{it.readBytes()}
    private fun decode(data:ByteArray)=AndroidOfflineDecoderRouter.decode(
        inst.targetContext,"fixture.npvs",data)

    @Test fun signedPythonReferenceDecryptsWithIdenticalFields() {
        val profile=asset("npvs-v5-appkey.npvs")
        val golden=JSONObject(String(asset("npvs-v5-appkey.json"),Charsets.UTF_8))
        val result=JSONObject(decode(profile) ?: error("Native NPVS v5 returned null"))
        assertEquals(golden.getJSONObject("metadata").getString("issuedAt"),
            result.getJSONObject("metadata").getString("issuedAt"))
        assertEquals(golden.getJSONObject("metadata").getJSONObject("policy").getInt("configVersion"),
            result.getJSONObject("metadata").getJSONObject("policy").getInt("configVersion"))
        val expected=golden.getJSONObject("document").getJSONArray("configs").getJSONObject(0)
        val actual=result.getJSONObject("document").getJSONArray("configs").getJSONObject(0)
        assertEquals(expected.getString("server"),actual.getString("server"))
        assertEquals(expected.getInt("port"),actual.getInt("port"))
        assertEquals(golden.getJSONObject("document").toString(),
            result.getJSONObject("document").toString())
    }
    @Test fun tamperedSignatureAndCiphertextAreRejected() {
        val bytes=asset("npvs-v5-appkey.npvs")
        for(index in listOf(bytes.size-1,bytes.size-65,12)){
            val changed=bytes.clone()
            changed[index]=(changed[index].toInt() xor 1).toByte()
            assertNull("Mutation at $index must be rejected",decode(changed))
        }
    }
}

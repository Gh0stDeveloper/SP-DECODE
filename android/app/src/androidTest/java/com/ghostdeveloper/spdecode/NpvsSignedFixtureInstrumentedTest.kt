package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.NpvsEmbeddedFields
import org.json.JSONArray
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
    private fun asPlain(value:Any?):Any? = when(value) {
        is JSONObject -> value.keys().asSequence().toList().sorted()
            .associateWith { asPlain(value.get(it)) }
        is JSONArray -> (0 until value.length()).map { asPlain(value.get(it)) }
        null,JSONObject.NULL -> null
        else -> value
    }

    @Test fun signedPythonReferenceWithNestedBase64MatchesCompleteJson() {
        val encrypted=asset("npvs-v5-appkey-embedded.npvs")
        val golden=JSONObject(String(asset("npvs-v5-appkey-embedded.json"),Charsets.UTF_8))
        val decoded=decode(encrypted) ?: error("Native NPVS v5 nested fields rejected")
        val actual=JSONObject(decoded)
        assertEquals(asPlain(golden),asPlain(actual))
        assertFalse("Known npvs1 wrappers must not remain", decoded.contains("npvs1:"))
        val config=actual.getJSONObject("document").getJSONArray("configs")
            .getJSONObject(0).getJSONObject("sshConfig")
        assertEquals("cybertunnel-fidelson015",config.getString("sshUsername"))
        assertEquals("1234",config.getString("sshPassword"))
        assertEquals("GET / HTTP/1.1\\nHost: fr1.wssht.site",config.getString("payload"))
        assertEquals("El Salvador",config.getJSONObject("extra").getString("region"))
        // Unmarked, Base64-shaped credentials remain literal (Python parity).
        assertEquals("dGVzdA==",config.getString("opaque"))
        val mutated=encrypted.clone()
        mutated[mutated.size-1]=(mutated.last().toInt() xor 1).toByte()
        assertNull("Altered signed profile must fail",decode(mutated))
    }

    @Test fun invalidOrNonUtf8MarkedValuesAreNotReturnedAsPartialJson() {
        for(value in listOf("npvs1:","npvs1:!", "npvs1:/w==","npvs1:///////")) {
            try {
                NpvsEmbeddedFields.unwrap(JSONObject().put("key",value))
                fail("Must reject malformed embedded field: $value")
            } catch (_: Exception) {
                // Authentication must never produce success with encoded remnants.
            }
        }
        val nested=JSONObject().put("opaque","dGVzdA==")
        val preserved=NpvsEmbeddedFields.unwrap(nested) as JSONObject
        assertEquals("dGVzdA==",preserved.getString("opaque"))
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

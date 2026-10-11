package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.LegacyBatch2Materials
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/** S.2 historical source-to-vault parity; never embed raw key literals here. */
@RunWith(AndroidJUnit4::class)
class PhaseS2LegacyMaterialsInstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private val ctx get() = inst.targetContext

    private fun verify(entries:JSONObject,name:String,actual:ByteArray) {
        val spec=entries.getJSONObject(name)
        assertEquals("Original length mismatch for $name",spec.getInt("bytes"),actual.size)
        val digest=MessageDigest.getInstance("SHA-256").digest(actual)
            .joinToString(""){(it.toInt()and 255).toString(16).padStart(2,'0')}
        assertEquals("Historical source parity mismatch for $name",spec.getString("sha256"),digest)
    }

    @Test fun sixLegacyDecoderPortsRecoverExactlyOriginalKeyMaterial() {
        val root=JSONObject(inst.context.assets.open("parity/s2-legacy-fixtures.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        assertEquals(1,root.getInt("schemaVersion"))
        val expected=root.getJSONObject("materials")
        val sip=LegacyBatch2Materials.sip(ctx)
        verify(expected,"sipAes",sip.aesKey)
        verify(expected,"sipVer8",sip.ver8Key)
        verify(expected,"sshBlowfish",LegacyBatch2Materials.ssh(ctx))
        verify(expected,"sksConfig",LegacyBatch2Materials.sks(ctx).toByteArray(Charsets.UTF_8))
        val cloudy=LegacyBatch2Materials.cloudy(ctx)
        verify(expected,"cloudyAes",cloudy.aesKey)
        verify(expected,"cloudyIv",cloudy.iv)
        verify(expected,"goldSeed",LegacyBatch2Materials.goldSeed(ctx))
        val tnl=LegacyBatch2Materials.tnl(ctx)
        verify(expected,"tnlPassword1",tnl.passwords[0].toByteArray(Charsets.UTF_8))
        verify(expected,"tnlPassword2",tnl.passwords[1].toByteArray(Charsets.UTF_8))
        verify(expected,"tnlOpl",tnl.oplSecret.toByteArray(Charsets.UTF_8))
        verify(expected,"tnlOt",tnl.otKey)
        assertEquals(11,expected.length())
        assertFalse(ctx.assets.list("")?.contains("embedded_kotlin_profiles.json")==true)
    }
}

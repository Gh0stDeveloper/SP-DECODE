package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.HcHccfgPort
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

    @Test fun lockedHccfgRequiresExplicitOneFileCredentialAndPreservesLegacy() {
        val locked=sample("variant-hc-hccfg-password.hc")
        assertTrue(HcHccfgPort.requiresExternalPassword(locked))
        assertFalse(HcHccfgPort.requiresExternalPassword(sample("variant-hc-hccfg.hc")))
        assertFalse(HcHccfgPort.requiresExternalPassword(sample("variant-hc-legacy.hc")))
        assertNull(AndroidOfflineDecoderRouter.decode(app,"locked.hc",locked))

        val vault=DevicePrivateCredentialVault(app)
        val input="Synthetic-S4-HCCFG-Test-Only".toByteArray(Charsets.UTF_8)
        val record=vault.provision("Synthetic locked HC",input)
        input.fill(0)
        try {
            val decoded=vault.use(record.id){secret ->
                AndroidOfflineDecoderRouter.decodeWithUserPassword(app,"locked.hc",locked,secret)
            }
            assertNotNull(decoded)
            assertEquals("example.org",JSONObject(decoded!!).getJSONArray("config")
                .getJSONObject(0).getString("host"))
            val wrong="wrong-password".toByteArray()
            try {
                assertNull(AndroidOfflineDecoderRouter.decodeWithUserPassword(app,
                    "locked.hc",locked,wrong))
            }finally{wrong.fill(0)}
            val fake="abc".toByteArray()
            try {
                assertNull(AndroidOfflineDecoderRouter.decodeWithUserPassword(app,
                    "wrong.ehi",locked,fake))
            }finally{fake.fill(0)}
        }finally{vault.delete(record.id)}
        assertNull(AndroidOfflineDecoderRouter.decode(app,"locked.hc",locked))
        assertNotNull(decode("hc-legacy.hc"))
    }

    @Test fun hcHwidLockRequiresExplicitUserInputAndPreservesFullProfile() {
        val input=sample("variant-hc-hccfg-hwid.hc")
        val requirements=HcHccfgPort.inspectRequirements(input)!!
        assertTrue(requirements.hwidRequired)
        assertFalse(requirements.passwordRequired)
        assertFalse(requirements.headerAuthenticated) // stream-v3 metadata is advisory
        assertFalse(HcHccfgPort.requiresExternalPassword(input))
        assertNull(AndroidOfflineDecoderRouter.decode(app,"locked.hc",input))
        val document=AndroidOfflineDecoderRouter.decodeWithCredentials(
            app,"locked.hc",input,null,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assertNotNull(document)
        val root=JSONObject(document!!)
        assertEquals("7.11.19 (885)",root.getString("app_version"))
        assertEquals(false,root.getJSONObject("requirements").getBoolean("password_required"))
        assertTrue(root.getJSONObject("requirements").getBoolean("hwid_required"))
        assertEquals("free",root.getJSONObject("protections").getString("accessMode"))
        assertTrue(root.has("main_config"))
        val profile=root.getJSONArray("config").getJSONObject(0)
        assertEquals("example.org",profile.getString("host"))
        assertEquals(3,profile.getInt("flags"))
        assertEquals("s0",profile.getString("label"))
        assertEquals("example.org",profile.getJSONObject("options").getString("sni"))
        assertEquals(1700000000000L,profile.getLong("updated_at_ms"))
        assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
            app,"locked.hc",input,null,"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
        assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
            app,"locked.hc",input,null,null))
        assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
            app,"wrong.ehi",input,null,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    }

    @Test fun hcDualLockRequiresBothCredentialsAndRejectsWrongValues() {
        val input=sample("variant-hc-hccfg-dual.hc")
        val requirements=HcHccfgPort.inspectRequirements(input)!!
        assertTrue(requirements.passwordRequired)
        assertTrue(requirements.hwidRequired)
        assertFalse(requirements.headerAuthenticated)
        assertNull(AndroidOfflineDecoderRouter.decode(app,"dual.hc",input))
        val right="Synthetic-S4-HCCFG-Test-Only".toByteArray(Charsets.UTF_8)
        val wrong="Synthetic-Wrong-Password".toByteArray(Charsets.UTF_8)
        try {
            assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
                app,"dual.hc",input,right,null))
            assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
                app,"dual.hc",input,null,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
                app,"dual.hc",input,wrong,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
            assertNull(AndroidOfflineDecoderRouter.decodeWithCredentials(
                app,"dual.hc",input,right,"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
            val result=AndroidOfflineDecoderRouter.decodeWithCredentials(
                app,"dual.hc",input,right,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            assertNotNull(result)
            val root=JSONObject(result!!)
            assertEquals(443,root.getJSONArray("config").getJSONObject(0).getInt("port"))
            assertTrue(root.getJSONObject("requirements").getBoolean("password_required"))
            assertTrue(root.getJSONObject("requirements").getBoolean("hwid_required"))
            assertTrue(root.has("main_config"))
        }finally{
            right.fill(0);wrong.fill(0)
        }
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

package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.TlsReferencePort
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Six independently encrypted reference profiles, including 8.5.0. */
@RunWith(AndroidJUnit4::class)
class Tls850AndDarkBase64InstrumentedTest {
    private val inst get()=InstrumentationRegistry.getInstrumentation()
    private val ctx get()=inst.targetContext
    private fun fixture(file:String)=inst.context.assets.open("parity/"+file).use{it.readBytes()}

    @Test fun allTls850KeysAndLegacyProfileMatchOriginalPython() {
        for(profile in 1..6) {
            val raw=fixture("tls850-profile-$profile.tls")
            val expected=fixture("tls850-profile-$profile.txt")
            val source=TlsReferencePort.decode(raw)
            assertNotNull("No TLS profile $profile",source)
            assertArrayEquals("TLS authenticated Python match $profile",
                expected,source!!.toByteArray(Charsets.UTF_8))
            assertArrayEquals("TLS file router profile $profile",expected,
                AndroidOfflineDecoderRouter.decode(ctx,"test.tls",raw)
                    ?.toByteArray(Charsets.UTF_8))
            val structured=JsonParser.parseString(
                ResultJsonDisplay.render(source,"tls")).asJsonObject
            assertEquals(profile,structured.getAsJsonObject("_tls")
                .get("key_profile").asInt)
            assertTrue(structured.getAsJsonObject("_tls")
                .get("authenticated").asBoolean)
            if(profile<6) assertFalse(structured.has("legacy_dns_mode"))
            else assertEquals(2,structured.get("legacy_dns_mode").asInt)
        }
    }

    @Test fun tlsTextUsesSameAuthenticatedEngineAndRejectsTamper() {
        val raw=fixture("tls850-profile-1.tls")
        val token=String(raw,Charsets.UTF_8)
        val input=TextProtocolDecoder.identify("tls://"+token)
        assertNotNull(input)
        assertNotNull(TextProtocolDecoder.decode(ctx,input!!))
        assertNotNull(TlsReferencePort.decode(raw))
        assertNull(TlsReferencePort.decode("tls://!!!!".toByteArray()))
        assertNull(TlsReferencePort.decode(ByteArray(10)))
        // Alphabetically valid altered token must fail authentication.
        val damaged=token.toCharArray()
        damaged[80]=if(damaged[80]=='A')'B' else 'A'
        assertNull(TlsReferencePort.decode(String(damaged).toByteArray()))
    }

    @Test fun bareDarkTunnelBase64DispatchedBeforeNetmod() {
        val raw=fixture("dark-aescfb-msgpack.dark")
        val token=String(raw,Charsets.UTF_8).trim().substringAfter("://")
        val exact=TextProtocolDecoder.decode(ctx,
            TextProtocolDecoder.identify("dtunnel://"+token)!!)
        assertNotNull(exact)
        val id=TextProtocolDecoder.identify(token)
        assertNotNull("Bare Base64 valid Dark envelope must be recognized",id)
        assertEquals("dark",id!!.protocol)
        val pasted=TextProtocolDecoder.decode(ctx,id)
        assertEquals(JsonParser.parseString(exact),JsonParser.parseString(pasted))
        for(scheme in listOf("darkb64","darkbase64")) {
            assertEquals("dark",TextProtocolDecoder.identify("$scheme://"+token)?.protocol)
            val value=TextProtocolDecoder.decode(ctx,
                TextProtocolDecoder.identify("$scheme://"+token)!!)
            assertEquals(JsonParser.parseString(exact),JsonParser.parseString(value))
        }
        assertEquals("dark",TextProtocolDecoder.identify(
            token.chunked(50).joinToString("\n"))?.protocol)
        assertNull(TextProtocolDecoder.identify(
            java.util.Base64.getEncoder().encodeToString(
                "{\"hello\":\"world\"}".toByteArray())))
    }
}

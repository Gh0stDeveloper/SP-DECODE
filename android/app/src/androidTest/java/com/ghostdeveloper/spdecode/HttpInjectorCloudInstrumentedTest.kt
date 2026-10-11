package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.Deflater
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

/**
 * Pure local synthetic HTTP Injector cloud vectors. Never calls the cloud
 * provider; the integration requires an explicit user-triggered network action.
 */
@RunWith(AndroidJUnit4::class)
class HttpInjectorCloudInstrumentedTest {
    private val port = HttpInjectorCloudPort
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun cloudReferencesAndEmojiVectorResolveToTheSameKey() {
        assertEquals("TEST1234",port.parseReference("TEST1234"))
        assertEquals("TEST1234",port.parseReference("https://ehi.link/TEST1234"))
        assertEquals("TEST1234",port.parseReference("ehi://ehi.link/TEST1234"))
        assertEquals("TEST1234",port.parseReference("💉😩😘😩😧😩😗😘🙌😠🙍😤😐🚀"))
    }

    @Test fun malformedReferencesAndEmojiSequencesAreRejectedWithoutNetworking() {
        val bad = listOf(
            "https://evil.example/TEST1234",
            "http://ehi.link/TEST1234",
            "https://ehi.link/TEST1234?token=x",
            "https://ehi.link:444/TEST1234",
            "https://ehi.link@evil.example/TEST1234",
            "https://ehi.link/A%2FB",
            "💉😩😘😩😧😩😗😘🙌😠🙍😤😐",
            "💉😩😘😩😧😩😗😘🙌😠🙍😤😐💩🚀",
            " ",
        )
        bad.forEach { input ->
            try {
                port.parseReference(input)
                fail("Expected invalid reference")
            } catch (expected: HttpInjectorCloudPort.CloudException) {
                assertEquals(HttpInjectorCloudPort.Reason.REFERENCE,expected.reason)
            }
        }
    }

    @Test fun fixedSignedRequestMatchesIndependentPythonReference() {
        val (body,headers) = port.signedRequest(
            "TEST1234",1700000000L,"00000000-0000-4000-8000-000000000000",
            "identity-synthetic")
        try {
            assertEquals("config_key=TEST1234",String(body,StandardCharsets.US_ASCII))
            assertEquals("03p7UQBNZXTELXW82PMwoNeyta0%3D",
                headers.getValue("x-signature"))
            assertEquals("244",headers.getValue("x-app-build"))
            assertEquals("android",headers.getValue("x-platform"))
        } finally { body.fill(0) }
    }

    @Test fun syntheticAuthenticatedResponseRejectsUnsupportedInnerEhiAndTampering() {
        val response = sampleResponse()
        try {
            // Valid API transport is authenticated, but a fake EHI payload
            // must never be reported as a successful decoded configuration.
            val failure = assertThrows(HttpInjectorCloudPort.CloudException::class.java) {
                port.decodeResponse(context,response)
            }
            assertEquals(HttpInjectorCloudPort.Reason.DECODER,failure.reason)
            val outer = JSONObject(String(response,Charsets.UTF_8))
            val raw = Base64.decode(outer.getString("data"),Base64.NO_WRAP)
            raw[22] = (raw[22].toInt() xor 1).toByte()
            outer.put("data", Base64.encodeToString(raw,Base64.NO_WRAP))
            assertEquals(HttpInjectorCloudPort.Reason.INTEGRITY,
                assertThrows(HttpInjectorCloudPort.CloudException::class.java) {
                    port.decodeResponse(context,outer.toString().toByteArray())
                }.reason)
        } finally { response.fill(0) }
    }

    @Test fun serverRejectionHasExplicitReason() {
        assertEquals(HttpInjectorCloudPort.Reason.SERVER,
            assertThrows(HttpInjectorCloudPort.CloudException::class.java) {
                port.decodeResponse(context,"{\"code\":401}".toByteArray())
            }.reason)
    }

    private fun sampleResponse(): ByteArray {
        val configData = Base64.encodeToString(ByteArray(32){1},Base64.NO_WRAP)
        val payload = JSONObject()
            .put("status","success")
            .put("config_data",configData)
            .put("achilles","synthetic").toString().toByteArray(Charsets.UTF_8)
        val deflater = Deflater()
        val compressed = try {
            deflater.setInput(payload)
            deflater.finish()
            val out=ByteArrayOutputStream()
            val block=ByteArray(1024)
            while(!deflater.finished()){
                val n=deflater.deflate(block)
                if(n<=0)error("Deflate stuck")
                out.write(block,0,n)
            }
            out.toByteArray()
        } finally { deflater.end();payload.fill(0) }
        val key="GialHt24BQOZ+pwUE2++82H/EtnTqFh4"
            .toByteArray(Charsets.UTF_8)
        val iv=ByteArray(16){it.toByte()}
        val cipher=Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        val encrypted=cipher.doFinal(compressed)
        val mac=Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key,"HmacSHA256"))
        val tag=mac.doFinal(encrypted)
        key.fill(0)
        val envelope=iv+tag+encrypted
        return JSONObject().put("code",200)
            .put("data",Base64.encodeToString(envelope,Base64.NO_WRAP))
            .toString().toByteArray(Charsets.UTF_8)
    }
}

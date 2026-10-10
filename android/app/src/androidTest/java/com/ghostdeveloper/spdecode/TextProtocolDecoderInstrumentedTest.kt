package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.JsonParser
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class TextProtocolDecoderInstrumentedTest {
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext
    private fun base64(data:ByteArray)=Base64.encodeToString(data,Base64.NO_WRAP)
    private fun encrypt(clear:ByteArray,key:ByteArray,mode:String,iv:ByteArray?=null):ByteArray {
        val cipher=Cipher.getInstance(mode)
        if(iv==null)cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"))
        else cipher.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        return cipher.doFinal(clear)
    }
    private fun zeroPad(text:String):ByteArray {
        val source=text.toByteArray()
        val out=ByteArray((source.size+15)/16*16)
        source.copyInto(out)
        return out
    }
    private fun result(link:String):String? {
        val input=TextProtocolDecoder.identify(link)?:return null
        return TextProtocolDecoder.decode(ctx,input)
    }

    @Test fun vmessBase64JsonRoundTripsNestedData() {
        val json="""{"v":"2","add":"example.invalid","nested":{"tls":true,"port":443}}"""
        val decoded=result("You can share vmess://"+base64(json.toByteArray()))
        val value=JsonParser.parseString(decoded).asJsonObject
        assertEquals("example.invalid",value.get("add").asString)
        assertTrue(value.getAsJsonObject("nested").get("tls").asBoolean)
    }

    @Test fun netmodAesEcbAndArmodShareBotSpecificKeys() {
        val net="""{"name":"demo","server":"example.invalid","nested":{"port":123}}"""
        val enc=base64(encrypt(net.toByteArray(),
            "_netsyna_netmod_".toByteArray(),"AES/ECB/PKCS5Padding"))
        val value=JsonParser.parseString(result("nm-vmess://"+enc)).asJsonObject
        assertEquals(123,value.getAsJsonObject("nested").get("port").asInt)
        val params="profile=%7B%22host%22%3A%22demo%22%7D&payload=GET%20%2F&port=8080"
        val ar=base64(encrypt(params.toByteArray(),
            Base64.decode("YXJ0dW5uZWw3ODc5Nzg5eA==",Base64.DEFAULT),
            "AES/ECB/PKCS5Padding"))
        val arm=JsonParser.parseString(result("ar-ssh://"+ar)).asJsonObject
        assertEquals("demo",arm.getAsJsonObject("profile").get("host").asString)
        assertEquals("GET /",arm.get("payload").asString)
    }

    @Test fun xrayPbAndHowdyReproduceBotCbcContainers() {
        val pb="""{"server":"example.invalid","items":[1,true]}"""
        val key="4p+ocx+hGTnbDdHOmzQCjVb9KTTSh+A3".toByteArray()
        val pbBytes=encrypt(zeroPad(pb),key,"AES/CBC/NoPadding",
            "android123456789".toByteArray())
        val encoded=result("pb-vless://"+base64(pbBytes))
        assertEquals("example.invalid",JsonParser.parseString(encoded)
            .asJsonObject.get("server").asString)
        val privateKey="poiuytrewqas+=~|".toByteArray()
        val iv="r4tgv3b2zcmdW6ZZ".toByteArray()
        val server=base64(encrypt(zeroPad("node.example"),privateKey,
            "AES/CBC/NoPadding",iv))
        val sni=base64(encrypt(zeroPad("sni.example"),privateKey,
            "AES/CBC/NoPadding",iv))
        val howdy="""{"username":"user","password":"secret","server":"$server","sni":"$sni","port":22,"type":"ssh"}"""
        val json=JsonParser.parseString(result("howdy://"+base64(howdy.toByteArray())))
            .asJsonObject
        assertEquals("node.example",json.get("server").asString)
        assertEquals("sni.example",json.get("sni").asString)
    }

    @Test fun zivpnV2boxAndLegacySshText() {
        val password=String(Base64.decode("dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ=",
            Base64.DEFAULT),Charsets.UTF_8)
        val key=MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
        val xml="""<map><entry key="host">demo.example</entry><entry key="password">example</entry></map>"""
        val token=base64(encrypt(xml.toByteArray(),key,"AES/CBC/PKCS5Padding",ByteArray(16)))
        assertEquals("demo.example",JsonParser.parseString(result("zivpn://"+token))
            .asJsonObject.get("host").asString)
        val url="vless://example.invalid?server=one&port=443&port=8443"
        val outer="v2box://?locked="+base64(url.toByteArray())
        val box=JsonParser.parseString(result(outer)).asJsonObject
        assertEquals("443, 8443",box.get("port").asString)
        val ssh=JsonParser.parseString(result("/decssh demo@66.1:67.1")).asJsonObject
        assertEquals("A",ssh.get("username").asString)
        assertEquals("B",ssh.get("password").asString)
    }

    @Test fun fullPasteAcceptsWrappedLinksWithoutSessions() {
        val ssc=TextProtocolDecoder.identify("ssc://aabb\n ccdd ee")
        assertNotNull(ssc)
        assertEquals("ssc://aabbccddee",ssc!!.content)
        assertNull(TextProtocolDecoder.decode(ctx,ssc))
        val dark=TextProtocolDecoder.identify("dtunnel://abcd+/\n==")
        assertEquals("dtunnel://abcd+/==",dark?.content)
        // A continuation alone never attaches to a previous pasted link.
        assertNull(TextProtocolDecoder.identify("ee ff"))
        // The app processes each complete paste; Telegram part labels are invalid.
        assertNull(TextProtocolDecoder.identify("parte 2/2"))
    }

    @Test fun negativeTamperedTextNeverReportsSuccess() {
        assertNull(TextProtocolDecoder.identify("regular chat with no scheme"))
        assertNull(result("vmess://not-valid-?"))
        assertNull(result("nm-vmess://AAAAAA"))
        assertNull(result("howdy://AAAA"))
        assertNull(result("v2box://?locked="))
        assertNull(TextProtocolDecoder.identify("x".repeat(TextProtocolDecoder.MAX_CHARS+1)))
    }

    @Test fun netmodSshTextUsesTextCipherAndPreservesNonJsonPayload() {
        // Unlike the .nm file decoder, the nm-ssh:// text scheme uses the
        // single bot-specific key, and the bot accepts non-JSON cleartext.
        for((clear,field) in listOf(
            "{\"username\":\"netmod-user\",\"server\":\"example.invalid\"}" to "username",
            "ssh-user:secret@example.invalid:22" to "decodedText"
        )) {
            val encrypted=base64(encrypt(clear.toByteArray(Charsets.UTF_8),
                "_netsyna_netmod_".toByteArray(Charsets.UTF_8),"AES/ECB/PKCS5Padding"))
            val decoded=JsonParser.parseString(result("nm-ssh://"+encrypted)).asJsonObject
            assertNotNull(decoded.get(field))
            assertEquals(if(field=="decodedText")clear else "netmod-user",
                decoded.get(field).asString)
        }
        assertNull(result("nm-ssh://AAAAAA"))
    }

    @Test fun armodSshTextMatchesBotQueryDecodingAndEmbeddedAccount() {
        val body="payload=GET%2520%252F&profile=%7B%22host%22%3A%22demo%22%7D" +
            "&ssh=user:pass@example.invalid:22&empty=&ignored"
        val encrypted=base64(encrypt(body.toByteArray(Charsets.UTF_8),
            Base64.decode("YXJ0dW5uZWw3ODc5Nzg5eA==",Base64.DEFAULT),
            "AES/ECB/PKCS5Padding"))
        val decoded=JsonParser.parseString(result("ar-ssh://"+encrypted)).asJsonObject
        assertEquals("GET /",decoded.get("payload").asString)
        assertEquals("demo",decoded.getAsJsonObject("profile").get("host").asString)
        assertEquals("user:pass@example.invalid:22",decoded.get("ssh").asString)
        assertFalse(decoded.has("empty"))
        assertFalse(decoded.has("ignored"))
    }

    @Test fun darkTunnelTextAndFileReuseIdenticalDecoderAcrossImports() {
        val original=InstrumentationRegistry.getInstrumentation().context.assets.open(
            "parity/dark-aescfb-msgpack.dark").use { it.readBytes() }
        val expected=TextProtocolDecoder.decode(ctx,
            TextProtocolDecoder.identify("dtunnel://"+
                String(original,Charsets.UTF_8).trim().substringAfter("://"))!!)
        assertNotNull("Original Dark Tunnel golden must decode through text",expected)
        val baseline=JsonParser.parseString(expected)
        val raw=String(original,Charsets.UTF_8).trim().substringAfter("://")
        for(scheme in listOf("dark","dtunnel","dt")) {
            val resultText=result("$scheme://"+raw.chunked(47).joinToString("\n"))
            assertEquals("Dark text $scheme must match first import",
                baseline,JsonParser.parseString(resultText))
        }
        // Must never keep an old file's key, IV or decoded data between imports.
        val second=result("dark://"+raw)
        assertEquals(baseline,JsonParser.parseString(second))
        assertNull(result("dark://invalid-data"))
    }
}

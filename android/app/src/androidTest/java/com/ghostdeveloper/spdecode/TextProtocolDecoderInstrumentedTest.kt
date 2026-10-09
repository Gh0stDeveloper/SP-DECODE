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

    @Test fun darkAndSscFragmentSessionDoesNotFabricateAResult() {
        val first=TextMultipartAssembler.next(null,"ssc://aabb",1000)
        assertNotNull(first)
        assertEquals(1,first!!.parts)
        assertNull(TextProtocolDecoder.decode(ctx,first.input))
        val second=TextMultipartAssembler.next(first," ccddee ",2000)
        assertEquals(2,second!!.parts)
        assertEquals("ssc://aabbccddee",second.input.content)
        assertNull(TextMultipartAssembler.next(second,"chat message",3000))
        assertNull(TextMultipartAssembler.next(second,"ff",602001))
        val dark=TextMultipartAssembler.next(null,"dtunnel://abcd+/==",1000)
        assertNotNull(dark)
        assertEquals(2,TextMultipartAssembler.next(dark,"efgh",1200)?.parts)
    }

    @Test fun negativeTamperedTextNeverReportsSuccess() {
        assertNull(TextProtocolDecoder.identify("regular chat with no scheme"))
        assertNull(result("vmess://not-valid-?"))
        assertNull(result("nm-vmess://AAAAAA"))
        assertNull(result("howdy://AAAA"))
        assertNull(result("v2box://?locked="))
        assertNull(TextProtocolDecoder.identify("x".repeat(TextProtocolDecoder.MAX_CHARS+1)))
    }
}

package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.util.zip.GZIPInputStream

/** Phase E cryptographic primitives. No network, plaintext/key logging or guessed passwords. */
internal object SpecialCrypto {
    const val MAX = 2 * 1024 * 1024
    val gson = GsonBuilder().disableHtmlEscaping().serializeNulls().setPrettyPrinting().create()
    fun hex(s:String):ByteArray {
        require(s.length%2==0 && s.matches(Regex("[0-9a-fA-F]*")))
        return ByteArray(s.length/2){s.substring(it*2,it*2+2).toInt(16).toByte()}
    }
    fun b64(raw:String):ByteArray = Base64.decode(raw,Base64.DEFAULT)
    fun b64Strict(raw:String):ByteArray {
        require(raw.isNotEmpty() && raw.matches(Regex("[a-zA-Z0-9+/]*={0,2}")) &&
            raw.length%4 != 1)
        return Base64.decode(raw,Base64.DEFAULT)
    }
    fun utf8(b:ByteArray):String = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(b)).toString()
    fun sha(b:ByteArray):ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    fun hmac(k:ByteArray,b:ByteArray):ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(k,"HmacSHA256"));doFinal(b)
    }
    fun pbkdf(p:ByteArray,s:ByteArray,n:Int,len:Int):ByteArray =
        GenericVpnPort.pbkdf2Sha256(p,s,n,len)
    fun gcm(key:ByteArray,nonce:ByteArray,cipherAndTag:ByteArray):ByteArray {
        require(nonce.size==12 && cipherAndTag.size>=16)
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,nonce))
        return cipher.doFinal(cipherAndTag)
    }
    /** ITV Python decrypts AES-GCM ciphertext without verifying a tag; reproduce
     * the same counter keystream for its 12-byte nonce WITHOUT claiming integrity. */
    fun gcmUnauthenticatedStream(key:ByteArray,nonce:ByteArray,data:ByteArray):ByteArray {
        require(key.size==32 && nonce.size==12)
        val initial=nonce+byteArrayOf(0,0,0,2)
        val cipher=Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(initial))
        return cipher.doFinal(data)
    }
    fun cbc(key:ByteArray,iv:ByteArray,enc:ByteArray,unpad:Boolean=true):ByteArray {
        require(iv.size==16 && enc.isNotEmpty() && enc.size%16==0)
        val cipher=Cipher.getInstance(if(unpad) "AES/CBC/PKCS5Padding" else "AES/CBC/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        return cipher.doFinal(enc)
    }
    fun cfb(key:ByteArray,iv:ByteArray,enc:ByteArray):ByteArray {
        val cipher=Cipher.getInstance("AES/CFB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),IvParameterSpec(iv))
        return cipher.doFinal(enc)
    }
    fun chacha(key:ByteArray,nonce:ByteArray,tag:ByteArray,encrypted:ByteArray):ByteArray {
        require(key.size==32 && nonce.size==12 && tag.size==16)
        val cipher=ChaCha20Poly1305()
        cipher.init(false,AEADParameters(KeyParameter(key),128,nonce))
        val data=encrypted+tag
        val out=ByteArray(cipher.getOutputSize(data.size))
        val count=cipher.processBytes(data,0,data.size,out,0)
        val size=count+cipher.doFinal(out,count)
        return out.copyOf(size)
    }
    fun gzip(data:ByteArray):ByteArray=GZIPInputStream(ByteArrayInputStream(data)).use { input->
        val out=java.io.ByteArrayOutputStream()
        val buf=ByteArray(8192)
        while(true) { val n=input.read(buf);if(n<0)break
            require(out.size()+n<=MAX);out.write(buf,0,n) }
        out.toByteArray()
    }
    fun parse(raw:String):JsonElement? = try{JsonParser.parseString(raw)}catch(_:Exception){null}
    fun parseDocument(raw:String):JsonElement?=parse(raw)?.takeIf{it.isJsonObject||it.isJsonArray}
    fun render(raw:String):String {
        val doc=parse(raw)
        return if(doc==null)raw else gson.toJson(doc)
    }
    fun check(data:ByteArray):Boolean=data.isNotEmpty()&&data.size<=MAX
}

package com.ghostdeveloper.spdecode.parity

import android.util.Base64
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure, bounded source-compatible primitives for Phase F.
 * No network lookups, remote services, privileged APIs or secret logging.
 * XXTEA is reversible obfuscation, not authenticated encryption.
 */
internal object IndependentCrypto {
    const val MAX = 2*1024*1024
    fun b64(s:String):ByteArray = Base64.decode(s,Base64.DEFAULT)
    fun hex(s:String):ByteArray = SpecialCrypto.hex(s)
    fun utf8(bytes:ByteArray):String = SpecialCrypto.utf8(bytes)
    fun pbkdfSha512(password:ByteArray,salt:ByteArray,iterations:Int,length:Int):ByteArray {
        require(iterations in 10000..500_000 && length in 1..64 && salt.size in 1..128)
        val mac=Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(password,"HmacSHA512"))
        val block=salt+byteArrayOf(0,0,0,1)
        var u=mac.doFinal(block)
        val result=u.clone()
        repeat(iterations-1){
            u=mac.doFinal(u)
            for(i in result.indices) result[i]=(result[i].toInt() xor u[i].toInt()).toByte()
        }
        u.fill(0)
        return result.copyOf(length).also{result.fill(0)}
    }
    fun xxteaDecrypt(data:ByteArray,rawKey:ByteArray,delta:Int):ByteArray?{
        if(data.size<8 || data.size>MAX) return null
        val wordCount=(data.size+3)/4
        if(wordCount<2) return null
        val v=IntArray(wordCount)
        for(i in data.indices)v[i/4]=v[i/4] or
            ((data[i].toInt() and 255) shl ((i%4)*8))
        val key=rawKey.copyOf(16)
        val k=IntArray(4)
        for(i in key.indices)k[i/4]=k[i/4] or ((key[i].toInt() and 255) shl ((i%4)*8))
        var sum=(6+52/wordCount)*delta
        fun mx(y:Int,z:Int,p:Int,e:Int):Int=
            ((((z ushr 5) xor (y shl 2))+((y ushr 3) xor (z shl 4))) xor
                ((sum xor y)+(k[(p and 3) xor e] xor z)))
        while(sum!=0){
            val e=(sum ushr 2) and 3
            var y=v[0]
            for(i in wordCount-1 downTo 1){
                val z=v[i-1];v[i]-=mx(y,z,i,e);y=v[i]
            }
            v[0]-=mx(y,v[wordCount-1],0,e)
            sum-=delta
        }
        val len=v.last().toLong() and 0xffffffffL
        val padded=wordCount.toLong()*4
        if(len !in (padded-7)..(padded-4))return null
        return ByteArray(len.toInt()){i-> (v[i/4] ushr ((i%4)*8)).toByte()}
    }

    /**
     * Original Python UTF-8 with errors=ignore: use decoder with IGNORE
     * rather than replacement characters, only where that family uses it.
     */
    fun utf8Ignore(data:ByteArray):String=Charsets.UTF_8.newDecoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.IGNORE)
        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.IGNORE)
        .decode(ByteBuffer.wrap(data)).toString()

    fun inflateCompressed(data:ByteArray,gzip:Boolean):ByteArray {
        require(data.size in 1..MAX)
        val input=if(gzip)java.util.zip.GZIPInputStream(ByteArrayInputStream(data))
            else InflaterInputStream(ByteArrayInputStream(data),Inflater())
        return input.use { source->
            val output=ByteArrayOutputStream()
            val buffer=ByteArray(8192)
            while(true){
                val count=source.read(buffer)
                if(count<0)break
                require(output.size()+count<=MAX)
                output.write(buffer,0,count)
            }
            output.toByteArray()
        }
    }
    fun gcmAad(key:ByteArray,nonce:ByteArray,ct:ByteArray,aad:ByteArray?):ByteArray {
        require(nonce.size==12&&ct.size>=16)
        val cipher=javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE,
            SecretKeySpec(key,"AES"),javax.crypto.spec.GCMParameterSpec(128,nonce))
        if(aad!=null)cipher.updateAAD(aad)
        return cipher.doFinal(ct)
    }
    fun stripScheme(raw:String):String = if("://" in raw)raw.substringAfterLast("://") else raw
    fun document(input:String):String?=SpecialCrypto.parseDocument(input)?.let{SpecialCrypto.gson.toJson(it)}
}

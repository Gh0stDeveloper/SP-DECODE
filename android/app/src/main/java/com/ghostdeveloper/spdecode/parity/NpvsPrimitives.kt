package com.ghostdeveloper.spdecode.parity

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** NPVS v5 SHA256, HKDF and authenticated ChaCha20-Poly1305, without fallbacks. */
internal object NpvsPrimitives {
    fun ascii(v:String)=v.toByteArray(Charsets.US_ASCII)
    fun join(vararg parts:ByteArray):ByteArray =
        ByteArray(parts.sumOf{it.size}).also{out->
            var offset=0
            for(part in parts){part.copyInto(out,offset);offset+=part.size}
        }
    fun read(a:ByteArray,from:Int,end:Int):ByteArray {
        require(from>=0 && end>=from && end<=a.size)
        return a.copyOfRange(from,end)
    }
    fun u16(a:ByteArray,i:Int):Int {
        require(i>=0 && i+2<=a.size)
        return ((a[i].toInt() and 255) shl 8) or (a[i+1].toInt() and 255)
    }
    fun u32(a:ByteArray,i:Int):Long {
        require(i>=0 && i+4<=a.size)
        return ((a[i].toLong() and 255) shl 24) or
            ((a[i+1].toLong() and 255) shl 16) or
            ((a[i+2].toLong() and 255) shl 8) or
            (a[i+3].toLong() and 255)
    }
    fun be16(i:Int)=byteArrayOf((i ushr 8).toByte(),i.toByte())
    fun be32(i:Int)=byteArrayOf((i ushr 24).toByte(),
        (i ushr 16).toByte(),(i ushr 8).toByte(),i.toByte())
    fun sha(a:ByteArray)=MessageDigest.getInstance("SHA-256").digest(a)
    fun hmac(key:ByteArray,msg:ByteArray):ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key,"HmacSHA256"))
            doFinal(msg)
        }
    fun hkdf(ikm:ByteArray,salt:ByteArray,context:ByteArray):ByteArray {
        val prk=hmac(if(salt.isEmpty()) ByteArray(32) else salt,ikm)
        return hmac(prk,join(context,byteArrayOf(1)))
    }
    fun fieldKey(dek:ByteArray,ctx:ByteArray,label:String,id:Int):ByteArray =
        hkdf(dek,ctx,join(ascii("NPV-fields-v1/"),ascii(label),ascii("/"),be16(id)))
    fun decrypt(key:ByteArray,nonce:ByteArray,payload:ByteArray,aad:ByteArray):ByteArray {
        require(key.size==32 && nonce.size==12 && payload.size>=16)
        val engine=ChaCha20Poly1305()
        engine.init(false,AEADParameters(KeyParameter(key),128,nonce,aad))
        val out=ByteArray(engine.getOutputSize(payload.size))
        val n=engine.processBytes(payload,0,payload.size,out,0)
        return out.copyOf(n+engine.doFinal(out,n))
    }
}

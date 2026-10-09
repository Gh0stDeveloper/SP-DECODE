package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * HTTP Injector .ehi original bypass IV route:
 * Java UTF-8 container -> AES-256-CBC -> AES-128-CBC -> XXTEA
 * -> original field-local custom Base64 XOR decoding.
 * Argon2id/ChaCha20-Poly1305 standard-IV profiles require a separate
 * approved Argon2 implementation and are explicitly not guessed.
 */
object EhiPort {
    private val p=LegacyPortPrimitives
    private val l1=p.hex("7e1210f7aab956f7a668bda6e57feddb7f84ad840aef8d27b1b969959be3ab6c")
    private val l2=p.hex("b2bc617c32d8b9eb1943a5ffa8051eea")
    private val eoo="null=V5kU5+FFrY\u0000".toByteArray(Charsets.UTF_8)
    private val ivs=listOf("221d572349555f1d112133236b1f4a3f",
        "5543494c53443e3f4a6a4539384e776a",
        "374c2541575e4d531a3c327b75431e5f").map{p.hex(it)}
    private const val NORMAL="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private const val CUSTOM="RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
    private fun unwrap(input:ByteArray):ByteArray {
        p.bounded(input)
        val bb=ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN)
        fun readUtf():String {
            require(bb.remaining()>=2)
            val n=bb.short.toInt()and 65535
            require(bb.remaining()>=n)
            return p.utf8(ByteArray(n).also{bb.get(it)})
        }
        readUtf();require(bb.remaining()>=8);bb.position(bb.position()+8)
        readUtf();require(bb.remaining()>=12);bb.position(bb.position()+8)
        val n=bb.int;require(n in 1..p.MAX_INPUT && bb.remaining()>=8+n)
        bb.position(bb.position()+8)
        return ByteArray(n).also{bb.get(it)}
    }
    private fun words(raw:ByteArray):IntArray=IntArray((raw.size+3)/4){i->
        var v=0;for(j in 0..3)if(i*4+j<raw.size)
            v=v or ((raw[i*4+j].toInt()and 255) shl (j*8))
        v
    }
    private fun xxtea(input:ByteArray):ByteArray {
        val v=words(input)
        require(v.size>=2)
        val k=words(eoo.copyOf(16))
        val n=v.size
        var sum=(6+52/n)*0x9e3779b9.toInt()
        while(sum!=0){
            val e=(sum ushr 2)and 3
            var y=v[0]
            for(i in n-1 downTo 1){
                val z=v[i-1]
                val mx=(((z ushr 5) xor (y shl 2))+
                    ((y ushr 3) xor (z shl 4))) xor
                    ((sum xor y)+(k[(i and 3) xor e] xor z))
                y=v[i]-mx
                v[i]=y
            }
            val z=v[n-1]
            val mx=(((z ushr 5) xor (y shl 2))+
                ((y ushr 3) xor (z shl 4))) xor
                ((sum xor y)+(k[e] xor z))
            v[0]-=mx
            sum-=0x9e3779b9.toInt()
        }
        val bytes=ByteArray(n*4)
        v.forEachIndexed { i,num->for(j in 0..3)bytes[i*4+j]=(num ushr(8*j)).toByte()}
        val count=v[n-1].toLong() and 0xffffffffL
        return if(count>0 && count<=bytes.size)bytes.copyOf(count.toInt())
            else bytes.dropLastWhile{it==0.toByte()}.toByteArray()
    }
    private fun field(value:String,key:String):String? {
        if(value.isBlank())return value
        return try {
            val clean=value.reversed().replace("?","").map{ch->
                val n=CUSTOM.indexOf(ch)
                if(n>=0)NORMAL[n]else ch
            }.joinToString("")
            var hex=p.utf8(p.b64(clean))
            if(hex.length%2!=0)hex="0"+hex
            val raw=p.hex(hex);require(key.isNotEmpty())
            val decoded=ByteArray(raw.size) {i->
                (raw[i].toInt() xor key[i%key.length].code).toByte()
            }.filter{it!=0.toByte()}.toByteArray()
            p.utf8(decoded)
        }catch(_:Exception){null}
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        val payload=unwrap(input)
        var config:JSONObject?=null
        for(iv in ivs) {
            val first=try{p.utf8(p.cbc(payload,l1,iv))}catch(_:Exception){continue}
            val parts=first.split(':')
            if(parts.size<3)continue
            val raw=try{
                p.cbc(p.b64(parts[2]),l2,p.b64(parts[0]))
            }catch(_:Exception){continue}
            val clear=xxtea(raw)
            val begin=clear.indexOf('{'.code.toByte())
            if(begin<0)continue
            config=try{JSONObject(p.utf8(clear.copyOfRange(begin,clear.size)))}catch(_:Exception){null}
            if(config!=null)break
        }
        val profile=config?:error("EHI bypass variant did not authenticate")
        val salt=profile.optString("configSalt","EVZJNI")
        val filtered=JSONObject()
        for(key in p.keys(profile)){
            val v=profile.get(key)
            if(v is String&&v.isNotBlank()){
                val decoded=if(key=="configMessage")v else field(v,salt)
                if(decoded!=null)filtered.put(key,decoded)
                else if(key=="overwriteServerData")filtered.put(key,v)
            }else filtered.put(key,v)
        }
        FinalJsonSurface.render(".ehi",FinalJsonSurface.body(filtered),
            trailingNewline=true)
    }
}

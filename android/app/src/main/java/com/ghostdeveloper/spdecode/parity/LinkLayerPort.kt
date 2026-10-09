package com.ghostdeveloper.spdecode.parity

import org.bouncycastle.crypto.BlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.BlowfishEngine
import org.bouncycastle.crypto.engines.CAST5Engine
import org.bouncycastle.crypto.engines.Salsa20Engine
import org.bouncycastle.crypto.modes.CFBBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Offline parity of decoders/Python/linklayer.py (LinkLayer VPN 3.11.2 VER6).
 *
 * Uses the supplied real-file-validated Python state machine, including
 * Blowfish-CFB, AES-CFB, Salsa20, CAST5-CFB, PBKDF2-HMAC-SHA1 and Go gob.
 * CFB segments are the full cipher block, as in the Go implementation.
 * This format has no MAC; strict NativeConfig schema parsing is not an
 * authenticity guarantee. No network, JNI, root or unsafe object loading.
 */
object LinkLayerPort {
    const val MAX_INPUT = 8 * 1024 * 1024
    private const val MAX_STRING = 1024 * 1024
    private val iv = hex("a7734f9c12ac1b01a415f2c1fc78e66b")
    private val salt = "sH3CIVoF#rWLtJo6".toByteArray(Charsets.US_ASCII)

    private fun hex(s:String):ByteArray = ByteArray(s.length/2) { i ->
        s.substring(i*2,i*2+2).toInt(16).toByte()
    }
    private fun check(value:Boolean, message:String="Invalid LinkLayer VER6 configuration") {
        if(!value)throw IllegalArgumentException(message)
    }
    private fun slice(a:ByteArray,start:Int,end:Int):ByteArray {
        check(start>=0 && end>=start && end<=a.size,"Truncated LinkLayer VER6 container")
        return a.copyOfRange(start,end)
    }
    private fun join(a:ByteArray,b:ByteArray):ByteArray =
        ByteArray(a.size+b.size).also {
            a.copyInto(it,0)
            b.copyInto(it,a.size)
        }
    private fun cfb(engine:BlockCipher,key:ByteArray,data:ByteArray):ByteArray {
        val cipher=CFBBlockCipher(engine,engine.blockSize*8)
        cipher.init(false,ParametersWithIV(KeyParameter(key),iv.copyOf(engine.blockSize)))
        return ByteArray(data.size).also {
            cipher.processBytes(data,0,data.size,it,0)
        }
    }
    /** PBKDF2(password=RAW Go bytes, salt, 1500, dkLen=32, HMAC-SHA1).
     * PBEKeySpec is NOT used because it transforms byte passwords to chars.
     */
    private fun pbkdf2(password:ByteArray):ByteArray {
        check(password.size==16)
        val hmac=Mac.getInstance("HmacSHA1")
        hmac.init(SecretKeySpec(password,"HmacSHA1"))
        val result=ByteArray(32)
        var offset=0
        for(blockIndex in 1..2) {
            val counter=byteArrayOf(0,0,0,blockIndex.toByte())
            var u=hmac.doFinal(join(salt,counter))
            val xor=u.clone()
            repeat(1499) {
                u=hmac.doFinal(u)
                for(i in xor.indices)xor[i]=(xor[i].toInt() xor u[i].toInt()).toByte()
            }
            val count=minOf(xor.size,result.size-offset)
            xor.copyInto(result,offset,0,count)
            offset+=count
        }
        return result
    }

    internal fun decryptGob(input:ByteArray):ByteArray {
        check(input.size in 355..MAX_INPUT)
        check(input.copyOfRange(0,4).contentEquals("VER6".toByteArray(Charsets.US_ASCII)),
            "Unsupported LinkLayer header or version")
        val blowfishKey=slice(input,input.size-8,input.size)
        val outer=cfb(BlowfishEngine(),blowfishKey,slice(input,4,input.size-8))
        check(outer.size>=72)
        val material=slice(outer,outer.size-72,outer.size)
        val aesKey=join(slice(material,0,16),slice(material,material.size-16,material.size).reversedArray())
        val salsa=cfb(AESEngine.newInstance(),aesKey,slice(outer,0,outer.size-72))
        check(salsa.size>=76,"Truncated Salsa20 container")
        val reversedPacket=slice(salsa,32,salsa.size-32).reversedArray()
        check(reversedPacket.size>=12,"Truncated Salsa20 packet")
        val stream=Salsa20Engine().apply {
            init(true,ParametersWithIV(KeyParameter(slice(salsa,0,32)),
                slice(reversedPacket,0,8)))
        }
        val packet=ByteArray(reversedPacket.size)
        reversedPacket.copyInto(packet,0,0,8)
        stream.processBytes(reversedPacket,8,reversedPacket.size-8,packet,8)
        val length=((packet[8].toLong() and 255L) shl 24) or
            ((packet[9].toLong() and 255L) shl 16) or
            ((packet[10].toLong() and 255L) shl 8) or
            (packet[11].toLong() and 255L)
        val blockLength=packet.size-12
        check(length>=75L && length<=blockLength.toLong()/3L &&
            length*3L==blockLength.toLong(),"Invalid CAST5 segment length")
        val n=length.toInt()
        val middle=slice(packet,12+n,12+2*n)
        val castKey=slice(middle,middle.size-16,middle.size)
        val decoded=cfb(CAST5Engine(),castKey,slice(middle,0,middle.size-16))
        check(decoded.isNotEmpty(),"Missing CAST5 ordering flag")
        val inner=when(decoded[0].toInt() and 255) {
            0 -> slice(decoded,1,decoded.size)
            1 -> {
                val stage=slice(decoded,1,decoded.size)
                val half=stage.size/2
                join(slice(stage,half,stage.size).reversedArray(),slice(stage,0,half))
            }
            else -> throw IllegalArgumentException("Invalid CAST5 ordering flag")
        }
        check(inner.size>=16+42,"Truncated LinkLayer inner record")
        val wrapped=slice(inner,16,inner.size)
        val mask=pbkdf2(slice(inner,0,16))
        for(i in 0 until minOf(mask.size,wrapped.size)) {
            wrapped[i]=(wrapped[i].toInt() xor mask[i].toInt()).toByte()
        }
        val key=slice(wrapped,wrapped.size-32,wrapped.size)
        val temp=key[0]
        key[0]=key[key.size-1]
        key[key.size-1]=temp
        val encrypted=join(slice(wrapped,wrapped.size-42,wrapped.size-32),
            slice(wrapped,0,wrapped.size-42).reversedArray())
        return cfb(AESEngine.newInstance(),key,encrypted)
    }

    // Exact, ordered NativeConfig schema from the Go structure recovered
    // for LinkLayer VPN 3.11.2. Go gob omits fields with zero values.
    private val schema:LinkedHashMap<String,Any> = linkedMapOf(
        "BlockAll" to 1,"BlockPayloadSNI" to 1,"BlockAuth" to 1,
        "BlockServer" to 1,"StartWithHWID" to 1,"BlockRoot" to 1,
        "BlockSniffer" to 1,"OnlyCarrier" to 6,"ExpireTimeConfig" to 2,
        "MessageConfig" to 6,"DeviceHWID" to 6,"Username" to 6,
        "Password" to 6,"TypeAccount" to 2,"TypeLayer" to 2,
        "SSL" to linkedMapOf<String,Any>("Single" to 1,"Sni" to 6,"Host" to 6),
        "HTTP" to linkedMapOf<String,Any>("Single" to 1,"Payload" to 6,"Host" to 6),
        "HTTPSSL" to linkedMapOf<String,Any>(
            "Single" to 1,"Host" to 6,"SNI" to 6,"Payload" to 6),
        "WS" to linkedMapOf<String,Any>(
            "EnableHTTP" to 1,"EnableTrue" to 1,"SNI" to 6,
            "Domain" to 6,"Host" to 6),
        "DNSTT" to linkedMapOf<String,Any>(
            "Domain" to 6,"Pubkey" to 6,"Timeout" to 6,"Udp" to 6),
        "UDPHysteria" to linkedMapOf<String,Any>(
            "Server" to 6,"UdpPortRange" to 6,"Obfs" to 6,
            "Up_mbps" to 2,"Down_mbps" to 2,"Insecure" to 1,
            "EnableInterval" to 1,"Interval" to 2),
        "HTTPDual" to linkedMapOf<String,Any>(
            "Host" to 6,"Domain" to 6,"SplitRequest" to 1,"SNI" to 6,
            "EnableSSLTLS" to 1,"Nchunks" to 2,"Nparalels" to 2,"Version" to 6),
        "SSH" to linkedMapOf<String,Any>(
            "SSHLayer" to 2,"SSHServer" to 6,"SSHPayload" to 6,
            "SSHProxy" to 6,"SSHSni" to 6,"SSHDNSPkey" to 6,
            "SSHDomain" to 6,"SSHDNSServer" to 6),
        "IndexHTTPort" to 2,"IndexSSLPort" to 2,
    )
    private data class Definition(val name:String,val fields:List<Pair<String,Int>>)
    private class Reader(private val data:ByteArray) {
        var position=0
            private set
        val remaining get()=data.size-position
        fun take(count:Int):ByteArray {
            check(count>=0 && count<=remaining,"Truncated Go gob data")
            val result=data.copyOfRange(position,position+count)
            position+=count
            return result
        }
        fun uint():Long {
            val first=take(1)[0].toInt() and 255
            if(first<128)return first.toLong()
            val width=256-first
            check(width in 1..8,"Invalid Go gob integer width")
            var out=0L
            repeat(width){out=(out shl 8) or ((take(1)[0].toLong()) and 255L)}
            return out
        }
        fun sint():Long {
            val u=uint()
            return if(u and 1L != 0L)(u ushr 1).inv() else u ushr 1
        }
        fun smallUInt(cap:Int):Int {
            val n=uint()
            check(n>=0 && n<=cap.toLong(),"Go gob numeric value exceeds limit")
            return n.toInt()
        }
        fun name():String {
            val n=smallUInt(MAX_STRING)
            val raw=take(n)
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw)).toString()
        }
        fun expect(n:Int) { check(uint()==n.toLong(),"Invalid Go gob type definition") }
        fun finish() { check(remaining==0,"Trailing Go gob message data") }
    }
    private fun definition(r:Reader,id:Int):Definition {
        check(r.uint()==3L,"Unsupported Go gob type")
        r.expect(1);r.expect(1)
        val name=r.name()
        r.expect(1);check(r.sint()==id.toLong(),"Go gob type id mismatch")
        r.expect(0);r.expect(1)
        val count=r.smallUInt(64)
        check(count in 1..64)
        val fields=ArrayList<Pair<String,Int>>(count)
        repeat(count) {
            r.expect(1)
            val field=r.name()
            r.expect(1)
            val type=r.sint()
            check(type in 1L..4096L,"Invalid Go gob field type")
            r.expect(0)
            fields.add(field to type.toInt())
        }
        r.expect(0);r.expect(0)
        check(fields.map{it.first}.toSet().size==fields.size,"Duplicate Go gob field")
        return Definition(name,fields)
    }
    private fun validate(types:Map<Int,Definition>,root:Int) {
        check(types[root]?.name=="NativeConfig","Missing NativeConfig Go gob root")
        val visited=HashSet<Int>()
        fun visit(id:Int,expected:Map<String,Any>,depth:Int) {
            check(depth<=8 && visited.add(id),"Invalid NativeConfig type graph")
            val fields=types[id]?.fields ?: error("Missing Go gob nested type")
            check(fields.map{it.first}==expected.keys.toList(),"Unsupported NativeConfig fields")
            for((name,typeId) in fields) {
                val wanted=expected[name]!!
                if(wanted is Map<*,*>) {
                    @Suppress("UNCHECKED_CAST")
                    visit(typeId,wanted as Map<String,Any>,depth+1)
                } else check(wanted==typeId,"Unsupported NativeConfig field type")
            }
        }
        visit(root,schema,0)
        check(visited==types.keys,"Unexpected Go gob type definitions")
    }
    private fun zero(id:Int,types:Map<Int,Definition>,depth:Int=0):Any {
        check(depth<=8)
        return when(id) {
            1->false
            2->0L
            6->""
            else -> JSONObject().also {obj->
                val fields=types[id]?.fields ?: error("Missing nested type")
                for((name,fieldId) in fields)obj.put(name,zero(fieldId,types,depth+1))
            }
        }
    }
    private fun value(r:Reader,types:Map<Int,Definition>,id:Int,depth:Int=0):Any {
        check(depth<=8)
        return when(id){
            1 -> {
                val v=r.uint()
                check(v==0L||v==1L,"Invalid Go gob boolean")
                v==1L
            }
            2 -> r.sint()
            6 -> r.name()
            else -> {
                val fields=types[id]?.fields ?: error("Missing Go gob struct")
                val obj=zero(id,types,depth) as JSONObject
                var index=-1
                while(true) {
                    val delta=r.smallUInt(256)
                    if(delta==0)break
                    index+=delta
                    check(index<fields.size,"Invalid Go gob field index")
                    val (field,fieldType)=fields[index]
                    obj.put(field,value(r,types,fieldType,depth+1))
                }
                obj
            }
        }
    }
    internal fun decodeGob(bytes:ByteArray):JSONObject {
        check(bytes.size in 1..MAX_INPUT,"Invalid Go gob payload length")
        val stream=Reader(bytes)
        val types=LinkedHashMap<Int,Definition>()
        var result:JSONObject?=null
        while(stream.remaining>0) {
            val length=stream.smallUInt(MAX_INPUT)
            val message=Reader(stream.take(length))
            val id=message.sint()
            if(id<0L) {
                val actual=-id
                check(actual>=65L && actual<=4096L && !types.containsKey(actual.toInt())
                    && types.size<16,"Invalid Go gob type id or count")
                types[actual.toInt()]=definition(message,actual.toInt())
            }else {
                check(id in 65L..4096L && result==null,"Unexpected Go gob value")
                validate(types,id.toInt())
                result=value(message,types,id.toInt()) as JSONObject
            }
            message.finish()
        }
        return result ?: throw IllegalArgumentException("Missing Go gob NativeConfig")
    }
    fun decode(input:ByteArray):String? {
        if(input.size !in 355..MAX_INPUT)return null
        return try {
            LegacyPortPrimitives.prettyJson(decodeGob(decryptGob(input)))+"\n"
        }catch(_:Exception){null}
    }
}

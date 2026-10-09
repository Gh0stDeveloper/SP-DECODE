package com.ghostdeveloper.spdecode.parity

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Data-only MessagePack subset sufficient for Dark Tunnel, with bounds.
 * Rejects extension types and unsupported tokens; never instantiates classes.
 */
internal class StrictMessagePack(raw:ByteArray) {
    private val b=ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
    private var nodes=0
    private fun take(n:Int):ByteArray {
        require(n>=0 && n<=1024*1024 && b.remaining()>=n)
        return ByteArray(n).also{b.get(it)}
    }
    private fun u8()=b.get().toInt()and 255
    private fun u16()=b.short.toInt()and 65535
    private fun u32():Int {val v=b.int;require(v>=0);return v}
    private fun string(n:Int)=String(take(n),Charsets.UTF_8)
    fun decode():Any?{
        val value=read(0);require(!b.hasRemaining());return value
    }
    private fun arr(n:Int,depth:Int):List<Any?> {
        require(n in 0..65536)
        return (0 until n).map{read(depth+1)}
    }
    private fun map(n:Int,depth:Int):LinkedHashMap<String,Any?>{
        require(n in 0..65536)
        val result=linkedMapOf<String,Any?>()
        repeat(n){
            val k=read(depth+1)
            require(k is String)
            result[k]=read(depth+1)
        }
        return result
    }
    private fun read(depth:Int):Any?{
        require(depth<=32 && ++nodes<=150000 && b.hasRemaining())
        val type=u8()
        if(type<0x80)return type
        if(type in 0x80..0x8f)return map(type and 15,depth)
        if(type in 0x90..0x9f)return arr(type and 15,depth)
        if(type in 0xa0..0xbf)return string(type and 31)
        if(type>=0xe0)return type-256
        return when(type){
            0xc0->null
            0xc2->false
            0xc3->true
            0xc4->take(u8())
            0xc5->take(u16())
            0xc6->take(u32())
            0xca->b.float
            0xcb->b.double
            0xcc->u8()
            0xcd->u16()
            0xce->(b.int.toLong()and 0xffffffffL)
            0xcf->b.long
            0xd0->b.get().toInt()
            0xd1->b.short.toInt()
            0xd2->b.int
            0xd3->b.long
            0xd9->string(u8())
            0xda->string(u16())
            0xdb->string(u32())
            0xdc->arr(u16(),depth)
            0xdd->arr(u32(),depth)
            0xde->map(u16(),depth)
            0xdf->map(u32(),depth)
            else->error("Unsupported MessagePack type")
        }
    }
}

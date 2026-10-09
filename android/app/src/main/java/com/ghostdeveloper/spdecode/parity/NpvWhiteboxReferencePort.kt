package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import org.json.JSONArray
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Port of NPVTUNNEL.py's exact two-round white-box stream transform.
 *
 * Immutable tables are exported at build time from the source's restricted
 * data-only pickle. No Python VM or Python pickle runs on-device.
 */
internal object NpvWhiteboxReferencePort {
    private val p=LegacyPortPrimitives
    private class Tables(context:Context) {
        val p2=ByteArray(96*256)
        val p3=IntArray(16*256)
        val p5=IntArray(16*256)
        val p4=ByteArray(16*256)
        init {
            val bytes=context.assets.open("npv_whitebox.bin").use{it.readBytes()}
            require(bytes.size==8+24576+32768+4096)
            val bb=ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val header=ByteArray(8).also{bb.get(it)}
            require(String(header,Charsets.US_ASCII)=="NPWA0001")
            bb.get(p2)
            for(i in p3.indices)p3[i]=bb.int
            for(i in p5.indices)p5[i]=bb.int
            bb.get(p4)
            require(!bb.hasRemaining())
        }
        fun box(x:Int,a:Int,b:Int):Int=p2[x*256+(a shl 4)+b].toInt() and 15
        private fun mix(input:IntArray,t:IntArray):IntArray {
            val out=IntArray(16)
            for(col in 0..3) {
                val c=col*4
                val v=IntArray(4){t[(c+it)*256+input[c+it]]}
                for(row in 0..3) {
                    val idx=col*24+row*6
                    val hiShift=28-row*8
                    val loShift=24-row*8
                    val hi=box(idx+4,
                        box(idx,(v[0] ushr hiShift)and 15,(v[1] ushr hiShift)and 15),
                        box(idx+1,(v[2] ushr hiShift)and 15,(v[3] ushr hiShift)and 15))
                    val lo=box(idx+5,
                        box(idx+2,(v[0] ushr loShift)and 15,(v[1] ushr loShift)and 15),
                        box(idx+3,(v[2] ushr loShift)and 15,(v[3] ushr loShift)and 15))
                    out[col*4+row]=(hi shl 4)or lo
                }
            }
            return out
        }
        fun encrypt(block:ByteArray):ByteArray {
            require(block.size==16)
            val perm=intArrayOf(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11)
            var s=IntArray(16){block[it].toInt()and 255}
            s=IntArray(16){s[perm[it]]}
            s=mix(mix(s,p3),p5)
            s=IntArray(16){s[perm[it]]}
            return ByteArray(16){p4[it*256+s[it]]}
        }
    }
    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        var text=p.utf8(input).trim()
        if(text.startsWith("NPVTSUB1"))text=text.substring(8).trim()
        else if(text.startsWith("NPVT1"))text=text.substring(5).trim()
        val parts=text.split(',')
        require(parts.size>=2)
        val raw=p.b64(parts[1]);require(raw.size>16)
        val iv=raw.copyOfRange(0,16)
        val ciphertext=raw.copyOfRange(16,raw.size)
        val engine=Tables(context)
        val clear=ByteArray(ciphertext.size)
        var key=ByteArray(16)
        for(i in ciphertext.indices){
            if(i%16==0){
                key=engine.encrypt(iv)
                for(index in 15 downTo 0) {
                    iv[index]=(iv[index]+1).toByte()
                    if(iv[index]!=0.toByte())break
                }
            }
            clear[i]=(ciphertext[i].toInt() xor key[i%16].toInt()).toByte()
        }
        val plain=p.utf8(clear)
        val json=try {
            if(plain.trimStart().startsWith("[")) {
                val arr=JSONArray(plain)
                if(arr.length()>0 && arr.get(0) is JSONObject) arr.getJSONObject(0)
                else JSONObject().put("raw_data",plain)
            }else JSONObject(plain)
        }catch(_:Exception){JSONObject().put("raw_data",plain)}
        FinalJsonSurface.render(".npv",FinalJsonSurface.body(json),
            trailingNewline=true)
    }
}

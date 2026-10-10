package com.ghostdeveloper.spdecode.parity

/** Byte-accurate, 13 two-stage rounds plus final lookup: npvs.py::_whitebox_block. */
internal class NpvsWhiteboxEvaluator(private val table: ByteArray) {
    private val shift = intArrayOf(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11)
    private val rounds = (table[0].toInt() and 255)-1
    private val first = 1+rounds*24576
    private val final = first+rounds*16384
    private val second = final+4096
    init { require(rounds==13 && second+rounds*16384==table.size) }
    private fun word(i:Int):Int =
        ((table[i].toInt() and 255) shl 24) or
        ((table[i+1].toInt() and 255) shl 16) or
        ((table[i+2].toInt() and 255) shl 8) or
        (table[i+3].toInt() and 255)
    private fun combine(input:IntArray, round:Int, base:Int):IntArray {
        val output=IntArray(16)
        for(col in 0..3) {
            val words=IntArray(4) {
                val i=col*4+it
                word(base+round*16384+i*1024+input[i]*4)
            }
            for(row in 0..3) {
                val start=1+round*24576+(col*24+row*6)*256
                fun pair(o:Int,a:Int,b:Int,s:Int):Int =
                    table[start+o*256+
                        ((words[a] ushr s) and 15)*16+
                        ((words[b] ushr s) and 15)].toInt() and 255
                val high=table[start+1024+pair(0,0,1,28-8*row)*16+
                    pair(1,2,3,28-8*row)].toInt() and 255
                val low=table[start+1280+pair(2,0,1,24-8*row)*16+
                    pair(3,2,3,24-8*row)].toInt() and 255
                output[col*4+row]=(high shl 4) or low
            }
        }
        return output
    }
    fun encrypt(block:ByteArray):ByteArray {
        require(block.size==16)
        var state=IntArray(16){block[it].toInt() and 255}
        repeat(rounds){r->
            state=IntArray(16){state[shift[it]]}
            state=combine(state,r,first)
            state=combine(state,r,second)
        }
        state=IntArray(16){state[shift[it]]}
        return ByteArray(16){table[final+it*256+state[it]]}
    }
}

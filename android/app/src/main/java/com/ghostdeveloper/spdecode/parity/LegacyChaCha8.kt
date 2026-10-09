package com.ghostdeveloper.spdecode.parity

/** ChaCha20 (original 64-bit nonce/64-bit block counter), identical to
 * PyCryptodome ChaCha20.new(key=32,nonce=8); seek(64)=counter 1.
 * Not interchangeable with JCA's 96-bit IETF ChaCha20 nonce.
 */
internal object LegacyChaCha8 {
    private fun word(b:ByteArray,i:Int):Int=
        (b[i].toInt()and 255) or ((b[i+1].toInt()and 255) shl 8) or
            ((b[i+2].toInt()and 255) shl 16) or ((b[i+3].toInt()and 255) shl 24)
    private fun rotate(v:Int,n:Int)=(v shl n) or (v ushr (32-n))
    private fun quarter(s:IntArray,a:Int,b:Int,c:Int,d:Int){
        s[a]+=s[b];s[d]=rotate(s[d] xor s[a],16)
        s[c]+=s[d];s[b]=rotate(s[b] xor s[c],12)
        s[a]+=s[b];s[d]=rotate(s[d] xor s[a],8)
        s[c]+=s[d];s[b]=rotate(s[b] xor s[c],7)
    }
    fun decrypt(key:ByteArray,nonce:ByteArray,input:ByteArray,counterStart:Long=1):ByteArray {
        require(key.size==32 && nonce.size==8 && input.size<=1024*1024)
        val constants=intArrayOf(0x61707865,0x3320646e,0x79622d32,0x6b206574)
        val state=IntArray(16)
        for(i in 0..3)state[i]=constants[i]
        for(i in 0..7)state[4+i]=word(key,i*4)
        state[14]=word(nonce,0);state[15]=word(nonce,4)
        val out=ByteArray(input.size)
        var position=0
        var counter=counterStart
        while(position<input.size){
            state[12]=counter.toInt();state[13]=(counter ushr 32).toInt()
            val s=state.copyOf()
            repeat(10){
                quarter(s,0,4,8,12);quarter(s,1,5,9,13)
                quarter(s,2,6,10,14);quarter(s,3,7,11,15)
                quarter(s,0,5,10,15);quarter(s,1,6,11,12)
                quarter(s,2,7,8,13);quarter(s,3,4,9,14)
            }
            for(i in 0..15)s[i]+=state[i]
            val count=minOf(64,input.size-position)
            for(j in 0 until count)
                out[position+j]=(input[position+j].toInt() xor
                    ((s[j/4] ushr ((j%4)*8)) and 255)).toByte()
            position+=count;counter++
        }
        return out
    }
}

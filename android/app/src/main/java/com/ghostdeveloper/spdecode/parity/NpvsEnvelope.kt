package com.ghostdeveloper.spdecode.parity

/** Fully bounds-checked, signature-verified NPVS v5 app-key envelope. */
internal class NpvsEnvelope private constructor(
    val header:ByteArray,
    val salt:ByteArray,
    val wrapped:ByteArray,
    val prefixEnd:Int,
    val nonce:ByteArray,
    val configId:ByteArray,
    val publicKey:ByteArray,
    val metadataCiphertext:ByteArray,
    val body:ByteArray
) {
    companion object {
        fun parse(data:ByteArray):NpvsEnvelope {
            val p=NpvsPrimitives
            require(data.size in 89..NpvsPort.MAX_INPUT &&
                p.read(data,0,4).contentEquals(p.ascii("NPVS")) &&
                data[4]==5.toByte())
            val len=p.u32(data,5)
            require(len in 135L..262144L && 9L+len+80<=data.size)
            val header=p.read(data,9,9+len.toInt())
            require(header[0]==1.toByte() && header[50]==2.toByte())
            val recipients=p.u16(header,51)
            require(recipients<=1024)
            val offset=53+recipients*125
            require(offset+82<=header.size && p.u16(header,offset)==2)
            val prefixEnd=offset+78
            val mlen=p.u32(header,prefixEnd)
            require(mlen>=16 && mlen==header.size.toLong()-prefixEnd-4)
            val end=9+len.toInt()
            val bodyLen=p.u32(data,end+12)
            require(bodyLen>=70 && end.toLong()+16+bodyLen+64==data.size.toLong())
            val pub=p.read(header,17,50)
            NpvsSignature.verify(data,pub)
            return NpvsEnvelope(
                header=header,
                salt=p.read(header,offset+2,offset+18),
                wrapped=p.read(header,offset+18,offset+78),
                prefixEnd=prefixEnd,
                nonce=p.read(data,end,end+12),
                configId=p.read(header,1,17),
                publicKey=pub,
                metadataCiphertext=p.read(header,prefixEnd+4,header.size),
                body=p.read(data,end+16,data.size-64)
            )
        }
    }
}

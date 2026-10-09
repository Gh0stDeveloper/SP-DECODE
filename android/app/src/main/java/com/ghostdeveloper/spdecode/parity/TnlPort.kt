package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Original decoders/Python/tnl.py:
 * - two .tnl PBKDF2-SHA256/AES-GCM keys
 * - OpenTunnel (OT) base64 seed+length+scramble transport
 * - OPL2 binary mask+CRC32+PBKDF2/100000/AES-GCM
 * - XML entry renderer excludes file protections.
 */
object TnlPort {
    private val p=LegacyPortPrimitives
    private val passwords=listOf("B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg",
        "A^ST^f6ASG6AS5asd")
    private const val OPL_SECRET="f3a91c4e2d7b05869e4f1a3c8d2e6b07a5c9f2e14d8b3a76e0f5c1d9b4a72e3f"
    private const val OPL_LEN_XOR= -1481390639
    private val OT_KEY=p.hex("bd561d5a60918ccde642091edd0f754c3346ecf0d609f161811f8c26c130e287")
    private val ignored=setOf("file.proteger","file.msg","file.appVersionCode",
        "file.validade","file.pedirLogin","file.VersionCode",
        "file.protection","file.validate","file.askLogin")
    private fun gcmTriple(text:String,password:String,iterations:Int, bits:Int):ByteArray {
        val split=text.trim().split('.')
        require(split.size==3)
        val salt=p.b64(split[0]);val nonce=p.b64(split[1]);val encrypted=p.b64(split[2])
        val spec=PBEKeySpec(password.toCharArray(),salt,iterations,bits)
        val key=try{SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec).encoded}finally{spec.clearPassword()}
        val cipher=Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,nonce))
        return cipher.doFinal(encrypted)
    }
    private fun openTnl(input:ByteArray):ByteArray {
        p.bounded(input)
        if(input.size>=12 && input[0]==0x4f.toByte()&&input[1]==0x50.toByte()
            &&input[2]==0x4c.toByte()&&input[3]==2.toByte()){
            val header=ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN)
            val encryptedLen=header.getInt(4) xor OPL_LEN_XOR
            require(encryptedLen>=0 && encryptedLen<=input.size-12)
            val actual=ByteArray(encryptedLen)
            for(i in actual.indices){
                val r=i%8
                val mask=if(r==0)195 else ((195 ushr(8-r)) or (195 shl r))and 255
                actual[i]=((input[12+i].toInt() and 255) xor mask xor(i and 255)).toByte()
            }
            val checksum=CRC32().apply{update(actual)}.value
            require(checksum==(header.getInt(8).toLong() and 0xffffffffL))
            return gcmTriple(p.utf8(actual),OPL_SECRET,100000,256)
        }
        val text=p.utf8(input).trim()
        if('.' in text)for(password in passwords){
            try{return gcmTriple(text,password,1000,128)}
            catch (_:Exception){}
        }
        val raw=p.b64(text)
        require(raw.size>=8)
        val bb=ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val seed=bb.int
        val n=bb.int
        require(n>=0&&n<=raw.size-8)
        return ByteArray(n){i->
            val x=(raw[8+i].toInt() and 255) xor ((7*i+13)and 255)
            val rotated=((x ushr 3) or (x shl 5)) and 255
            ((OT_KEY[i%32].toInt() and 255) xor ((seed ushr ((i*8)and 24))and 255)
                xor rotated).toByte()
        }
    }
    fun decode(input:ByteArray):String?=p.safeDecode{
        val xml=p.utf8(openTnl(input))
        val values=linkedMapOf<String,String>()
        val lines=xml.split('\n')
        var i=0
        while(i<lines.size) {
            val line=lines[i].trim()
            if(line.startsWith("<entry")){
                val start=line.indexOf("key=\"")+5
                val end=if(start>=5)line.indexOf('"',start) else -1
                if(end>start) {
                    var name=line.substring(start,end)
                    if(name.isNotEmpty()&&name !in ignored) {
                        val open=line.indexOf("\">",end)+2
                        if(open>1) {
                            var text=line.substring(open)
                            if("</entry>" in text)text=text.substringBefore("</entry>")
                            else {
                                while(i+1<lines.size && "</entry>" !in lines[i+1]){
                                    i++;text+="\n"+lines[i]
                                }
                                if(i+1<lines.size){i++;text+="\n"+lines[i].substringBefore("</entry>")}
                            }
                            text=text.trim()
                            if(text.isNotEmpty()) {
                                if(name=="proxyPayload")name="Payload"
                                values[name]=text
                            }
                        }
                    }
                }
            }
            i++
        }
        require(values.isNotEmpty())
        "{\n"+values.entries.joinToString(",\n"){
            "  "+p.jsonQuote(it.key)+": "+p.jsonQuote(it.value)
        }+"\n}\n"
    }
}

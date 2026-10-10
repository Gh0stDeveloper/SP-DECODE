package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Authenticated field inventory, exact IDs and reference graph from npvs.py. */
internal object NpvsFields {
    fun read(body:ByteArray,dek:ByteArray,context:ByteArray):JSONObject {
        val p=NpvsPrimitives
        require(body.size>=70 &&
            p.read(body,0,4).contentEquals(byteArrayOf(78,80,70,1)) &&
            MessageDigest.isEqual(p.read(body,4,36),context))
        val count=p.u16(body,36)
        require(count>0)
        val inventory=p.read(body,0,body.size-32)
        val expected=p.hmac(p.fieldKey(dek,context,"inventory",0),inventory)
        require(MessageDigest.isEqual(expected,p.read(body,body.size-32,body.size)))
        var pos=38
        var last=0
        val records=linkedMapOf<Int,Any>()
        repeat(count) {
            require(pos+6<=body.size-32)
            val id=p.u16(body,pos)
            val length=p.u32(body,pos+2)
            pos+=6
            require(id>last && length in 16L..1048592L &&
                length<=body.size-32L-pos)
            val payload=p.read(body,pos,pos+length.toInt())
            pos+=length.toInt()
            val aad=p.join(p.ascii("NPV-fields-v1/record/"),context,
                p.be16(id),p.be32(length.toInt()-16))
            val clear=p.decrypt(p.fieldKey(dek,context,"field",id),
                ByteArray(12),payload,aad)
            records[id]=NpvsJson.parse(clear)
            last=id
        }
        require(pos==body.size-32 && records.containsKey(65535))
        val used=hashSetOf<Int>()
        fun resolve(node:Any?,depth:Int):Any {
            require(depth<=128)
            return when(node) {
                is JSONObject->JSONObject().also{out->
                    for(key in LegacyPortPrimitives.keys(node)){
                        out.put(key,resolve(node.get(key),depth+1))
                    }
                }
                is JSONArray->JSONArray().also{out->
                    for(index in 0 until node.length()){
                        out.put(resolve(node.get(index),depth+1))
                    }
                }
                else->{
                    require(node is Int || node is Long)
                    val id=(node as Number).toInt()
                    require(id in 1..65534 && records.containsKey(id))
                    val scalar=records.getValue(id)
                    require(scalar !is JSONObject && scalar !is JSONArray)
                    used.add(id)
                    scalar
                }
            }
        }
        val document=resolve(records.getValue(65535),0)
        require(document is JSONObject && document.opt("configs") is JSONArray)
        require(used==records.keys.filter{it!=65535}.toSet())
        return document as JSONObject
    }
}

package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Strict, bounded, data-only Java serialization parser matching sockip.py.
 * Handles objects, primitive fields, arrays, enums, class-descriptors,
 * references and annotations without instantiating Java classes.
 */
internal class SockipObjectReader(input:ByteArray) {
    private val buf=ByteBuffer.wrap(input).order(ByteOrder.BIG_ENDIAN)
    private data class Descriptor(val name:String,var flags:Int=0,
        val fields:MutableList<Pair<String,String>> = mutableListOf(),
        var parent:Descriptor?=null)
    private val handles=linkedMapOf<Int,Any?>()
    private var next=0x7e0000
    private var nodes=0
    init{require(input.size in 4..(4*1024*1024))}
    private fun assertRemaining(n:Int) { require(n>=0 && n<=buf.remaining()) }
    private fun bytes(n:Int):ByteArray{assertRemaining(n);return ByteArray(n).also{buf.get(it)}}
    private fun u1():Int{assertRemaining(1);return buf.get().toInt()and 255}
    private fun u2():Int{assertRemaining(2);return buf.short.toInt()and 65535}
    private fun u4():Int{assertRemaining(4);return buf.int}
    private fun utf(long:Boolean=false):String{
        val n=if(long){assertRemaining(8);buf.long}else u2().toLong()
        require(n in 0..1024*1024)
        return String(bytes(n.toInt()),Charsets.UTF_8)
    }
    private fun register(value:Any?):Any?{handles[next++]=value;return value}
    fun read():JSONObject{
        require(bytes(4).contentEquals(byteArrayOf(0xac.toByte(),0xed.toByte(),0,5)))
        val root=content(0) as? MutableMap<*,*> ?:error("not a Java object")
        require(!buf.hasRemaining())
        val out=JSONObject()
        for((k,v)in root)if(k is String&&k!="__class__")out.put(k,toJson(v))
        return out
    }
    private fun toJson(value:Any?,level:Int=0):Any?{
        require(level<=32)
        return when(value){
            is Map<*,*>->JSONObject().also {o->
                for((k,v)in value)if(k is String)o.put(k,toJson(v,level+1))
            }
            is List<*>->JSONArray().also{arr->value.forEach{arr.put(toJson(it,level+1))}}
            null->JSONObject.NULL
            else->value
        }
    }
    private fun content(depth:Int,forced:Int=-1):Any? {
        require(depth<=64 && ++nodes<=150000)
        val tag=if(forced>=0)forced else u1()
        return when(tag){
            0x70->null
            0x71->{val handle=u4();require(handles.containsKey(handle));handles[handle]}
            0x72->descriptor(depth+1)
            0x73->obj(depth+1)
            0x74->register(utf())
            0x75->array(depth+1)
            0x77->bytes(u1())
            0x79->{handles.clear();next=0x7e0000;content(depth+1)}
            0x7a->{val size=u4();require(size in 0..4*1024*1024);bytes(size)}
            0x7c->register(utf(true))
            0x7e->enum(depth+1)
            else->error("unsupported Java stream token")
        }
    }
    private fun descriptor(depth:Int):Descriptor{
        val name=utf()
        bytes(8)
        val d=register(Descriptor(name)) as Descriptor
        d.flags=u1()
        val count=u2();require(count<=512)
        repeat(count){
            val code=u1().toChar().toString()
            val fieldName=utf()
            val type=if(code=="L"||code=="[")
                content(depth+1) as? String ?:error("bad descriptor type")
            else code
            d.fields.add(fieldName to type)
        }
        while(true){val tag=u1();if(tag==0x78)break;content(depth+1,tag)}
        val parent=content(depth+1)
        require(parent==null || parent is Descriptor)
        d.parent=parent as? Descriptor
        return d
    }
    private fun lineage(d:Descriptor):List<Descriptor>{
        val result=mutableListOf<Descriptor>()
        var cur:Descriptor?=d
        while(cur!=null){require(result.size<=32);result.add(cur);cur=cur.parent}
        return result.reversed()
    }
    private fun obj(depth:Int):MutableMap<String,Any?>{
        val d=content(depth+1) as? Descriptor ?:error("no Java class descriptor")
        val map=linkedMapOf<String,Any?>("__class__" to d.name)
        register(map)
        for(cls in lineage(d)){
            for((name,type)in cls.fields)map[name]=field(type,depth+1)
            if((cls.flags and 1)!=0)skipCustom(depth+1)
        }
        return map
    }
    private fun skipCustom(depth:Int){
        while(true){val token=u1();if(token==0x78)return;content(depth+1,token)}
    }
    private fun array(depth:Int):MutableList<Any?> {
        val d=content(depth+1) as? Descriptor?:error("no array descriptor")
        val n=u4();require(n in 0..100000)
        val list=mutableListOf<Any?>()
        register(list)
        when(d.name.removePrefix("[")){
            "B"->{val raw=bytes(n);raw.forEach{list.add(it.toInt())}}
            "I"->repeat(n){assertRemaining(4);list.add(buf.int)}
            "J"->repeat(n){assertRemaining(8);list.add(buf.long)}
            "Z"->bytes(n).forEach{list.add(it.toInt()!=0)}
            else->repeat(n){list.add(content(depth+1))}
        }
        return list
    }
    private fun enum(depth:Int):MutableMap<String,Any?>{
        val d=content(depth+1) as? Descriptor?:error("no enum descriptor")
        val out=linkedMapOf<String,Any?>("__class__" to d.name)
        register(out)
        out["value"]=content(depth+1) as? String ?:error("invalid enum")
        return out
    }
    private fun field(type:String,depth:Int):Any?{
        require(type.isNotEmpty())
        return when(type[0]){
            'B'->{assertRemaining(1);buf.get().toInt()}
            'C'->u2().toChar().toString()
            'D'->{assertRemaining(8);buf.double}
            'F'->{assertRemaining(4);buf.float}
            'I'->{assertRemaining(4);buf.int}
            'J'->{assertRemaining(8);buf.long}
            'S'->{assertRemaining(2);buf.short.toInt()}
            'Z'->u1()!=0
            'L','['->content(depth+1)
            else->error("unsupported primitive")
        }
    }
}

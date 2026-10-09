package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject

/**
 * WeTunnel .ipt: original custom XXTEA-like JavaScript-compatible 32-bit
 * arithmetic. Never treat a partially decoded string as a valid profile.
 */
object IptPort {
    private val p=LegacyPortPrimitives
    private val password=p.b64("QEFkZWRheW8ncyBXZVR1bm5lbA==")
        .copyOfRange(0,16)
    private val labels=sortedMapOf(
        "PSInstall" to "PS Install","DeviceID" to "Device ID",
        "RootBlock" to "Root Block","isBlockVPN" to "Block VPN",
        "isXposed" to "Xposed","isBlockAppList" to "Block App List",
        "ConfigAppBlockList" to "Config App Block List",
        "MobileData" to "Mobile Data","ExpireDate" to "Expire Date",
        "Message" to "Message","Config" to "Config","Flag" to "Flag",
        "Payload" to "Payload","SNIHost" to "SNI Host",
        "DNSAddress" to "DNS Address","Type" to "Type",
        "ProxyHost" to "Proxy Host","ProxyPort" to "Proxy Port",
        "Server" to "Server","Name" to "Name"
    )
    private fun longs(data:ByteArray):IntArray=IntArray((data.size+3)/4) { i ->
        var value=0
        for(j in 0 until 4) if(i*4+j<data.size)
            value=value or ((data[i*4+j].toInt() and 255) shl (8*j))
        value
    }
    private fun decrypt(input:ByteArray):String {
        val raw=p.b64(p.utf8(input).trim())
        val blocks=longs(raw)
        require(blocks.size>=2 && blocks.size<=65536)
        val key=longs(password)
        val count=blocks.size
        val delta=-0x658C6C4CL
        var sum=(6+52/count)*delta
        var y=blocks[0]
        while(sum!=0L) {
            val e=((sum shr 2) and 3L).toInt()
            for (index in count-1 downTo 0) {
                val z=blocks[if(index>0) index-1 else count-1]
                val first=((z ushr 5) xor (y shl 2)) +
                    ((y ushr 3) xor (z shl 4))
                val second=sum.toInt() xor y
                val mx= first xor (second + (key[(index and 3) xor e] xor z))
                y=blocks[index]-mx
                blocks[index]=y
            }
            sum-=delta
        }
        val clear=ByteArray(count*4)
        blocks.forEachIndexed { i, number ->
            for (j in 0 until 4) clear[i*4+j]=(number ushr (8*j)).toByte()
        }
        return String(clear,Charsets.ISO_8859_1).trimEnd('\u0000').trimEnd('N')
    }
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val clear=decrypt(input)
        val start=clear.indexOf('{')
        val end=clear.lastIndexOf('}')
        require(start>=0 && end>=start)
        val obj=JSONObject(clear.substring(start,end+1))
        require(obj.length()>0)
        val fields=labels.entries.filter { obj.has(it.key) }.joinToString("") { (key,label) ->
            "│[۞] $label: " + p.pythonValue(obj.get(key)) + "\n"
        }
        require(fields.isNotEmpty())
        p.header("(.ipt)")+"\n"+fields+"\n"+p.footer()
    }
}

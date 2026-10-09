package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject

/**
 * NapsternetV .npv2 Node xorCrypto: subtract one UTF-16 code unit per key unit.
 * The key candidates and output labels are frozen from the same repository.
 */
object Npv2Port {
    private val p=LegacyPortPrimitives
    private val modes=listOf("V2Ray (vmess)","Shadowsocks","Socks","V2Ray (vless)","Trojan")

    private fun unwrap(content:String,key:String):String=buildString(content.length) {
        content.forEachIndexed { i,c-> append((c.code-key[i%key.length].code).toChar()) }
    }
    private fun value(item:JSONObject,name:String):String? {
        if(!item.has(name)||item.isNull(name))return null
        return when(val v=item.get(name)) {
            is Boolean->v.toString()
            else->v.toString()
        }
    }
    private fun parse(input:JSONObject):LinkedHashMap<String,String> {
        val out=linkedMapOf<String,String>()
        fun copy(from:JSONObject, fromName:String,toName:String) {
            value(from,fromName)?.let{out[toName]=it}
        }
        val profile=input.optJSONObject("vmess")
        if(profile!=null){
            val type=profile.optInt("configType",-1)
            if(type in 0..4) {
                out["connectionMethod"]=modes[type]
                copy(profile,"remarks","remarks")
                when(type) {
                    0,3->{
                        val m=linkedMapOf(
                            "address" to "V2RayHost","port" to "V2RayPort",
                            "id" to "V2RayUserId","alterId" to "V2RayAlterId",
                            "network" to "V2RayNetwork","path" to "V2RayWSPath",
                            "requestHost" to "V2RayWSHost","security" to "V2RaySecurity",
                            "sni" to "V2RayTLS","allowInsecure" to "V2RayTLSInsecure",
                            "quicSecurity" to "V2RayQUICSec","quicKey" to "V2RayQUICKey",
                            "headerType" to "V2RayHeader","encryption" to "V2RayEncryption",
                            "enableMux" to "V2RayMux")
                        m.forEach {(a,b)->copy(profile,a,b)}
                    }
                    1->linkedMapOf("address" to "shadowsocksHost","port" to "shadowsocksPort",
                        "security" to "shadowsocksEncryptionMethod",
                        "id" to "shadowsocksPassword","enableMux" to "shadowsocksMux")
                        .forEach {(a,b)->copy(profile,a,b)}
                    2->linkedMapOf("address" to "socksHost","port" to "socksPort",
                        "username" to "socksUsername","id" to "socksPassword",
                        "enableMux" to "socksMux").forEach {(a,b)->copy(profile,a,b)}
                    4->linkedMapOf("address" to "trojanAddress","port" to "trojanPort",
                        "id" to "trojanPass","sni" to "trojanSNI",
                        "allowInsecure" to "trojanVerifySSL").forEach {(a,b)->copy(profile,a,b)}
                }
            } else out["note1"]="Something went wrong."
        }
        input.optJSONObject("security")?.let { sec ->
            linkedMapOf("blockRooted" to "blockedRoot","onlyMobileNetwork" to "mobileData",
                "onlyPlayStore" to "googlePlay").forEach{(a,b)->copy(sec,a,b)}
            if(sec.optString("password").length>1) {
                out["passwordProtected"]="true";copy(sec,"password","passwordValue")
            }
            copy(sec,"version","build")
            val expiry=sec.optString("expiryDate")
            if(expiry.length>1)out["expireDate"]=expiry
            else copy(sec,"xExpiryDate","expireDate")
        }
        out["credits"]="\n├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @DecryptSP \n" +
            "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @TEAM_CHICO_CP\n└───────────────\n"
        return out
    }
    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val keys=LegacyModuleText.keys(context).getJSONArray("npv2Passwords")
        val encoded=p.utf8(input)
        var decoded:JSONObject?=null
        for(i in 0 until keys.length()) {
            try {
                decoded=JSONObject(unwrap(encoded,keys.getString(i)))
                break
            } catch (_:Exception) { }
        }
        LegacyModuleText.render(context,parse(decoded ?: error("No NPV2 key matched")))
    }
}

package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.json.JSONArray
import org.json.JSONObject
import java.nio.charset.CodingErrorAction
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * NUR TUNNEL VPN 1.0.8.8 / build 138.
 *
 * Source parity: NUR_TUNNEL_SOLID.py and NUR_TUNNEL_SERVERS.py.
 * These are different, strictly typed documents sharing the authenticated envelope.
 * Offline .solid never fetches a URL. The server screen explicitly fetches encrypted
 * catalog bytes and then feeds them to decodeCatalog().
 */
internal object NurTunnelPort {
    const val MAX_INPUT = 16 * 1024 * 1024
    private const val MAX_FIELDS = 100000
    private const val MAX_DEPTH = 64

    // Historical public decoding constants ship only in the encrypted build asset.
    // The vault reduces casual DEX exposure, not recoverability under reverse engineering.
    private fun secrets(context:Context):Pair<ByteArray,ByteArray> {
        val profile=JSONObject(SecureAssetVault.readText(context,
            "embedded_kotlin_profiles.json")).getJSONObject("nurTunnel")
        return Pair(
            Base64.decode(profile.getString("exportSecretB64"),Base64.NO_WRAP),
            Base64.decode(profile.getString("internalSecretB64"),Base64.NO_WRAP)
        )
    }
    private val carrierPattern = Regex("[A-Za-z0-9+/]*={0,2}")
    private val hexPattern = Regex("[0-9a-fA-F]+")
    private val encryptedFields = setOf(
        "Payload", "SNI", "V2rayAddress", "V2rayConfig", "V2rayHost", "V2raySNI",
        "BugDNS", "CustomProxy", "URI", "ServerIPHost", "OVPNUser", "OVPNPass",
        "UDP_obfs", "UDP_user", "CustomCertificate", "SlowDNSHost", "SlowDNSKey",
        "V2rayUUID", "V2rayPath", "H2pass", "DefOVPNUser", "DefOVPNPass",
        "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert",
    )

    private fun normalize(data:ByteArray):String {
        require(data.isNotEmpty() && data.size<=MAX_INPUT)
        val utf8 = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val input = utf8.decode(ByteBuffer.wrap(data)).toString()
            .removePrefix("\uFEFF").trim().replace("\r","").replace("\n","")
        require(input.isNotEmpty() && input.length<=MAX_INPUT && input.all { it.code<128 })
        return input
    }

    private fun open(text:String,secrets:Pair<ByteArray,ByteArray>):String {
        val exported = text.length%4==1 && text.length>=61
        val internal = text.length%4==0 && text.length>=60
        require(exported || internal) { "Unsupported NUR envelope" }
        val carrier = if(exported) text.take(3)+text.drop(4) else text
        require(carrierPattern.matches(carrier)) { "Invalid NUR Base64 envelope" }
        val raw = Base64.decode(carrier,Base64.DEFAULT)
        require(raw.size>=44 && raw.size<=MAX_INPUT)
        val salt=raw.copyOfRange(0,16)
        val nonce=raw.copyOfRange(16,28)
        val params=Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withSalt(salt).withIterations(3).withMemoryAsKB(8192)
            .withParallelism(1).withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .build()
        val key=ByteArray(32)
        val secret=if(exported)secrets.first else secrets.second
        try {
            Argon2BytesGenerator().apply { init(params) }.generateBytes(secret,key)
            val cipher=Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE,SecretKeySpec(key,"AES"),GCMParameterSpec(128,nonce))
            cipher.updateAAD(salt)
            val clear=cipher.doFinal(raw.copyOfRange(28,raw.size))
            try {
                return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(clear)).toString()
            } finally { clear.fill(0) }
        } finally {
            key.fill(0)
            salt.fill(0)
            nonce.fill(0)
            raw.fill(0)
        }
    }

    private fun candidate(value:String):Boolean {
        val text=value.trim().replace("\r","").replace("\n","")
        if(text.length%2==0 && hexPattern.matches(text))return false
        if(text.length<60 || text.length%4 !in setOf(0,1))return false
        val carrier=if(text.length%4==1)text.take(3)+text.drop(4) else text
        return carrierPattern.matches(carrier)
    }

    private fun fields(root:JSONObject,secrets:Pair<ByteArray,ByteArray>) {
        var count=0
        fun visit(node:Any?,depth:Int,field:String):Any? {
            count++
            require(count<=MAX_FIELDS && depth<=MAX_DEPTH) { "NUR structure limit" }
            return when(node) {
                is JSONObject -> {
                    val names=node.keys().asSequence().toList()
                    names.forEach { name-> node.put(name,visit(node.opt(name),depth+1,name)) }
                    node
                }
                is JSONArray -> {
                    for(i in 0 until node.length())node.put(i,visit(node.opt(i),depth+1,field))
                    node
                }
                is String -> if(field in encryptedFields && candidate(node))open(node.trim().replace("\r","").replace("\n",""),secrets) else node
                else -> node
            }
        }
        visit(root,0,"")
    }

    private fun document(context:Context,input:ByteArray):JSONObject {
        val material=secrets(context)
        try {
            val root=JSONObject(open(normalize(input),material))
            fields(root,material)
            return root
        } finally {
            material.first.fill(0)
            material.second.fill(0)
        }
    }

    fun decodeSolid(context:Context,input:ByteArray):String?=try {
        val doc=document(context,input)
        require(doc.opt("Name") is String && doc.opt("TunnelType") is String) {
            "Not a NUR .solid profile"
        }
        LegacyPortPrimitives.prettyJson(doc)+"\n"
    }catch(_:Exception){null}

    fun decodeCatalog(context:Context,input:ByteArray):String?=try {
        val doc=document(context,input)
        require(doc.opt("Version") is String)
        val servers=doc.getJSONArray("Servers")
        val networks=doc.getJSONArray("Networks")
        for(array in listOf(servers,networks)) {
            for(i in 0 until array.length())require(array.opt(i) is JSONObject)
        }
        LegacyPortPrimitives.prettyJson(doc)+"\n"
    }catch(_:Exception){null}
}

package com.ghostdeveloper.spdecode.parity

import android.content.Context
import android.util.Base64
import org.json.JSONObject

/** Native offline parity of npvs.py::decode_npvs, no runtime or crypto fallback. */
object NpvsPort {
    const val MAX_INPUT = 4 * 1024 * 1024
    private val p=NpvsPrimitives
    private fun url64(data:ByteArray):String =
        Base64.encodeToString(data,Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    internal fun decodeDocument(context:Context,data:ByteArray):JSONObject {
        val env=NpvsEnvelope.parse(data)
        val block=NpvsWhiteboxEvaluator(NpvsWhitebox.tables(context))
            .encrypt(env.salt)
        val kdk=p.sha(p.join(p.ascii("npvtunnel/appkey/v2 "),block,env.configId))
        val dek=p.decrypt(kdk,p.read(env.wrapped,0,12),
            p.read(env.wrapped,12,env.wrapped.size),env.salt)
        require(dek.size==32)
        val mkey=p.hkdf(dek,env.nonce,p.ascii("NPVS-v5/metadata"))
        val meta=NpvsJson.parse(p.decrypt(mkey,env.nonce,
            env.metadataCiphertext,p.read(env.header,0,env.prefixEnd)))
        require(meta is JSONObject && meta.opt("policy") is JSONObject)
        meta as JSONObject
        val policy=meta.getJSONObject("policy")
        val sourcePolicy=linkedMapOf<String,Any?>(
            "onlyMobileNetwork" to NpvsJson.get(policy,"onlyMobileNetwork",false),
            "attestationLevel" to NpvsJson.get(policy,"attestationLevel",""),
            "expiresAt" to NpvsJson.get(policy,"expiresAt",null),
            "displayMessage" to NpvsJson.get(policy,"displayMessage",""),
            "customServerMessage" to NpvsJson.get(policy,"customServerMessage","")
        )
        val cv=policy.opt("configVersion")
        if(cv!=null && cv!=JSONObject.NULL && cv!=false && cv!=0 && cv!="")
            sourcePolicy["configVersion"]=cv
        val sourceHeader=linkedMapOf<String,Any?>(
            "v" to 5,
            "configId" to url64(env.configId),
            "issuedAt" to NpvsJson.get(meta,"issuedAt",""),
            "creator" to linkedMapOf("fp" to url64(p.sha(env.publicKey)),
                "pk" to url64(env.publicKey)),
            "policy" to sourcePolicy,
            "recipients" to null
        )
        val binding=p.sha(p.join(p.ascii("NPVS-v5/source-fields-v1/"),
            NpvsJson.canonical(sourceHeader).toByteArray(Charsets.UTF_8),env.nonce))
        val doc=NpvsFields.read(env.body,dek,binding)
        val authenticated=JSONObject().put("metadata",meta).put("document",doc)
        // Match npvs.py::decode_npvs_complete after all signature, AEAD and
        // authenticated field-inventory checks. No partial/plaintext fallback.
        return NpvsEmbeddedFields.unwrap(authenticated) as JSONObject
    }
    fun decode(context:Context,input:ByteArray):String? = try {
        LegacyPortPrimitives.prettyJson(decodeDocument(context,input))+"\n"
    } catch (_:Exception) {
        null
    }
}

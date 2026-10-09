package com.ghostdeveloper.spdecode.parity

import android.content.Context
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.InflaterInputStream

/**
 * HTTP Tweak 1.6.3 four original byte-substitution/permutation variants.
 * Independent of other AES/TEA decoders; 12 inverse rounds, proprietary
 * block chaining and bounded zlib inflate before strict JSON parsing.
 */
internal object HttpTweakReferencePort {
    private val p=LegacyPortPrimitives
    private const val ROUNDS=12
    private const val BLOCK=16
    fun decode(context:Context,input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val raw=p.b64(p.utf8(input))
        require(raw.size>=33 && raw.size%16==1)
        val variant=raw[0].toInt() and 255
        require(variant in 1..4)
        val catalog=JSONObject(context.assets.open("http_tweak_source_tables.json")
            .bufferedReader(Charsets.UTF_8).use{it.readText()})
        val tables=catalog.getJSONObject(variant.toString())
        val keys=p.b64(tables.getString("round_keys"))
        val permutations=p.b64(tables.getString("permutations"))
        val substitutions=p.b64(tables.getString("substitutions"))
        require(keys.size==192 && permutations.size==192 && substitutions.size==3072)
        val inverse=ByteArray(substitutions.size)
        for(round in 0 until ROUNDS) {
            val used=BooleanArray(256)
            for(index in 0..255) {
                val value=substitutions[round*256+index].toInt() and 255
                require(!used[value])
                used[value]=true
                inverse[round*256+value]=index.toByte()
            }
        }
        var previous=raw.copyOfRange(1,17)
        val output=ByteArray(raw.size-17)
        var at=17
        while(at<raw.size) {
            val cipher=raw.copyOfRange(at,at+BLOCK)
            var state=cipher.copyOf()
            for(round in (ROUNDS-1)downTo 0) {
                val base=round*BLOCK
                val stage=ByteArray(BLOCK)
                for(i in 0 until BLOCK) {
                    val dest=permutations[base+i].toInt() and 15
                    stage[dest]=(state[i].toInt() xor keys[base+i].toInt()).toByte()
                }
                for(i in 0 until BLOCK)state[i]=inverse[round*256+
                    (stage[i].toInt() and 255)]
            }
            for(i in 0 until BLOCK)output[at-17+i]=
                (state[i].toInt() xor previous[i].toInt()).toByte()
            previous=cipher
            at+=BLOCK
        }
        val bytes=ByteArrayOutputStream()
        InflaterInputStream(ByteArrayInputStream(output)).use{ stream->
            val block=ByteArray(4096)
            while(true){
                val n=stream.read(block)
                if(n<0)break
                bytes.write(block,0,n)
                require(bytes.size()<=p.MAX_INPUT)
            }
        }
        val json=JSONObject(p.utf8(bytes.toByteArray()))
        require(json.length()>0)
        "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ht/.htb)\n"+
            "│[۞] Aplicación: HTTP Tweak\n├───────────────\n"+
            p.prettyJson(json)+"\n└───────────────\n"
    }
}

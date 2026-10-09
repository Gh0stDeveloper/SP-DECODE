package com.ghostdeveloper.spdecode

/**
 * One in-memory session for pasted SSC / Dark Tunnel fragments, analogous to
 * the bot's text_sessions.py (single user/device; no Telegram chat IDs).
 * Drafts are never persisted to Bundle, Room, DataStore or disk.
 */
data class TextPartSession(
    val input:TextProtocolDecoder.Input,
    val parts:Int,
    val updatedAtMs:Long,
)

object TextMultipartAssembler {
    const val TIMEOUT_MS=600_000L

    fun next(previous:TextPartSession?,fragment:String,nowMs:Long):TextPartSession? {
        if(fragment.length>TextProtocolDecoder.MAX_CHARS)return null
        val detected=TextProtocolDecoder.identify(fragment)
            ?.takeUnless { it.protocol=="netmod" && "://" !in fragment }
        if(detected!=null) {
            if(!detected.multipart)return null
            val compact=compact(detected,detected.content)?:return null
            return TextPartSession(detected.copy(content=compact),1,nowMs)
        }
        if(previous==null||nowMs-previous.updatedAtMs>TIMEOUT_MS||
            nowMs<previous.updatedAtMs)return null
        val body=compact(previous.input,fragment)?:return null
        if(previous.input.content.length+body.length>TextProtocolDecoder.MAX_CHARS)return null
        return previous.copy(
            input=previous.input.copy(content=previous.input.content+body),
            parts=previous.parts+1,updatedAtMs=nowMs,
        )
    }

    private fun compact(input:TextProtocolDecoder.Input,value:String):String? {
        // Only allow the character alphabet actually used by this protocol.
        val noNoise=value.filterNot{
            it.isWhitespace()||it=='\u200b'||it=='\u200c'||it=='\u200d'||
            it=='\ufeff'||it=='\u0060'
        }
        if(noNoise.isEmpty())return null
        val prefix=when(input.protocol){
            "ssc"->"ssc://"
            "dark"->input.content.substringBefore("://")+"://"
            else->return null
        }
        val candidate=if(noNoise.startsWith(prefix,ignoreCase=true))
            noNoise.substring(prefix.length) else noNoise
        if(candidate.isEmpty())return null
        val valid=when(input.protocol){
            "ssc"->candidate.length<=TextProtocolDecoder.MAX_CHARS &&
                candidate.all{it in "0123456789abcdefABCDEF"}
            "dark"->candidate.length<=TextProtocolDecoder.MAX_CHARS &&
                candidate.all{it in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_=-"}
            else->false
        }
        if(!valid)return null
        // The initial fragment has a scheme. Continuations never repeat it.
        return if(value.contains("://"))prefix+candidate else candidate
    }
}

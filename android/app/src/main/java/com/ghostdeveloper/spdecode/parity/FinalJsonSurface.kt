package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject

/** Exact Python top-level presentation shared by originals that explicitly
 * invoke _format_top_level_json, without re-parsing string field values.
 */
internal object FinalJsonSurface {
    private val p=LegacyPortPrimitives
    private fun compact(v:Any?,depth:Int=0):String {
        require(depth<=24)
        return when(v){
            is JSONObject ->p.keys(v).joinToString(",", "{", "}") {
                p.jsonQuote(it)+":"+compact(v.get(it),depth+1)
            }
            is JSONArray ->(0 until v.length()).joinToString(",","[","]"){
                compact(v.get(it),depth+1)
            }
            is String->p.jsonQuote(v)
            is Boolean->v.toString()
            null,JSONObject.NULL->"null"
            else->v.toString()
        }
    }
    fun body(data:JSONObject):String=p.keys(data).joinToString("\n"){key->
        val v=data.get(key)
        val text=when(v){
            is JSONObject,is JSONArray->compact(v)
            null,JSONObject.NULL->"null"
            is String->v
            else->v.toString()
        }
        "│[۞] "+key+": "+text
    }
    fun render(suffix:String,body:String,trailingSpace:Boolean=false, trailingNewline:Boolean=false):String {
        require(body.isNotBlank())
        return "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 ("+suffix+")\n"+
            "│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"+
            body+"\n\n├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n"+
            "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"+
            (if(trailingSpace)" "else "")+(if(trailingNewline)"\n"else "")
    }
}

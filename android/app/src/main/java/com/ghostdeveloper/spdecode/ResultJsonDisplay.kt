package com.ghostdeveloper.spdecode

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive

/**
 * Display-only pure JSON. Neither this renderer nor privacy redaction changes
 * DecodeView.rawText, the encrypted history or the user's original exports.
 *
 * If a legacy decoder cannot be parsed as key/value fields, preserve each
 * nondecorative output line as a JSON string, instead of silently losing it.
 */
object ResultJsonDisplay {
    private val gson=GsonBuilder().serializeNulls().disableHtmlEscaping()
        .setPrettyPrinting().create()
    private val decorativeLine=Regex("""^[\\s│┌┐└┘├┤─═╔╗╚╝╠╣]+$""")
    private val decoratedHeading=Regex(
        """(?i)^\\s*│?\\s*(?:SP\\s*[-–]\\s*DECODE|[┌└├╔╚].*|(?:Developer|Group|Channel|Créditos|Credits|Copyright)\\s*:)""")
    private const val MAX_DEPTH=24

    fun render(raw:String,suffix:String,maskCredentials:Boolean=false):String {
        // Supports plain JSON arrays, primitives and objects, not just the
        // original bot-style text accepted by ResultPresentation.parse().
        val trimmed=raw.trim()
        val direct=if(trimmed.startsWith("{")||trimmed.startsWith("["))parse(trimmed)
            else null
        val document=ResultPresentation.parse(raw,suffix)
        val base=when {
            direct!=null->direct
            document.jsonParsed||document.fields.isNotEmpty()->
                parse(document.json) ?: JsonObject()
            else->fallback(raw,suffix)
        }
        return gson.toJson(normalize(base,maskCredentials,0))
    }

    private fun fallback(raw:String,suffix:String):JsonObject {
        val lines=JsonArray()
        raw.lineSequence().forEach { source ->
            val line=source.trim().removePrefix("│").trim()
            if(line.isNotBlank() && !decorativeLine.matches(source.trim()) &&
                !decoratedHeading.containsMatchIn(source.trim())) lines.add(line)
        }
        return JsonObject().apply {
            addProperty("format",suffix)
            add("content",lines)
        }
    }

    private fun parse(value:String):JsonElement?=try {
        JsonParser.parseString(value)
    }catch(_:Exception){null}

    private fun normalize(input:JsonElement,mask:Boolean,depth:Int):JsonElement {
        if(depth>=MAX_DEPTH)return input.deepCopy()
        return when {
            input.isJsonObject->JsonObject().also { output ->
                for((key,value) in input.asJsonObject.entrySet()){
                    output.add(key,if(mask && ResultPresentation.isCredential(key))
                        JsonPrimitive("••••••••")
                    else normalize(value,mask,depth+1))
                }
            }
            input.isJsonArray->JsonArray().also { arr ->
                for(value in input.asJsonArray)arr.add(normalize(value,mask,depth+1))
            }
            input.isJsonPrimitive && input.asJsonPrimitive.isString->{
                val raw=input.asString
                val trimmed=raw.trim()
                val embedded=if((trimmed.startsWith("{")&&trimmed.endsWith("}"))||
                    (trimmed.startsWith("[")&&trimmed.endsWith("]")))parse(trimmed) else null
                if(embedded!=null && (embedded.isJsonObject||embedded.isJsonArray))
                    normalize(embedded,mask,depth+1)
                else input.deepCopy()
            }
            else->input.deepCopy()
        }
    }
}

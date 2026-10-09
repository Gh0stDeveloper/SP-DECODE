package com.ghostdeveloper.spdecode

import com.google.gson.GsonBuilder
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive

/**
 * Presentation-only renderer for bot output: keep its original headers,
 * separators, key order and ALL values. Only expand syntactically valid JSON
 * objects/arrays found in value positions (or standalone JSON documents).
 *
 * Never replace DecodeView.rawText: clipboard "original" and encrypted
 * history must continue storing the exact decoder response.
 */
object RawResultFormatter {
    private val fieldLine = Regex("""^(\s*│\[[^]]+]\s*[^:\r\n]+:\s*)(.*)$""")
    private val keyLine = Regex("""^\s*│\[[^]]+]\s*([^:\r\n]+):""")
    private val pretty = GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create()
    private const val MAX_JSON_CHARS = 256 * 1024
    private const val MAX_RENDER_CHARS = 2 * 1024 * 1024
    private const val MAX_DEPTH = 20

    fun render(raw: String, maskCredentials: Boolean = false): String {
        if (raw.isEmpty()) return raw
        // Avoid choking the UI on an extraordinarily large decrypted response.
        if (raw.length > MAX_RENDER_CHARS) return if (maskCredentials)
            RedactionPolicy.mask(raw) else raw
        val out = StringBuilder(raw.length)
        val lines = raw.split('\n')
        for ((index, original) in lines.withIndex()) {
            if (index > 0) out.append('\n')
            val line = original.removeSuffix("\r")
            val match = fieldLine.matchEntire(line)
            if (match == null) {
                out.append(if (maskCredentials) RedactionPolicy.mask(line) else line)
                continue
            }
            val prefix = match.groupValues[1]
            val value = match.groupValues[2]
            val name = keyLine.find(line)?.groupValues?.get(1)?.trim().orEmpty()
            if (maskCredentials && ResultPresentation.isCredential(name)) {
                out.append(prefix).append("••••••••")
                continue
            }
            val tree = parseContainer(value)
            if (tree == null) {
                out.append(if (maskCredentials) RedactionPolicy.mask(line) else line)
            } else {
                val displayed = if (maskCredentials) mask(tree, 0) else tree
                val formatted = pretty.toJson(displayed)
                out.append(prefix.trimEnd()).append('\n')
                // Align an entire formatted object under its parent field.
                for ((n, part) in formatted.lineSequence().withIndex()) {
                    if (n > 0) out.append('\n')
                    out.append("│   ").append(part)
                }
            }
        }
        // A standalone JSON object is also a complete native decoder output.
        if (!raw.lineSequence().any { fieldLine.matches(it.removeSuffix("\r")) }) {
            val trimmed = raw.trim()
            val tree = parseContainer(trimmed)
            if (tree != null) return pretty.toJson(if (maskCredentials) mask(tree, 0) else tree)
        }
        return out.toString()
    }

    private fun parseContainer(value: String): JsonElement? {
        val s = value.trim()
        if (s.length !in 2..MAX_JSON_CHARS || !(s.startsWith("{") && s.endsWith("}") ||
                    s.startsWith("[") && s.endsWith("]"))) return null
        return try {
            JsonParser.parseString(s).takeIf { it.isJsonObject || it.isJsonArray }
        } catch (_: Exception) { null }
    }

    /** Preview-only redaction of nested JSON keys, not the original data. */
    private fun mask(value: JsonElement, depth: Int): JsonElement {
        if (depth >= MAX_DEPTH) return JsonPrimitive("••••••••")
        return when {
            value.isJsonObject -> JsonObject().also { next ->
                for ((key, child) in value.asJsonObject.entrySet())
                    next.add(key, if (ResultPresentation.isCredential(key))
                        JsonPrimitive("••••••••") else mask(child, depth + 1))
            }
            value.isJsonArray -> JsonArray().also { array ->
                value.asJsonArray.forEach { array.add(mask(it, depth + 1)) }
            }
            else -> value.deepCopy()
        }
    }
}

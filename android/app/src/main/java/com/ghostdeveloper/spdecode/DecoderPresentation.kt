package com.ghostdeveloper.spdecode

/** The historical decoder output is immutable; redaction is UI/export only. */
data class DecodeView(
    val filename:String,
    val extension:String,
    val rawText:String,
    val fileBytes:Int,
) {
    val redactedText:String get()=RedactionPolicy.mask(rawText)
    val fields:List<Pair<String,String>> get()=RedactionPolicy.fields(rawText)
}

/** Fail-safe masking of obvious named secrets. The raw decoder output can also
 * contain undocumented secrets or free-form payloads: never promise complete
 * redaction and require deliberate confirmation before sharing raw text.
 */
object RedactionPolicy {
    private val sensitive=Regex(
        "(?i)(?:pass(?:word|wd)?|pwd|secret|token|key|clave|contraseñ|credential|auth|payload|private|cookie|bearer|session|uuid|hwid|sshuser|sshpass)"
    )
    private val item=Regex("""^(\s*(?:│\[[^]]+\]\s*)?([^:\r\n]{1,120})\s*:\s*)([^\r\n]*)$""")
    fun isSensitive(name:String)=sensitive.containsMatchIn(name)
    fun mask(input:String):String=input.lineSequence().joinToString("\n"){line->
        val m=item.matchEntire(line)
        if(m!=null&&isSensitive(m.groupValues[2]))m.groupValues[1]+"••••••••" else line
    }
    fun fields(input:String):List<Pair<String,String>> =
        input.lineSequence().mapNotNull{line->
            val m=item.matchEntire(line.trim())?:return@mapNotNull null
            val label=m.groupValues[2].trim()
            if(label.isEmpty() || label.length>80 || label.contains("𝗚𝗥𝗢𝗨𝗣")
                || label.contains("𝗖𝗛𝗔𝗡𝗡𝗘𝗟"))return@mapNotNull null
            label to m.groupValues[3].trim()
        }.take(30).toList()
}

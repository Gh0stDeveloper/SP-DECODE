package com.ghostdeveloper.spdecode

/** One extendable registry for settings and the accepted per-app language tag. */
data class SupportedLanguage(val tag:String,val nativeName:String)

object SupportedLanguages {
    val options:List<SupportedLanguage> = listOf(
        SupportedLanguage("system",""),
        SupportedLanguage("es","Español"),
        SupportedLanguage("en","English"),
        SupportedLanguage("pt-BR","Português (Brasil)"),
        SupportedLanguage("ar","العربية"),
    )
    fun supports(tag:String):Boolean=options.any{it.tag==tag}
}

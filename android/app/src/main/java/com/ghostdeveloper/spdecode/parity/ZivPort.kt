package com.ghostdeveloper.spdecode.parity

/** ZIV: two original candidate PBKDF2-SHA256 passwords, AES-GCM and XML labels.
 * Only ZIV's own two known passwords may be tested, no other format's keys.
 */
object ZivPort {
    private val p=LegacyPortPrimitives
    private val passwords=listOf("fubvx788b46v","SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5")
    private val extra=linkedMapOf(
        "v2rayprotocol" to "V2ray protocol",
        "file.appVersionCode" to "File App Version Code",
        "injectionmode" to "Injection mode",
        "udpForward" to "Udp Forward",
        "v2raytlsinsecure" to "V2RAY tls insecure",
        "wakelock" to "Wake lock",
        "speeddown" to "Speed down",
        "blockroot" to "Block root",
        "file.protect" to "File protect",
        "speedup" to "Speedup",
        "tunnelType" to "Tunnel Type")
    fun decode(input:ByteArray):String?=p.safeDecode {
        p.bounded(input)
        val text=passwords.firstNotNullOfOrNull { password ->
            try { p.dotGcm(input,password) } catch (_:Exception) { null }
        } ?: error("unsupported ZIV key")
        val head=Batch20Primitives.labeledDotGcm(input,
            // Validate this specific authenticated key again for canonical XML labels.
            passwords.first{password->try{p.dotGcm(input,password)==text}catch(_:Exception){false}},
            "ziv")
        if(extra.keys.none{key->text.contains("<entry key=\"$key\"")}) head
        else {
            val extraLines=extra.entries.mapNotNull {(key,label)->
                val xml=text.split('\n').firstOrNull{it.startsWith("<entry key=\"$key\">")}
                val v=xml?.substringAfter("\">")?.substringBefore("</entry>")?.trim().orEmpty()
                if(v.isEmpty()||v=="0"||v=="*******")null else "│[۞] $label: $v\n"
            }.joinToString("")
            head.replace("├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣",extraLines+"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣")
        }
    }
}

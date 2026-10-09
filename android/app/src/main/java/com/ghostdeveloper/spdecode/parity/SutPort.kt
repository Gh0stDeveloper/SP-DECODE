package com.ghostdeveloper.spdecode.parity

import org.json.JSONObject
/** Simeli .sut: nibble outer AES-CBC under SimeliFamilyForLifeTime plus
 * 11 inner independently encrypted Base64 AES-CBC values under sut password.
 */
object SutPort {
    private val p=LegacyPortPrimitives
    private const val INNER_PASSWORD="new#Pa\$\$wd#4#Maky,sim?2024tech&(.);#@980well*..smk.now"
    private val REQUIRED=listOf("UDPServerIP","ServerIP","Payload","Bug","SNI",
        "ServerUser","UDPServerUser","UDPServerPass","chaveKey","serverNameKey","dnsKey")
    private val OPTIONAL=listOf("TunnelType","isMsg","Message","HardwareID","Remind","Exp","mExp")
    fun decode(input:ByteArray):String?=p.safeDecode {
        val obj=XtpRoyReferencePort.open(input,"SimeliFamilyForLifeTime")
        val key=p.sha256(INNER_PASSWORD.toByteArray(Charsets.UTF_8))
        val fields=buildString {
            for(name in REQUIRED){
                val decrypted=p.utf8(p.cbc(p.b64(obj.getString(name)),key,ByteArray(16)))
                append("│[۞] [").append(name).append("]: ").append(decrypted).append('\n')
            }
            for(name in OPTIONAL){
                if(obj.has(name)&&!obj.isNull(name))
                    append("│[۞] [").append(name).append("]: ")
                        .append(p.pythonValue(obj.get(name))).append('\n')
            }
        }
        p.header("(.sut)",leadingLine=true)+"\n"+fields+p.footer()
    }
}

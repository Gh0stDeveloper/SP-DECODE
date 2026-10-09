package com.ghostdeveloper.spdecode.parity

/** .sksrv: own PBKDF2-SHA256 password + authenticated AES-GCM/XML. */
object SksrvPort {
    private const val PASSWORD = "6pq8YieK$8D2kT4a6Pizv3i56nWi"

    fun decode(input: ByteArray): String? = LegacyPortPrimitives.safeDecode {
        val p = LegacyPortPrimitives
        val xml = p.dotGcm(input, PASSWORD)
        // Preserve XML declaration filtering and original multiline format.
        val output = StringBuilder()
        for (line in xml.split('\n')) {
            val trimmed = line.trim()
            if (listOf("</properties>", "<?xml", "<!DOCTYPE", "<properties>")
                    .any { trimmed.startsWith(it) }) continue
            if ("<entry" in line && "{" in line && "}" in line) {
                output.append(line).append('\n')
            } else if ("<entry" in line) {
                output.append(p.simpleEntries(trimmed))
            } else if ("Arquivo de Configuração" !in line) {
                val filtered = line.replace("<comment/>", "").replace("</entry>", "")
                if (filtered.isNotEmpty()) output.append(filtered).append('\n')
            }
        }
        require(output.isNotEmpty())
        p.header("", leadingLine = true) + "\n" + output + p.footer()
    }
}

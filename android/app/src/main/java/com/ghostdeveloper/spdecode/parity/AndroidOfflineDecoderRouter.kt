package com.ghostdeveloper.spdecode.parity

import android.content.Context

/**
 * Deterministic offline Android reference dispatcher.
 *
 * A suffix maps to exactly one original decoder. No fallback to unrelated
 * cryptographic keys, no key brute forcing, no networking or subprocess.
 * Not exposed to users until the SAF/import UI and vendor validation gates.
 */
object AndroidOfflineDecoderRouter {
    fun decode(context: Context, filename: String, input: ByteArray): String? {
        if (input.isEmpty() || input.size > LegacyPortPrimitives.MAX_INPUT) return null
        val format = AndroidDecoderCatalog.detect(filename, AndroidDecoderCatalog.read(context))
            ?: return null
        if (format.portStatus == "not_implemented") return null
        return when (format.suffix) {
            "v2" -> V2RayReferencePort.decode(input)
            "tls" -> TlsReferencePort.decode(input)
            "phc" -> PhcPort.decode(input)
            "mina" -> MinaPort.decode(input)
            "vpnlite" -> VpnLitePort.decode(input)
            "cloudy" -> CloudyPort.decode(input)
            "mij" -> MijPort.decode(input)
            "fnnetwork" -> FnNetworkPort.decode(input)
            "uwu" -> UwuPort.decode(input)
            "sksrv" -> SksrvPort.decode(input)
            "maya" -> MayaPort.decode(input)
            "xui" -> XuiPort.decode(input)
            "at" -> AtPort.decode(input)
            "nm" -> NmPort.decode(input)
            "ost" -> OstPort.decode(input)
            "sbr" -> SbrPort.decode(input)
            "pcx" -> PcxPort.decode(input)
            "nt" -> NtPort.decode(input)
            "pb" -> PbPort.decode(input)
            "aro" -> AroPort.decode(input)
            "ipt" -> IptPort.decode(input)
            "gold" -> GoldPort.decode(input)
            else -> null
        }
    }
}

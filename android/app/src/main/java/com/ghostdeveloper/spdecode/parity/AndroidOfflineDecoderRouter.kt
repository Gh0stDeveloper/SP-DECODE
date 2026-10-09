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
        if (input.isEmpty() || input.size > (if (filename.endsWith(".lnk", ignoreCase=true)) LinkLayerPort.MAX_INPUT else LegacyPortPrimitives.MAX_INPUT)) return null
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
            "agn" -> AgnPort.decode(input)
            "cly" -> ClyPort.decode(input)
            "fɴ" -> FnLegacyPort.decode(input)
            "jvc" -> JvcPort.decode(input)
            "jvi" -> JviPort.decode(input)
            "v2i" -> V2iPort.decode(input)
            "sksrv.png" -> SksrvPngPort.decode(input)
            "xscks" -> XscksPort.decode(input)
            "mrc" -> MrcPort.decode(input)
            "mtl" -> MtlPort.decode(input)
            "jez" -> JezPort.decode(input)
            "hrt" -> HrtPort.decode(input)
            "ziv" -> ZivPort.decode(input)
            "epro" -> EproPort.decode(context,input)
            "npv2" -> Npv2Port.decode(context,input)
            "rez" -> RezPort.decode(input)
            "rezl" -> RezlPort.decode(input)
            "tvt" -> TvtPort.decode(input)
            "stk" -> StkPort.decode(input)
            "xtp" -> XtpPort.decode(input)
            "roy" -> RoyPort.decode(input)
            "sksplus" -> SksplusPort.decode(input)
            "sks" -> SksPort.decode(input)
            "sut" -> SutPort.decode(input)
            "tnl" -> TnlPort.decode(input)
            "ssh" -> SshPort.decode(input)
            "ht" -> HtPort.decode(context,input)
            "htb" -> HtbPort.decode(context,input)
            "hat" -> HatPort.decode(context,input)
            "ehil" -> EhilPort.decode(input)
            "dark" -> DarkPort.decode(input)
            "ehi" -> EhiPort.decode(input)
            "npv4" -> Npv4Port.decode(context,input)
            "npvt" -> NpvtPort.decode(context,input)
            "sip" -> SipPort.decode(input)
            "lnk" -> LinkLayerPort.decode(input)
            "ssc" -> SscPort.decode(input)
            "hc" -> HcPort.decode(context,input) ?: HcHccfgPort.decode(input)
            else -> null
        }
    }
}

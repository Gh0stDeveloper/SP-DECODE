package com.ghostdeveloper.spdecode

import android.content.Context
import com.ghostdeveloper.spdecode.parity.NurTunnelPort
import com.ghostdeveloper.spdecode.parity.SecureAssetVault
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Explicit, foreground-only NUR TUNNEL server catalog fetch.
 * The catalog is authenticated by the native offline decoder before it is shown.
 * No scheduled update, no server API, no fallback to plaintext or to .solid.
 */
internal object NurTunnelServerCatalog {
    private const val ENDPOINT_ASSET = "nur_tunnel_server_endpoint.json"
    private const val TIMEOUT_MS = 15000

    fun defaultUrl(context:Context):String {
        val document=JSONObject(SecureAssetVault.readText(context, ENDPOINT_ASSET))
        val endpoint=document.getString("catalogUrl")
        val url=URL(endpoint)
        require(url.protocol=="https" && url.host.isNotBlank() &&
            url.userInfo==null && url.port in -1..65535) {
            "Invalid protected NUR catalog endpoint"
        }
        return endpoint
    }

    fun download(urlText:String):ByteArray {
        require(urlText.length in 8..2048) { "Invalid URL length" }
        val url = URL(urlText.trim())
        require(url.protocol == "https" && !url.host.isNullOrBlank() &&
            url.userInfo == null && url.port in -1..65535) {
            "Use a direct HTTPS catalog URL without embedded credentials"
        }
        val connection=(url.openConnection() as HttpsURLConnection)
        try {
            connection.instanceFollowRedirects=false
            connection.connectTimeout=TIMEOUT_MS
            connection.readTimeout=TIMEOUT_MS
            connection.setRequestProperty("User-Agent","NUR TUNNEL VPN")
            connection.setRequestProperty("Accept-Encoding","identity")
            connection.requestMethod="GET"
            if(connection.responseCode!=200)throw IOException("NUR catalog HTTP status")
            val result=ByteArrayOutputStream()
            connection.inputStream.use { stream ->
                val chunk=ByteArray(8192)
                while(true) {
                    val amount=stream.read(chunk)
                    if(amount<0)break
                    if(result.size()+amount>NurTunnelPort.MAX_INPUT)throw IOException("Catalog too large")
                    result.write(chunk,0,amount)
                }
            }
            return result.toByteArray()
        } finally {
            connection.disconnect()
        }
    }

    fun decodeDownloaded(context:Context,data:ByteArray):String =
        NurTunnelPort.decodeCatalog(context,data)
            ?: throw IOException("NUR catalog authentication or format failed")
}

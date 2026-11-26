package diw.wallet.app.android

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import diw.wallet.app.res.Res
import diw.wallet.app.res.lan_permission
import diw.wallet.app.tr
import diw.wallet.core.document.sign.FetchReply
import diw.wallet.core.profile.bonds.BondsLanLink
import diw.wallet.core.profile.bonds.LanInterface
import okhttp3.Dns
import okhttp3.OkHttpClient
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import kotlin.time.Duration

/**
 * Android 17 (API 37) asks apps that target it for ACCESS_LOCAL_NETWORK (in the Nearby devices group) before any
 * socket to a private address: LAN age proofs, zkTLS and zkPassport on the local network, and OpenID4VP verification
 * on the local network all go through a [BondsLanLink]; plain HTTP to a local server goes through [guard]. Without
 * the permission the system drops the packets, so a listener would wait for nothing and a post would time out; this
 * asks for it and stops the exchange with a reason.
 */
class LocalNetworkGate(private val context: Context, private val activity: () -> Activity?) {
    /** Whether this device needs the permission and does not have it yet. */
    fun missing(): Boolean = Build.VERSION.SDK_INT >= ANDROID_17 &&
        context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED

    /** Null when local network traffic is allowed; otherwise asks for the permission and returns what to tell people. */
    fun unavailableReason(): String? {
        if (!missing()) return null
        activity()?.let { a -> a.runOnUiThread { a.requestPermissions(arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK), REQUEST) } }
        return tr(Res.string.lan_permission)
    }

    fun check() {
        unavailableReason()?.let { throw LocalNetworkPermissionException(it) }
    }

    /**
     * HTTP through [builder] checks the permission before it reaches a local address: a literal private host before
     * the call, a name once it resolves to one. Loopback is not local network traffic and stays allowed.
     */
    fun guard(builder: OkHttpClient.Builder) {
        builder.addInterceptor { chain ->
            literal(chain.request().url.host)?.let { if (isLocal(it)) check() }
            chain.proceed(chain.request())
        }
        builder.dns { host -> Dns.SYSTEM.lookup(host).also { addresses -> if (addresses.any(::isLocal)) check() } }
    }

    /** Checks the permission when [address] is on a local network; other addresses pass. */
    fun checkAddress(address: InetAddress) {
        if (isLocal(address)) check()
    }

    /** [link] with the permission checked first: no addresses (and a permission prompt) while it is missing. */
    fun wrap(link: BondsLanLink): BondsLanLink = object : BondsLanLink {
        override fun localInterfaces(): List<LanInterface> = if (unavailableReason() != null) emptyList() else link.localInterfaces()

        override suspend fun serve(
            addresses: List<String>,
            path: String,
            maxPayload: Int,
            onListening: (urls: List<String>) -> Unit,
            get: (suspend (target: String) -> Pair<String, ByteArray>?)?,
            answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
        ): ByteArray {
            check()
            return link.serve(addresses, path, maxPayload, onListening, get, answer)
        }

        override suspend fun post(url: String, body: ByteArray, timeout: Duration): Pair<Int, String> {
            check()
            return link.post(url, body, timeout)
        }

        override suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?, timeout: Duration): FetchReply {
            check()
            return link.exchange(url, body, contentType, accept, timeout)
        }

        override fun preferred(urls: List<String>): List<String> = link.preferred(urls)
    }

    companion object {
        const val ANDROID_17 = 37
        const val REQUEST = 7303

        /** Private (RFC 1918), link-local, unique local IPv6 (fc00::/7) and multicast addresses. */
        fun isLocal(address: InetAddress): Boolean =
            address.isSiteLocalAddress || address.isLinkLocalAddress || address.isMulticastAddress ||
                (address is Inet6Address && (address.address[0].toInt() and 0xfe) == 0xfc)

        /** [host] as an address when it is an IP literal; names are left to the resolver. */
        private fun literal(host: String): InetAddress? {
            val bare = host.removePrefix("[").removeSuffix("]")
            val ip = bare.isNotEmpty() && (':' in bare || bare.all { it.isDigit() || it == '.' })
            return if (ip) runCatching { InetAddress.getByName(bare) }.getOrNull() else null
        }
    }
}

/** A local network exchange stopped because Android 17 has not granted ACCESS_LOCAL_NETWORK yet. */
class LocalNetworkPermissionException(message: String) : IOException(message)

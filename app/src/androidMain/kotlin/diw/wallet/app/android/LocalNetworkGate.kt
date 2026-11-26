package diw.wallet.app.android

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Looper
import diw.wallet.app.res.Res
import diw.wallet.app.res.lan_permission
import diw.wallet.app.res.lan_permission_settings
import diw.wallet.app.tr
import diw.wallet.core.document.sign.FetchReply
import diw.wallet.core.profile.bonds.BondsLanLink
import diw.wallet.core.profile.bonds.LanInterface
import kotlinx.coroutines.future.await
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Dns
import okhttp3.OkHttpClient
import java.io.IOException
import java.io.InterruptedIOException
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Android 17 (API 37) asks apps that target it for ACCESS_LOCAL_NETWORK (in the Nearby devices group) before any
 * socket to a private address: LAN age proofs, zkTLS and zkPassport on the local network, and OpenID4VP verification
 * on the local network all go through a [BondsLanLink]; plain HTTP to a local server goes through [guard]. Without
 * the permission the system drops the packets, so a listener would wait for nothing and a post would time out.
 *
 * The request waits for the person's answer instead of failing at once: a grant goes on with the exchange that asked,
 * a refusal or a dismissed dialog (Back, a tap outside) stops it with a reason, and a refusal the system will not ask
 * about again points to the app's settings. One dialog serves every exchange waiting at the same time; leaving the
 * screen cancels the wait and leaves the dialog's answer for the next try.
 */
class LocalNetworkGate(private val context: Context, private val activity: () -> Activity?) {
    private val lock = Any()
    private var pending: CompletableFuture<Boolean>? = null

    /** The last answer was a refusal the system will not show the dialog for again. */
    @Volatile private var refusedForGood = false

    /** Whether this device needs the permission and does not have it yet. */
    fun missing(): Boolean = Build.VERSION.SDK_INT >= ANDROID_17 &&
        context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED

    private fun reason(): String = tr(if (refusedForGood) Res.string.lan_permission_settings else Res.string.lan_permission)

    /** The dialog's answer, asking when no dialog is open; null when no activity is in the foreground to ask from. */
    private fun ask(): CompletableFuture<Boolean>? = synchronized(lock) {
        pending?.let { return it }
        val a = activity()?.takeIf { !it.isFinishing && !it.isDestroyed } ?: return null
        CompletableFuture<Boolean>().also { answer ->
            pending = answer
            a.runOnUiThread { a.requestPermissions(arrayOf(Manifest.permission.ACCESS_LOCAL_NETWORK), REQUEST) }
        }
    }

    /** Drops [answer] after a wait gave up, so the next try asks again rather than waiting on a dialog long gone. */
    private fun forget(answer: CompletableFuture<Boolean>) = synchronized(lock) {
        if (pending === answer) pending = null
    }

    /**
     * The dialog closed: [granted] is false for a refusal and for a dialog dismissed without an answer ([answered]
     * false, which says nothing about later dialogs). [a] is the activity that received it; while the dialog shows,
     * the activity is paused and no longer the one in the foreground.
     */
    fun onResult(a: Activity, granted: Boolean, answered: Boolean = true) {
        if (granted) refusedForGood = false
        else if (answered && Build.VERSION.SDK_INT >= ANDROID_17) {
            refusedForGood = !a.shouldShowRequestPermissionRationale(Manifest.permission.ACCESS_LOCAL_NETWORK)
        }
        val answer = synchronized(lock) { pending.also { pending = null } }
        answer?.complete(granted && !missing())
    }

    /** Null when local network traffic is allowed, asking and waiting for the answer first; otherwise why not. */
    suspend fun prepare(wait: Duration = WAIT): String? {
        if (!missing()) return null
        val answer = ask() ?: return reason()
        val granted = withTimeoutOrNull(wait) { answer.await() }
        if (granted == null) forget(answer)
        return if (granted == true && !missing()) null else reason()
    }

    /**
     * The blocking form of [prepare] for socket and resolver callbacks: waits for the dialog on a background thread,
     * and throws [LocalNetworkPermissionException] when the permission is still missing.
     */
    fun check() {
        if (!missing()) return
        val onMain = Looper.myLooper() == Looper.getMainLooper()
        val answer = if (onMain) null else ask()
        val granted = answer?.let {
            try {
                it.get(WAIT.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                forget(it)
                false
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw InterruptedIOException(e.message)
            }
        } ?: false
        if (!granted || missing()) throw LocalNetworkPermissionException(reason())
    }

    /** Checks the permission when [address] is on a local network; other addresses pass. */
    fun checkAddress(address: InetAddress) {
        if (isLocal(address)) check()
    }

    /**
     * HTTP through [builder] checks the permission before it reaches a local address: a literal private host before
     * the call, a name once it resolves to one. Loopback is not local network traffic and stays allowed.
     */
    fun guard(builder: OkHttpClient.Builder) {
        builder.addInterceptor { chain ->
            literal(chain.request().url.host)?.let(::checkAddress)
            chain.proceed(chain.request())
        }
        builder.dns { host -> Dns.SYSTEM.lookup(host).also { addresses -> addresses.firstOrNull(::isLocal)?.let(::checkAddress) } }
    }

    /** [link] with the permission asked for first: no addresses while it is missing, and [BondsLanLink.prepare] asks. */
    fun wrap(link: BondsLanLink): BondsLanLink = object : BondsLanLink {
        override fun localInterfaces(): List<LanInterface> = if (missing()) emptyList() else link.localInterfaces()

        override suspend fun prepare(): String? = this@LocalNetworkGate.prepare() ?: link.prepare()

        private suspend fun allowed() {
            this@LocalNetworkGate.prepare()?.let { throw LocalNetworkPermissionException(it) }
        }

        override suspend fun serve(
            addresses: List<String>,
            path: String,
            maxPayload: Int,
            onListening: (urls: List<String>) -> Unit,
            get: (suspend (target: String) -> Pair<String, ByteArray>?)?,
            answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
        ): ByteArray {
            allowed()
            return link.serve(addresses, path, maxPayload, onListening, get, answer)
        }

        override suspend fun post(url: String, body: ByteArray, timeout: Duration): Pair<Int, String> {
            allowed()
            return link.post(url, body, timeout)
        }

        override suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?, timeout: Duration): FetchReply {
            allowed()
            return link.exchange(url, body, contentType, accept, timeout)
        }

        override fun preferred(urls: List<String>): List<String> = link.preferred(urls)
    }

    companion object {
        const val ANDROID_17 = 37
        const val REQUEST = 7303

        /** How long an exchange waits for the dialog before it gives up with the reason. */
        val WAIT = 3.minutes

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

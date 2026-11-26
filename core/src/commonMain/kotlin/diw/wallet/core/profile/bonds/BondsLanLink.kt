package diw.wallet.core.profile.bonds

import diw.wallet.core.i18n.ct
import kotlinx.coroutines.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Age proofs and presentations over the local network, this wallet's extension: the verifier listens on its Wi-Fi or
 * hotspot addresses and its request QR names them as plain http URLs; the holder posts to the one on its own network
 * and reads the reply. A device with several network cards (Wi-Fi and hotspot at once, Ethernet and Wi-Fi, virtual
 * adapters) listens on all of them, since it cannot know which one the other phone shares.
 */
interface BondsLanLink {
    /** This device's private IPv4 addresses another phone could reach, best first; empty when there is none. */
    fun localAddresses(): List<String> = localInterfaces().map { it.address }

    /** The same addresses with the network card each belongs to, for the screens and technical details. */
    fun localInterfaces(): List<LanInterface>

    /**
     * Asks for what the platform needs before local network use (the Android 17 local network permission) and waits
     * for the answer: null when the local network can be used, otherwise why not, to show in place of "no network".
     * Call it before [localInterfaces]; cancelling stops waiting and leaves nothing behind.
     */
    suspend fun prepare(): String? = null

    /**
     * Listens on each of [addresses] at a free port and answers POSTs to [path]: [answer] turns a body into the JSON
     * reply and says whether the exchange is over. [onListening] receives the URLs to put in the request, in the order
     * of [addresses] (an address that cannot be bound is left out). Returns the body that ended the exchange; cancel
     * to stop listening. With [get], GET requests are answered too: it maps the request target to a content type and
     * body, or null for 404 (the OpenID4VP request object of a wallet verifying on the local network).
     */
    suspend fun serve(
        addresses: List<String>,
        path: String,
        maxPayload: Int,
        onListening: (urls: List<String>) -> Unit,
        get: (suspend (target: String) -> Pair<String, ByteArray>?)? = null,
        answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
    ): ByteArray

    /** Posts [body] as JSON to a LAN [url] and returns the status and reply text; the verifier checks before it answers. */
    suspend fun post(url: String, body: ByteArray, timeout: Duration): Pair<Int, String>

    /**
     * One clear-text exchange with a LAN [url] (a GET, or a POST of [body] as [contentType]) over the network the
     * address belongs to: the OpenID4VP request and response of a wallet verifying on the local network.
     */
    suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?, timeout: Duration): diw.wallet.core.document.sign.FetchReply

    /** [urls] reordered so those on a subnet of this device come first; the rest keep their order. */
    fun preferred(urls: List<String>): List<String> = urls
}

/** A local address and its network card: [label] names the card for people (Wi-Fi, hotspot, Ethernet or the system's name). */
data class LanInterface(val address: String, val name: String, val label: String, val kind: Kind) {
    enum class Kind(private val titleKey: String) {
        WIFI("Wi-Fi"), HOTSPOT("core_lan_hotspot"), ETHERNET("core_lan_ethernet"), OTHER("core_lan_other");

        val title: String get() = if (titleKey.startsWith("core_")) ct(titleKey) else titleKey
    }
}

/** Which networks a listener is on, for people: "Wi-Fi、熱點". */
fun List<LanInterface>.networks(): String = map { it.kind.title }.distinct().joinToString(ct("core_sep_list")).ifEmpty { ct("core_lan_local") }

/** One line per address: "192.168.1.5（Wi-Fi，Intel(R) Wi-Fi 6 AX201）". */
fun List<LanInterface>.details(): List<String> = map { i ->
    i.address + ct("core_paren_open_space") + listOf(i.kind.title, i.label).distinct().joinToString(ct("core_sep_comma")) + ct("core_paren_close")
}

/** The most addresses a request carries: enough for Wi-Fi, hotspot and a wired card, small enough for the QR. */
const val MAX_LAN_URLS = 4

/**
 * Posts [body] to the first of [urls] that answers, trying those on this device's own subnets first. Only a failure to
 * get any reply moves on to the next URL; an HTTP reply, even a refusal, is the verifier's answer.
 */
suspend fun BondsLanLink.postFirst(urls: List<String>, body: ByteArray, timeout: Duration): Pair<Int, String> =
    postFirstFrom(urls, body, timeout).let { (status, text, _) -> status to text }

/** [postFirst], also returning the URL that answered. */
suspend fun BondsLanLink.postFirstFrom(urls: List<String>, body: ByteArray, timeout: Duration): Triple<Int, String, String> {
    if (urls.isEmpty()) throw IllegalArgumentException("No address to post to")
    val ordered = preferred(urls)
    var failure: Exception? = null
    for ((i, url) in ordered.withIndex()) {
        // The first address is most likely right; an unreachable one should not use up the whole wait.
        val wait = if (i == 0) timeout else minOf(timeout, OTHER_ADDRESS_TIMEOUT)
        try {
            val (status, text) = post(url, body, wait)
            return Triple(status, text, url)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            failure = e
        }
    }
    throw failure!!
}

private val OTHER_ADDRESS_TIMEOUT = 8.seconds

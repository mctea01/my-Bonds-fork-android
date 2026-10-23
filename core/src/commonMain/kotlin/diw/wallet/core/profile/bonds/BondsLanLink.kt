package diw.wallet.core.profile.bonds

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
     * Listens on each of [addresses] at a free port and answers POSTs to [path]: [answer] turns a body into the JSON
     * reply and says whether the exchange is over. [onListening] receives the URLs to put in the request, in the order
     * of [addresses] (an address that cannot be bound is left out). Returns the body that ended the exchange; cancel
     * to stop listening.
     */
    suspend fun serve(
        addresses: List<String>,
        path: String,
        maxPayload: Int,
        onListening: (urls: List<String>) -> Unit,
        answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
    ): ByteArray

    /** Posts [body] as JSON to a LAN [url] and returns the status and reply text; the verifier checks before it answers. */
    suspend fun post(url: String, body: ByteArray, timeout: Duration): Pair<Int, String>

    /** [urls] reordered so those on a subnet of this device come first; the rest keep their order. */
    fun preferred(urls: List<String>): List<String> = urls
}

/** A local address and its network card: [label] names the card for people (Wi-Fi, hotspot, Ethernet or the system's name). */
data class LanInterface(val address: String, val name: String, val label: String, val kind: Kind) {
    enum class Kind(val title: String) { WIFI("Wi-Fi"), HOTSPOT("熱點"), ETHERNET("有線網路"), OTHER("其他網路") }
}

/** Which networks a listener is on, for people: "Wi-Fi、熱點". */
fun List<LanInterface>.networks(): String = map { it.kind.title }.distinct().joinToString("、").ifEmpty { "區網" }

/** One line per address: "192.168.1.5（Wi-Fi，Intel(R) Wi-Fi 6 AX201）". */
fun List<LanInterface>.details(): List<String> = map { i ->
    i.address + "（" + listOf(i.kind.title, i.label).distinct().joinToString("，") + "）"
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

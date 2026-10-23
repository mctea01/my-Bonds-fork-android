package diw.wallet.core.profile.bonds

import kotlin.time.Duration

/**
 * Age proofs over the local network, this wallet's extension: the verifier listens on its own Wi-Fi or hotspot
 * address and its request QR names that address as a plain http response URL; the holder posts the package there and
 * reads the verdict from the reply. Clear text is acceptable because the package carries no claim value and the proofs
 * are bound to the request's nonce; anyone on the same network sees what the verifier sees.
 */
interface BondsLanLink {
    /** This device's private IPv4 addresses on the local network, best first; empty when there is none. */
    fun localAddresses(): List<String>

    /**
     * Listens on [address] at a free port and answers POSTs to [path]: [answer] turns a body into the JSON reply and
     * says whether the exchange is over. [onListening] receives the URL to put in the request. Returns the body that
     * ended the exchange; cancel to stop listening.
     */
    suspend fun serve(
        address: String,
        path: String,
        maxPayload: Int,
        onListening: (url: String) -> Unit,
        answer: suspend (body: ByteArray) -> Pair<ByteArray, Boolean>,
    ): ByteArray

    /** Posts [body] as JSON to a LAN [url] and returns the status and reply text; the verifier checks before it answers. */
    suspend fun post(url: String, body: ByteArray, timeout: Duration): Pair<Int, String>
}

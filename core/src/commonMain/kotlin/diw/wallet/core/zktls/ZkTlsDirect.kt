package diw.wallet.core.zktls

import diw.wallet.core.util.ProtocolException

/**
 * The holder's own query of a verification page, without a verifier: this device makes the planner's exact request
 * over an ordinary TLS connection and reads the page with the profile's rules. It proves nothing to anyone else; what
 * it read can only be kept as this wallet's own statement (WebProofCredentials.VCT_RECORD, a device record, not a
 * zero-knowledge proof). The inputs stay in the request bytes and are never kept.
 */
expect object ZkTlsDirect {
    /**
     * Sends [request] to the site of [profile] and returns the whole response. The site's certificate must chain to a
     * root of the platform or to one of [extraRoots] (DER), and its name must match the profile's host.
     */
    suspend fun fetch(profile: ZkTlsProfile, request: ByteArray, extraRoots: List<ByteArray>): ZkTlsFetched
}

/** A response read over this device's own TLS connection. */
class ZkTlsFetched(
    val received: ByteArray,
    val certChainDer: List<ByteArray>,
    val cipherSuite: String?,
    val protocol: String?,
    val time: Long,
)

/** Reading a fetched page the way a verifier would: only the parts the planner reveals, with the same rules. */
object ZkTlsDirectRead {
    fun outcome(profile: ZkTlsProfile, request: ByteArray, fetched: ZkTlsFetched, purpose: String): ZkTlsOutcome {
        if (fetched.received.size > profile.limits.maxRecv) {
            throw ProtocolException("invalid_response", "網站回應超過查驗頁描述檔的上限（${profile.limits.maxRecv} 位元組）")
        }
        val fields = profile.fields.map { it.name }
        val plan = ZkTlsPlanner.receivedReveal(profile, fields, fetched.received)
        val seen = ZkTlsHolder.masked(profile.host, fetched.certChainDer, fetched.time, request, fetched.received,
            ZkTlsPlanner.sentReveal(profile, request), plan.received)
        // A request object only names the fields to read; nothing of it leaves this device.
        val session = ZkTlsSessionRequest.create(listOf(ZkTlsTransport.Lan("192.168.0.1", 1)), ByteArray(32), profile, fields, purpose)
        return ZkTlsCheck.check(session, profile, seen)
    }
}

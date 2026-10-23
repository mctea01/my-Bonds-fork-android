package diw.wallet.core.zktls

import diw.wallet.core.zk.ZkResult

/**
 * TLSNotary between a holder and a verifier (p4-zkp.md section 5.2). Both run on Android and desktops; the channel
 * is Noise keyed to the request's `ck`, so the transports only carry ciphertext.
 */
interface ZkTlsEngine {
    /**
     * Holder: makes [request] (the planner's bytes for the profile) to the profile's site through the verifier of
     * [session], over the first transport that answers, and reveals only what the planner allows.
     */
    suspend fun prove(
        session: ZkTlsSessionRequest.Verified,
        profile: ZkTlsProfile,
        request: ByteArray,
        extraRoots: List<ByteArray>,
        step: (String) -> Unit,
    ): ZkResult<ZkTlsProved>

    /**
     * Verifier: a fresh X25519 key and listeners on the local network ([lan]) and on the relay at [relayUrl] (a ws or
     * wss base address). Throws when neither opens.
     */
    suspend fun open(lan: Boolean, relayUrl: String?): ZkTlsVerifierSession
}

/** One verifier session; [verify] can run once. */
interface ZkTlsVerifierSession {
    /** Where the holder reaches this session, for the request's `transport`. */
    val transports: List<ZkTlsTransport>

    /** The session's X25519 public key, the request's `ck`. */
    val publicKey: ByteArray

    /**
     * Waits for the holder of the signed request [jws] ([request] is its payload) and verifies the proof: the
     * transcript with only the revealed bytes. [waiting] reports progress. The session is closed afterwards.
     */
    suspend fun verify(
        jws: String,
        request: ZkTlsSessionRequest,
        profile: ZkTlsProfile,
        extraRoots: List<ByteArray>,
        waiting: (String) -> Unit,
    ): ZkResult<ZkTlsSeen>

    fun close()
}

/**
 * The holder's end of a session: the site's identity, and its own reading of what it revealed with the verifier's
 * rules ([outcome]), which is what the verifier will show.
 */
data class ZkTlsProved(
    val serverName: String,
    val certChainDer: List<ByteArray>,
    val time: Long,
    val cipherSuite: String,
    val plan: ZkTlsPlanner.Plan,
    val outcome: ZkTlsOutcome,
    val transport: ZkTlsTransport,
)

/** Holder-side helpers shared by every engine. */
object ZkTlsHolder {
    /** The transcript as the verifier receives it: only the [sent] and [received] ranges, other bytes zero. */
    fun masked(
        serverName: String,
        chain: List<ByteArray>,
        time: Long,
        sent: ByteArray,
        received: ByteArray,
        sentMask: List<ZkTlsRange>,
        receivedMask: List<ZkTlsRange>,
    ): ZkTlsSeen {
        fun keep(bytes: ByteArray, mask: List<ZkTlsRange>): ByteArray {
            val out = ByteArray(bytes.size)
            mask.forEach { bytes.copyInto(out, it.start, it.start, minOf(it.end, bytes.size)) }
            return out
        }
        return ZkTlsSeen(serverName, chain, time, keep(sent, sentMask), keep(received, receivedMask), sentMask, receivedMask)
    }

    /** Transports in the order the holder tries them: the local network, then a relay, then a verifier server. */
    fun ordered(transports: List<ZkTlsTransport>): List<ZkTlsTransport> = transports.sortedBy {
        when (it) {
            is ZkTlsTransport.Lan -> 0
            is ZkTlsTransport.Relay -> 1
            is ZkTlsTransport.Wss -> 2
        }
    }
}

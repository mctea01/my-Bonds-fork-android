package diw.wallet.core.zktls

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkTlsChannel
import diw.wallet.core.zk.native.bindings.ZkTlsReceiptIssuer
import diw.wallet.core.zk.native.bindings.ZkTlsVerified
import diw.wallet.core.zk.native.bindings.zktlsVerify
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.SecureRandom

/** A verifier's X25519 key for one session; the public half goes in the request as `ck`. */
class ZkTlsKey {
    private val key = X25519PrivateKeyParameters(SecureRandom())

    val publicKey: ByteArray = key.generatePublicKey().encoded

    internal val privateKey: ByteArray get() = key.encoded
}

/** The verifier's side over a channel a holder already opened; shared by the app and the test server. */
object ZkTlsVerification {
    /**
     * Runs TLSNotary as verifier for [jws] on [channel] and returns the transcript with only the revealed bytes. In
     * proxy mode this side connects to the profile's site itself. A holder that asks for a receipt gets what
     * [receipts] signs; a failure there only means no receipt. Throws ZkException on failure.
     */
    suspend fun verify(
        channel: ZkTlsChannel,
        jws: String,
        request: ZkTlsSessionRequest,
        profile: ZkTlsProfile,
        key: ZkTlsKey,
        extraRoots: List<ByteArray>,
        receipts: ZkTlsReceipts? = null,
    ): ZkResult<ZkTlsSeen> {
        // Runs on the native worker thread, which waits for the answer.
        val issuer = object : ZkTlsReceiptIssuer {
            override fun issue(verified: ZkTlsVerified, binding: ByteArray): ByteArray {
                val jwk = WebProofCredentials.bindingJwk(binding) ?: return ByteArray(0)
                val r = receipts ?: return ByteArray(0)
                return runCatching { runBlocking { r.issue(seen(verified), jwk) } }.getOrNull()
                    ?.encodeToByteArray()?.takeIf { it.size <= WebProofCredentials.MAX_RECEIPT } ?: ByteArray(0)
            }
        }
        val v = cancellable(channel) { token ->
            zktlsVerify(
                channel, profile.host, profile.port.toUShort(), profile.limits.maxSent.toUInt(), profile.limits.maxRecv.toUInt(),
                request.mode, token, ZkTlsSessionRequest.hash(jws), key.privateKey, extraRoots, issuer,
            )
        }
        return ZkResult.Ok(seen(v))
    }

    private fun seen(v: ZkTlsVerified): ZkTlsSeen {
        fun ranges(list: List<diw.wallet.core.zk.native.bindings.ZkRange>) = list.map { ZkTlsRange(it.start.toInt(), it.end.toInt()) }
        return ZkTlsSeen(v.serverName, v.certChainDer, v.time.toLong(), v.sent, v.received, ranges(v.sentMask), ranges(v.receivedMask))
    }
}

/**
 * Runs a blocking native call with a cancel token: cancelling the coroutine cancels the token and closes [channel],
 * which unblocks the native threads waiting on it.
 */
internal suspend fun <T> cancellable(channel: ZkTlsChannel, call: (ZkCancelToken) -> T): T = ZkCancelToken().use { token ->
    coroutineScope {
        val watcher = launch {
            try {
                awaitCancellation()
            } finally {
                token.cancel()
                channel.close()
            }
        }
        try {
            call(token)
        } finally {
            watcher.cancel()
        }
    }
}

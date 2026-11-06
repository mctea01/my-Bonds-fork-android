package diw.testservers.zktls

import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.ZkCancelToken
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.ZkRange
import diw.wallet.core.zk.native.bindings.ZkTlsChannel
import diw.wallet.core.zk.native.bindings.ZkTlsReceiptIssuer
import diw.wallet.core.zk.native.bindings.ZkTlsRequest
import diw.wallet.core.zk.native.bindings.ZkTlsReveal
import diw.wallet.core.zk.native.bindings.ZkTlsRevealChooser
import diw.wallet.core.zk.native.bindings.ZkTlsTranscript
import diw.wallet.core.zk.native.bindings.ZkTlsVerified
import diw.wallet.core.zk.native.bindings.zktlsProve
import diw.wallet.core.zk.native.bindings.zktlsVerify
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * WP5 acceptance on the desktop: a TLSNotary prover and verifier, joined by an in-memory byte channel that only
 * carries Noise ciphertext, prove a response of a local HTTPS target whose test CA both sides add to their roots.
 * The prover reveals the request line up to the path and the Host line, and status=OK in the response; the query
 * (a stand-in for private parameters) and the rest of the response reach the verifier as zero bytes.
 */
class ZkTlsLoopbackTest {
    private fun tlsnAvailable() {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged, "ZK native library not built")
        val directory = Files.createTempDirectory("diw-zk-native").toFile()
        val status = (ZkNative.load(directory) as? ZkResult.Ok)?.value
        assumeTrue(status != null && ZkBackend.TLSN in status.backends, "Native library built without tlsn")
    }

    @Test
    fun proxyMode() = loopback("proxy", chunked = false, bodySize = 24)

    @Test
    fun proxyModeChunkedResponse() = loopback("proxy", chunked = true, bodySize = 1024)

    @Test
    fun mpcMode() = loopback("mpc", chunked = false, bodySize = 24)

    /** A prover holding another verifier's Noise key gets nowhere, and neither side sees any transcript. */
    @Test
    fun wrongVerifierKeyFails() {
        tlsnAvailable()
        ZkTlsTarget().use { target ->
            val (prover, verifier) = InMemoryChannel.pair()
            val verifierKey = X25519PrivateKeyParameters(SecureRandom())
            val otherKey = X25519PrivateKeyParameters(SecureRandom())
            val hash = sha256("synthetic request JWS")
            val (proved, verified) = runBoth(
                { zktlsProve(prover, request(target, "proxy", 1024u), Chooser, ZkCancelToken(), hash, otherKey.generatePublicKey().encoded, listOf(target.caDer)) },
                { zktlsVerify(verifier, "localhost", target.port.toUShort(), 4096u, 1024u, "proxy", ZkCancelToken(), hash, verifierKey.encoded, listOf(target.caDer), Receipt) },
            )
            assertTrue(proved.isFailure && verified.isFailure)
            assertTrue(target.requests.isEmpty(), "the target is never contacted")
        }
    }

    /** The request hash is the Noise prologue: a prover answering another request is refused. */
    @Test
    fun otherRequestHashFails() {
        tlsnAvailable()
        ZkTlsTarget().use { target ->
            val (prover, verifier) = InMemoryChannel.pair()
            val key = X25519PrivateKeyParameters(SecureRandom())
            val (proved, verified) = runBoth(
                { zktlsProve(prover, request(target, "proxy", 1024u), Chooser, ZkCancelToken(), sha256("request A"), key.generatePublicKey().encoded, listOf(target.caDer)) },
                { zktlsVerify(verifier, "localhost", target.port.toUShort(), 4096u, 1024u, "proxy", ZkCancelToken(), sha256("request B"), key.encoded, listOf(target.caDer), Receipt) },
            )
            assertTrue(proved.isFailure && verified.isFailure)
        }
    }

    /** Without the test CA among its roots the verifier does not accept the target's certificate. */
    @Test
    fun untrustedServerCertificateFails() {
        tlsnAvailable()
        ZkTlsTarget().use { target ->
            val (prover, verifier) = InMemoryChannel.pair()
            val key = X25519PrivateKeyParameters(SecureRandom())
            val hash = sha256("synthetic request JWS")
            val (proved, verified) = runBoth(
                { zktlsProve(prover, request(target, "proxy", 1024u), Chooser, ZkCancelToken(), hash, key.generatePublicKey().encoded, listOf(target.caDer)) },
                { zktlsVerify(verifier, "localhost", target.port.toUShort(), 4096u, 1024u, "proxy", ZkCancelToken(), hash, key.encoded, emptyList(), Receipt) },
            )
            assertTrue(proved.isFailure && verified.isFailure)
        }
    }

    private fun loopback(mode: String, chunked: Boolean, bodySize: Int) {
        tlsnAvailable()
        ZkTlsTarget(bodySize, chunked).use { target ->
            val (proverChannel, verifierChannel) = InMemoryChannel.pair()
            val key = X25519PrivateKeyParameters(SecureRandom())
            val hash = sha256("synthetic request JWS")
            val maxRecv = (bodySize + 1024).toUInt()
            val (proved, verified) = runBoth(
                { zktlsProve(proverChannel, request(target, mode, maxRecv), Chooser, ZkCancelToken(), hash, key.generatePublicKey().encoded, listOf(target.caDer)) },
                { zktlsVerify(verifierChannel, "localhost", target.port.toUShort(), 4096u, maxRecv, mode, ZkCancelToken(), hash, key.encoded, listOf(target.caDer), Receipt) },
            )
            val transcript = proved.getOrThrow()
            val result = verified.getOrThrow()

            // The target really received the private query; the prover saw the whole response.
            assertTrue(target.requests.single().contains("secret=synthetic"))
            assertTrue(transcript.received.decodeToString().contains("status=OK"))
            assertEquals("localhost", result.serverName)
            assertContentEquals(target.leafDer, result.certChainDer.first())
            assertEquals("holder-key@localhost", transcript.receipt.decodeToString())

            val query = transcript.sent.indexOf('?'.code.toByte())
            assertTrue(query > 0)
            assertEquals(0, result.sent[query].toInt(), "the query stays hidden")
            assertZeroOutside(result.sent, result.sentMask)
            assertContentEquals(transcript.sent.copyOfRange(0, 10), result.sent.copyOfRange(0, 10))

            val revealed = result.receivedMask.single()
            assertEquals("status=OK", result.received.copyOfRange(revealed.start.toInt(), revealed.end.toInt()).decodeToString())
            assertZeroOutside(result.received, result.receivedMask)
            val commitment = result.commitments.single()
            assertEquals("SHA256", commitment.alg)
            assertEquals(32, commitment.digest.size)
            assertEquals(revealed, commitment.range)
        }
    }

    private fun assertZeroOutside(bytes: ByteArray, mask: List<ZkRange>) {
        bytes.forEachIndexed { i, b ->
            if (mask.none { i.toUInt() >= it.start && i.toUInt() < it.end }) assertEquals(0, b.toInt(), "byte $i is not revealed")
        }
    }

    private fun request(target: ZkTlsTarget, mode: String, maxRecv: UInt) = ZkTlsRequest(
        host = "localhost",
        port = target.port.toUShort(),
        request = ("GET /check?secret=synthetic HTTP/1.1\r\nHost: localhost:${target.port}\r\n" +
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encodeToByteArray(),
        maxSent = 4096u,
        maxRecv = maxRecv,
        mode = mode,
        binding = "holder-key".encodeToByteArray(),
    )

    /** Answers a receipt request with the binding and the verified server name, after the proof passed. */
    private object Receipt : ZkTlsReceiptIssuer {
        override fun issue(verified: ZkTlsVerified, binding: ByteArray): ByteArray =
            (binding.decodeToString() + "@" + verified.serverName).encodeToByteArray()
    }

    /** Reveals "GET /check", the Host line and status=OK, and commits to status=OK. */
    private object Chooser : ZkTlsRevealChooser {
        override fun choose(transcript: ZkTlsTranscript): ZkTlsReveal {
            val sent = transcript.sent
            val host = sent.find("Host: ".encodeToByteArray())
            val hostEnd = sent.find("\r\n".encodeToByteArray(), host) + 2
            val status = transcript.received.find("status=OK".encodeToByteArray())
            val ok = ZkRange(status.toUInt(), (status + 9).toUInt())
            return ZkTlsReveal(
                sent = listOf(ZkRange(0u, 10u), ZkRange(host.toUInt(), hostEnd.toUInt())),
                received = listOf(ok),
                commitSha256 = listOf(ok),
            )
        }
    }

    private fun sha256(text: String) = MessageDigest.getInstance("SHA-256").digest(text.encodeToByteArray())

    /** Runs both roles at once, as two devices would; a failure of one side closes nothing on the other by itself. */
    private fun runBoth(
        prover: () -> ZkTlsTranscript,
        verifier: () -> ZkTlsVerified,
    ): Pair<Result<ZkTlsTranscript>, Result<ZkTlsVerified>> {
        val pool = Executors.newFixedThreadPool(2)
        try {
            val p = pool.submit(Callable { runCatching(prover) })
            val v = pool.submit(Callable { runCatching(verifier) })
            return p.get(300, TimeUnit.SECONDS) to v.get(300, TimeUnit.SECONDS)
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * One end of an in-memory byte channel. Closing either end ends the channel for both after the bytes already
     * queued, so a peer blocked in receive is released, as a closed WebSocket would release it.
     */
    private class InMemoryChannel(
        private val inbound: LinkedBlockingQueue<ByteArray>,
        private val outbound: LinkedBlockingQueue<ByteArray>,
        private val closed: AtomicBoolean,
    ) : ZkTlsChannel {
        override fun send(data: ByteArray) {
            if (closed.get()) throw ZkException.Internal(900u)
            outbound.put(data.copyOf())
        }

        override fun receive(): ByteArray {
            val data = inbound.poll(240, TimeUnit.SECONDS) ?: throw ZkException.Internal(901u)
            if (data === END) {
                inbound.put(END)
                throw ZkException.Internal(902u)
            }
            return data
        }

        override fun close() {
            if (closed.compareAndSet(false, true)) {
                inbound.put(END)
                outbound.put(END)
            }
        }

        companion object {
            private val END = ByteArray(0)

            fun pair(): Pair<InMemoryChannel, InMemoryChannel> {
                val a = LinkedBlockingQueue<ByteArray>()
                val b = LinkedBlockingQueue<ByteArray>()
                val closed = AtomicBoolean(false)
                return InMemoryChannel(a, b, closed) to InMemoryChannel(b, a, closed)
            }
        }
    }
}

private fun ByteArray.find(needle: ByteArray, from: Int = 0): Int {
    for (i in from..size - needle.size) if (needle.indices.all { this[i + it] == needle[it] }) return i
    return -1
}

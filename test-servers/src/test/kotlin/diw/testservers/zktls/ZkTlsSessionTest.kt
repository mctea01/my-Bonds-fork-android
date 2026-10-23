package diw.testservers.zktls

import diw.testservers.TestPki
import diw.testservers.TestServers
import diw.wallet.core.did.DidResolver
import diw.wallet.core.zk.ZkBackend
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zktls.NativeZkTlsEngine
import diw.wallet.core.zktls.ZkTlsCheck
import diw.wallet.core.zktls.ZkTlsPlanner
import diw.wallet.core.zktls.ZkTlsProfiles
import diw.wallet.core.zktls.ZkTlsProved
import diw.wallet.core.zktls.ZkTlsSeen
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readBytes
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.multipaz.util.toBase64Url
import java.net.ServerSocket
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * zkTLS sessions end to end on one machine: the holder proves the synthetic record page through a verifier that is
 * the test server (wss), a device on the local network (TCP on 127.0.0.1, which the request rules accept as a private
 * address) or a device behind the relay. The relay itself is tested without the engine.
 */
class ZkTlsSessionTest {
    private val port = ServerSocket(0).use { it.localPort }
    private val base = "http://localhost:$port"
    private val insecure = setOf("localhost:$port")
    private lateinit var servers: TestServers
    private lateinit var server: io.ktor.server.engine.EmbeddedServer<*, *>
    private val http = HttpClient(Java)

    private fun tlsn(): Boolean {
        if (ZkNative::class.java.getResource("/zk/native") == null) return false
        val status = (ZkNative.load(Files.createTempDirectory("diw-zk-native").toFile()) as? ZkResult.Ok)?.value
        return status != null && ZkBackend.TLSN in status.backends
    }

    @BeforeTest
    fun start() = runBlocking {
        servers = TestServers(base, TestPki.create(), zkTls = { tlsn() }).init()
        server = servers.start(port, wait = false)
    }

    @AfterTest
    fun stop() {
        server.stop(100, 500)
        http.close()
    }

    private val inputs = mapOf("serial" to ZkTlsRecordPage.SERIAL, "code" to ZkTlsRecordPage.CODE)

    private fun engine(addresses: List<String> = emptyList()) = NativeZkTlsEngine(http, { addresses })

    private suspend fun holder(jws: String, values: Map<String, String> = inputs): ZkResult<ZkTlsProved> {
        val verified = ZkTlsSessionRequest.verify(jws, DidResolver(http), insecureHosts = insecure)
        val profile = ZkTlsProfiles.resolve(verified.request, allowInline = true)
        val request = ZkTlsPlanner.request(profile, values)
        return engine().prove(verified, profile, request, listOf(servers.recordPage.caDer)) {}
    }

    @Test
    fun serverVerifierOverWss() = runBlocking {
        assumeTrue(tlsn(), "Native library built without tlsn")
        val session = servers.zkTlsVerifier.create(ZkTlsRecordPage.PROFILE_ID, listOf("name", "date"), "入學查核", "proxy")
        val proved = holder(session.jws)
        assertTrue(proved is ZkResult.Ok, proved.toString())
        assertTrue(proved.value.outcome.passed)
        assertTrue(proved.value.transport is ZkTlsTransport.Wss)
        val state = withTimeout(30_000) {
            while (session.status == "verifying" || session.status == "waiting") delay(50)
            session.status
        }
        assertEquals("done", state, session.reason)
        val outcome = session.outcome!!
        assertTrue(outcome.passed)
        assertEquals(mapOf("name" to ZkTlsRecordPage.NAME, "date" to ZkTlsRecordPage.DATE), outcome.fields)
        // The site got the private query; a second holder on the same session is refused.
        assertTrue(servers.recordPage.requests.single().contains("serial=${ZkTlsRecordPage.SERIAL}"))
        assertTrue(holder(session.jws) is ZkResult.Failed)
    }

    @Test
    fun deviceVerifierOnTheLocalNetwork() = runBlocking {
        assumeTrue(tlsn(), "Native library built without tlsn")
        val seen = deviceSession(lan = true, relay = null, values = inputs)
        val text = seen.received.decodeToString()
        assertFalse(ZkTlsRecordPage.HIDDEN in text)
        assertFalse(ZkTlsRecordPage.SERIAL in seen.sent.decodeToString())
    }

    @Test
    fun deviceVerifierBehindTheRelay() = runBlocking {
        assumeTrue(tlsn(), "Native library built without tlsn")
        deviceSession(lan = false, relay = base, values = inputs)
        assertEquals(0, servers.zkTlsRelay.size)
    }

    @Test
    fun recordNotFound() = runBlocking {
        assumeTrue(tlsn(), "Native library built without tlsn")
        val session = servers.zkTlsVerifier.create(ZkTlsRecordPage.PROFILE_ID, listOf("name"), "測試", "proxy")
        val proved = holder(session.jws, inputs + ("serial" to "Z900000002"))
        assertTrue(proved is ZkResult.Ok, proved.toString())
        assertFalse(proved.value.outcome.found)
        withTimeout(30_000) { while (session.status != "done" && session.status != "failed") delay(50) }
        assertFalse(session.outcome!!.found)
        assertTrue(session.outcome!!.problems.isEmpty())
    }

    /** A device verifier ([lan] on 127.0.0.1, or in a relay room on [relay]) and a holder, run at once. */
    private suspend fun deviceSession(lan: Boolean, relay: String?, values: Map<String, String>): ZkTlsSeen = kotlinx.coroutines.coroutineScope {
        val verifier = engine(listOf("127.0.0.1")).open(lan, relay)
        val profile = servers.zkTlsVerifier.profile(ZkTlsRecordPage.PROFILE_ID)!!
        val request = ZkTlsSessionRequest.create(verifier.transports, verifier.publicKey, profile, listOf("name", "date"), "測試", inlineProfile = true)
        val signer = servers.pki.readerKey("verifier.example")
        val jws = ZkTlsSessionRequest.sign(request, signer, chain = signer.certChain.certificates)
        val verified = async { verifier.verify(jws, request, profile, listOf(servers.recordPage.caDer)) {} }
        val proved = holder(jws, values)
        val result = verified.await()
        assertTrue(proved is ZkResult.Ok, proved.toString())
        assertTrue(result is ZkResult.Ok, result.toString())
        assertEquals(if (lan) ZkTlsTransport.Lan::class else ZkTlsTransport.Relay::class, proved.value.transport::class)
        val outcome = ZkTlsCheck.check(request, profile, result.value)
        assertTrue(outcome.passed, outcome.problems.toString())
        assertEquals(proved.value.outcome.fields, outcome.fields)
        result.value
    }

    @Test
    fun relayPairsTwoAndRefusesAThird() = runBlocking {
        val client = HttpClient(Java) { install(WebSockets) }
        try {
            val room = ByteArray(16) { 9 }.toBase64Url()
            val url = "ws://localhost:$port/zktls/relay/$room"
            val a = client.webSocketSession(url)
            val b = client.webSocketSession(url)
            a.send(Frame.Binary(true, byteArrayOf(1, 2, 3)))
            assertEquals(listOf<Byte>(1, 2, 3), withTimeout(5_000) { (b.incoming.receive() as Frame.Binary).readBytes().toList() })
            b.send(Frame.Binary(true, byteArrayOf(4)))
            assertEquals(listOf<Byte>(4), withTimeout(5_000) { (a.incoming.receive() as Frame.Binary).readBytes().toList() })
            val c = client.webSocketSession(url)
            val refused = withTimeout(5_000) { runCatching { c.incoming.receive() }.getOrNull() }
            assertTrue(refused == null || refused is Frame.Close)
            a.close(io.ktor.websocket.CloseReason(io.ktor.websocket.CloseReason.Codes.NORMAL, ""))
            // Closing one side closes the other and frees the room.
            withTimeout(5_000) { runCatching { while (true) b.incoming.receive() } }
            withTimeout(5_000) { while (servers.zkTlsRelay.size > 0) delay(20) }
        } finally {
            client.close()
        }
    }
}

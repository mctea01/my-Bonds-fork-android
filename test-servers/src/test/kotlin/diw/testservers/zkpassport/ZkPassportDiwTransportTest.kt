package diw.testservers.zkpassport

import diw.testservers.zktls.ZkTlsRelay
import diw.wallet.core.zkpassport.JvmZkPassportVerifier
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol.Companion.hex
import diw.wallet.core.zkpassport.ZkPassportChannel
import diw.wallet.core.zkpassport.ZkPassportConfig
import diw.wallet.core.zkpassport.ZkPassportDiwNearby
import diw.wallet.core.zkpassport.ZkPassportDiwRelay
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportNearbyLink
import diw.wallet.core.zkpassport.ZkPassportNearbyPayload
import diw.wallet.core.zkpassport.ZkPassportProver
import diw.wallet.core.zkpassport.ZkPassportRegistry
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportResponder
import diw.wallet.core.zkpassport.ZkPassportSession
import diw.wallet.core.zkpassport.ZkPassportState
import io.ktor.client.HttpClient
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two copies of this wallet exchanging a zkPassport request without zkPassport's bridge (docs/design/zkpassport.md
 * 5.7 and 5.8): the user's relay, the local network or BLE (one exchange), and the registry record for offline use.
 * The standard link and bridge messages stay as zkPassport defines them.
 */
class ZkPassportDiwTransportTest {
    private val request = ZkPassportRequest(
        domain = "verify.example.org", name = "DIW", purpose = "Age check", scope = "adult",
        disclose = setOf(ZkPassportField.NATIONALITY), minAge = 18,
    )

    /** A bridge address nothing listens on: these exchanges must not need it. */
    private val noBridge = "ws://127.0.0.1:1/"

    private fun proof(index: Int) = buildJsonObject {
        put("name", "compare_age"); put("version", "0.22.0"); put("index", index); put("total", 2)
        put("proof", "0x" + hex(ByteArray(20_000).also { java.util.Random(index.toLong()).nextBytes(it) }))
        put("vkeyHash", "0x01")
    }

    private val done = buildJsonObject { putJsonObject("age") { putJsonObject("gte") { put("result", true) } } }

    @Test
    fun theStandardLinkCarriesNoExtension() {
        val creator = ZkPassportBridgeProtocol()
        val plain = ZkPassport.url(request, creator.bridgeId, 1_800_000_000)
        assertFalse("diw_" in plain, plain)
        assertEquals(plain, ZkPassport.url(request, creator.bridgeId, 1_800_000_000, null, null))
        val incoming = assertNotNull(ZkPassport.parseLink(plain))
        assertNull(incoming.diwRelay)
        assertNull(incoming.diwNearby)

        val relay = ZkPassportDiwRelay.open("wss://diw.example.org/zktls/relay", ByteArray(16) { it.toByte() })
        val nearby = ZkPassportDiwNearby(listOf("http://192.168.1.5:8080/zkp/a", "http://10.0.0.2:9000/zkp/a"), "0f8e6c1a-1b2c-4d3e-8f90-123456789abc")
        val extended = ZkPassport.url(request, creator.bridgeId, 1_800_000_000, relay, nearby)
        // The standard parameters come first and unchanged, so zkPassport's app reads the same request.
        assertTrue(extended.startsWith(plain + "&"), extended)
        val read = assertNotNull(ZkPassport.parseLink(extended))
        assertEquals(incoming.copy(link = read.link, diwRelay = read.diwRelay, diwNearby = read.diwNearby), read)
        assertEquals(relay, read.diwRelay)
        assertEquals(nearby, read.diwNearby)
        assertEquals("https://diw.example.org", read.diwRelay!!.origin)

        // Malformed parts are left out, not refused: the request is still zkPassport's.
        assertNull(ZkPassportDiwRelay.parse("https://diw.example.org/zktls/relay", relay.room))
        assertNull(ZkPassportDiwRelay.parse("wss://diw.example.org/other", relay.room))
        assertNull(ZkPassportDiwRelay.parse("wss://diw.example.org/zktls/relay", "short"))
        assertEquals(
            ZkPassportDiwNearby(listOf("http://192.168.1.5:8080/x")),
            ZkPassportDiwNearby.parse("http://192.168.1.5:8080/x,https://public.example/x,http://8.8.8.8/x", "not-a-uuid"),
        )
        assertNull(ZkPassportDiwNearby.parse("https://public.example/x", null))
    }

    @Test
    fun aRequestIsAnsweredOverTheUsersRelay() = runBlocking<Unit> {
        val relay = ZkTlsRelay()
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            install(WebSockets)
            routing { webSocket("/zktls/relay/{room}") { relay.join(call.parameters["room"]!!, this) } }
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val http = HttpClient(io.ktor.client.engine.java.Java)
            val verifier = JvmZkPassportVerifier(http, Files.createTempDirectory("zkpassport").toFile(), { null }, { false }, noBridge)
            val session = verifier.open(request, ZkPassportConfig(diwRelay = "ws://127.0.0.1:$port/zktls/relay"), this)
            val link = withTimeout(30_000) { session.state.first { it is ZkPassportState.Waiting } as ZkPassportState.Waiting }.url
            val incoming = assertNotNull(ZkPassport.parseLink(link))
            assertNotNull(incoming.diwRelay)

            val responder = ZkPassportResponder(http, incoming, noBridge)
            // The request reached this wallet through the relay, whose origin is shown for reference only: the relay
            // pairs a room by its id, so it never counts as the requester's confirmed origin.
            assertEquals("http://127.0.0.1", responder.connect())
            assertEquals(ZkPassportChannel.DIW_RELAY, responder.channel)
            assertFalse(responder.originMatches)
            responder.accept()
            withTimeout(30_000) { session.state.first { it == ZkPassportState.Generating } }
            responder.send(listOf("proof" to proof(0), "proof" to proof(1), "done" to done))
            val end = withTimeout(30_000) { session.state.first { it is ZkPassportState.Done || it is ZkPassportState.Failed } }
            responder.close()
            session.close()
            // Every proof arrived; this JVM has no zkPDF backend, so verification stops there.
            assertEquals(listOf("native_unavailable"), (end as ZkPassportState.Done).result.errors)
        } finally {
            server.stop(100, 1000)
        }
    }

    /** A nearby link that hands the payload to [session] as the app's LAN listener or BLE central would. */
    private class Direct(private val session: ZkPassportSession, private val way: String = "lan") : ZkPassportNearbyLink {
        val delivered = ArrayList<ByteArray>()
        override suspend fun probe(): String = way
        override suspend fun deliver(payload: ByteArray, onProgress: (String) -> Unit): ByteArray {
            delivered.add(payload)
            return session.nearby(payload)
        }
    }

    @Test
    fun aNearbyRequestIsAnsweredInOneExchangeWithoutAnyServer() = runBlocking<Unit> {
        val http = HttpClient(io.ktor.client.engine.java.Java)
        val verifier = JvmZkPassportVerifier(http, Files.createTempDirectory("zkpassport").toFile(), { null }, { false }, noBridge)
        val nearby = ZkPassportDiwNearby(listOf("http://192.168.1.5:8080/zkp/x"), "0f8e6c1a-1b2c-4d3e-8f90-123456789abc")
        val session = verifier.open(request, ZkPassportConfig(diwNearby = nearby), this)
        // Shown at once: no connection of the requester is needed.
        val link = withTimeout(5_000) { session.state.first { it is ZkPassportState.Waiting } as ZkPassportState.Waiting }.url
        val incoming = assertNotNull(ZkPassport.parseLink(link))
        assertEquals(nearby, incoming.diwNearby)

        val direct = Direct(session)
        val responder = ZkPassportResponder(http, incoming, noBridge, nearby = direct)
        assertEquals("", responder.connect())
        assertEquals(ZkPassportChannel.DIW_LAN, responder.channel)
        assertNull(responder.origin)
        responder.accept()
        // Nothing goes out until the answer is complete.
        assertTrue(direct.delivered.isEmpty())
        responder.send(listOf("proof" to proof(0), "proof" to proof(1), "done" to done))
        assertEquals(1, direct.delivered.size)
        val end = withTimeout(30_000) { session.state.first { it is ZkPassportState.Done || it is ZkPassportState.Failed } }
        assertEquals(listOf("native_unavailable"), (end as ZkPassportState.Done).result.errors)
        // The same answer again (a reply lost on the way) is acknowledged; anything else is not an answer.
        assertNull(ZkPassportNearbyPayload.replyError(session.nearby(direct.delivered.single())))
        assertEquals("payload", ZkPassportNearbyPayload.replyError(session.nearby("{}".encodeToByteArray())))
        responder.close()
        session.close()
    }

    @Test
    fun aNearbyRefusalReachesTheRequester() = runBlocking<Unit> {
        val http = HttpClient(io.ktor.client.engine.java.Java)
        val verifier = JvmZkPassportVerifier(http, Files.createTempDirectory("zkpassport").toFile(), { null }, { false }, noBridge)
        val session = verifier.open(request, ZkPassportConfig(diwNearby = ZkPassportDiwNearby(ble = "0f8e6c1a-1b2c-4d3e-8f90-123456789abc")), this)
        val link = withTimeout(5_000) { session.state.first { it is ZkPassportState.Waiting } as ZkPassportState.Waiting }.url
        val responder = ZkPassportResponder(http, assertNotNull(ZkPassport.parseLink(link)), noBridge, nearby = Direct(session, "ble"))
        responder.connect()
        assertEquals(ZkPassportChannel.DIW_BLE, responder.channel)
        responder.reject()
        assertEquals(ZkPassportState.Rejected, withTimeout(10_000) { session.state.first { it == ZkPassportState.Rejected } })
        responder.close()
        session.close()
    }

    @Test
    fun keysGoToAnotherCopyOfThisWalletOnly() = runBlocking<Unit> {
        // The requester's side read frame by frame, as it would arrive nearby.
        val creator = ZkPassportBridgeProtocol()
        val incoming = assertNotNull(ZkPassport.parseLink(ZkPassport.url(request, creator.bridgeId, 1_800_000_000, nearby = ZkPassportDiwNearby(listOf("http://192.168.1.5:8080/x")))))
        var delivered: ByteArray? = null
        val link = object : ZkPassportNearbyLink {
            override suspend fun probe() = "lan"
            override suspend fun deliver(payload: ByteArray, onProgress: (String) -> Unit): ByteArray {
                delivered = payload
                return ZkPassportNearbyPayload.reply()
            }
        }
        val responder = ZkPassportResponder(HttpClient(io.ktor.client.engine.java.Java), incoming, noBridge, nearby = link)
        responder.connect()
        responder.accept()
        val p = proof(0)
        val proved = ZkPassportProver.Proved(
            listOf(ZkPassportProver.Proof("compare_age", (p["proof"] as JsonPrimitive).content, "a2V5", "0x01", "0.22.0", null)),
            listOf("accept" to JsonObject(emptyMap()), "proof" to p, "done" to done),
            done,
        )
        responder.send(proved)
        val events = assertNotNull(ZkPassportNearbyPayload.decode(delivered!!)).flatMap { creator.receive(it, 1).second }
        assertEquals(ZkPassportBridgeProtocol.Event.Handshake, events.first())
        val messages = events.filterIsInstance<ZkPassportBridgeProtocol.Event.Message>()
        assertEquals(listOf("accept", "proof", "done"), messages.map { it.method })
        assertEquals(JsonPrimitive("a2V5"), (messages[1].params as JsonObject)["vkey"])
        // The same proof message stays as zkPassport sends it otherwise.
        assertEquals(p, JsonObject((messages[1].params as JsonObject) - "vkey"))
        responder.close()
    }

    @Test
    fun theRegistryAnswersFromItsRecordWhenTheNodeIsUnreachable() = runBlocking<Unit> {
        val root = "0x" + "ab".repeat(32)
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            routing {
                post("/") {
                    // latestRoot and isRootValid both read one word: the root, or 1 for valid.
                    val body = call.receiveText()
                    val result = if (ZkPassportRegistry.LATEST_ROOT.removePrefix("0x") in body) root else "0x" + "0".repeat(63) + "1"
                    call.respondText("""{"jsonrpc":"2.0","id":1,"result":"$result"}""", io.ktor.http.ContentType.Application.Json)
                }
            }
        }.start(wait = false)
        val cache = Files.createTempDirectory("zkpassport").toFile()
        val registry = ZkPassportRegistry(HttpClient(io.ktor.client.engine.java.Java), cache)
        try {
            val node = "http://127.0.0.1:${server.engine.resolvedConnectors().first().port}/"
            assertEquals(ZkPassportRegistry.Answer(root), registry.latestRootStatus(1, node, ZkPassportRegistry.CERTIFICATE_REGISTRY, 1_000))
            assertEquals(ZkPassportRegistry.Answer(true), registry.rootStatus(1, node, ZkPassportRegistry.CERTIFICATE_REGISTRY, root, 5, nowSeconds = 1_000))
        } finally {
            server.stop(100, 1000)
        }
        val offline = "http://127.0.0.1:1/"
        // Offline: the recorded answers, with the time they were read.
        assertEquals(ZkPassportRegistry.Answer(root, 1_000L), registry.latestRootStatus(1, offline, ZkPassportRegistry.CERTIFICATE_REGISTRY))
        assertEquals(ZkPassportRegistry.Answer(true, 1_000L), registry.rootStatus(1, offline, ZkPassportRegistry.CERTIFICATE_REGISTRY, root, 9))
        // A root never found valid here, another registry or another chain is still unreachable.
        assertFailsWith<ZkPassportRegistry.Unreachable> { registry.rootStatus(1, offline, ZkPassportRegistry.CERTIFICATE_REGISTRY, "0x" + "cd".repeat(32), 9) }
        assertFailsWith<ZkPassportRegistry.Unreachable> { registry.rootStatus(1, offline, ZkPassportRegistry.CIRCUIT_REGISTRY, root, 9) }
        assertFailsWith<ZkPassportRegistry.Unreachable> { registry.latestRootStatus(ZkPassport.SEPOLIA, offline, ZkPassportRegistry.CERTIFICATE_REGISTRY) }
        val record = registry.offlineRecord(1)
        assertEquals(root, record.latestRoot)
        assertEquals(1_000L, record.latestAt)
        assertFalse(record.certificates)
        registry.clear()
        assertNull(registry.offlineRecord(1).latestRoot)
    }
}

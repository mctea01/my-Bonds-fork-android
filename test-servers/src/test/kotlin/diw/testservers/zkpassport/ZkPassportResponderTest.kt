package diw.testservers.zkpassport

import diw.wallet.core.zkpassport.JvmZkPassportVerifier
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol.Companion.hex
import diw.wallet.core.zkpassport.ZkPassportConfig
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportHolderBridge
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportResponder
import diw.wallet.core.zkpassport.ZkPassportState
import io.ktor.client.HttpClient
import io.ktor.http.HttpHeaders
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.routing.routing
import io.ktor.server.websocket.DefaultWebSocketServerSession
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import diw.wallet.core.zkpassport.ZkPassportIncoming
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.nio.file.Files
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** This wallet answering a zkPassport request (Z3): the link, the joiner side of the bridge and a whole exchange. */
class ZkPassportResponderTest {
    private val request = ZkPassportRequest(
        domain = "verify.example.org", name = "DIW", purpose = "Age check", scope = "adult",
        disclose = setOf(ZkPassportField.NATIONALITY), minAge = 18,
    )

    private fun proof(index: Int) = buildJsonObject {
        put("name", "compare_age"); put("version", "0.22.0"); put("index", index); put("total", 2)
        put("proof", "0x" + hex(ByteArray(20_000).also { java.util.Random(index.toLong()).nextBytes(it) }))
        put("vkeyHash", "0x01")
    }

    @Test
    fun theLinkIsReadBack() {
        val creator = ZkPassportBridgeProtocol()
        val link = ZkPassport.url(request, creator.bridgeId, 1_800_000_000)
        val incoming = assertNotNull(ZkPassport.parseLink(link))
        assertEquals("verify.example.org", incoming.domain)
        assertEquals(creator.bridgeId, incoming.verifierPublicKey)
        assertEquals(ZkPassport.query(request), incoming.query)
        assertEquals("DIW", incoming.name)
        assertEquals("Age check", incoming.purpose)
        assertEquals("adult", incoming.scope)
        assertTrue(incoming.fastMode)
        assertFalse(incoming.devMode)
        assertEquals("https://verify.example.org", incoming.expectedOrigin)
        // Another host, a missing key or a broken query is not a request.
        assertNull(ZkPassport.parseLink(link.replace("https://zkpassport.id/", "https://zkpassport.example/")))
        assertNull(ZkPassport.parseLink(link.replace("&p=${creator.bridgeId}", "")))
        assertNull(ZkPassport.parseLink(link.replace("&c=", "&c=x")))
        assertNull(ZkPassport.parseLink("http://zkpassport.id/r?" + link.substringAfter('?')))
        // Request pages on a phone open the same query as zkpassport:///r.
        val app = assertNotNull(ZkPassport.parseLink("zkpassport:///r?" + link.substringAfter('?')))
        assertEquals(incoming.copy(link = app.link), app)
        assertEquals(link, app.link)
        assertNull(ZkPassport.parseLink("zkpassport:///x?" + link.substringAfter('?')))
    }

    @Test
    fun theOriginIsAskedForAgainWhenTheFirstConnectionGetsNone() = runBlocking<Unit> {
        // The bridge reports the origin only while the request page is connected: here not on the first connection.
        var connections = 0
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            install(WebSockets)
            routing {
                webSocket("/") {
                    if (++connections >= 2) send(Frame.Text(buildJsonObject {
                        put("method", "ooc"); putJsonObject("params") { put("origin", "https://verify.example.org") }
                    }.toString()))
                    for (frame in incoming) { }
                }
            }
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val link = ZkPassport.url(request, ZkPassportBridgeProtocol().bridgeId, 1_800_000_000)
            val http = HttpClient(io.ktor.client.engine.java.Java)
            val responder = ZkPassportResponder(http, assertNotNull(ZkPassport.parseLink(link)), "ws://127.0.0.1:$port/", originWaitMs = 500)
            assertEquals("https://verify.example.org", responder.connect())
            assertEquals(2, connections)
            responder.close()
            // Without any report the answer stops after the last attempt.
            connections = -10
            val silent = ZkPassportResponder(http, assertNotNull(ZkPassport.parseLink(link)), "ws://127.0.0.1:$port/", originWaitMs = 200)
            assertEquals("bridge_origin:3x", kotlin.test.assertFailsWith<ZkPassportResponder.Failure> { silent.connect() }.code)
            assertEquals(-7, connections)
            silent.close()
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun theHolderSideTalksToTheCreatorSide() {
        val creator = ZkPassportBridgeProtocol()
        val holder = ZkPassportHolderBridge(creator.bridgeId)
        val url = holder.connectUrl("wss://bridge.example")
        assertTrue(url.startsWith("wss://bridge.example?id=${creator.bridgeId}&v=1&moc=") && url.endsWith("&ooc"), url)
        val moc = java.net.URLDecoder.decode(url.substringAfter("&moc=").substringBefore("&ooc"), "UTF-8")
        val handshake = String(Base64.getDecoder().decode(moc))

        val (hello, events) = creator.receive(handshake, 1)
        assertEquals(listOf<ZkPassportBridgeProtocol.Event>(ZkPassportBridgeProtocol.Event.Handshake), events)
        // Before the bridge reports the origin, messages are taken as they come.
        assertEquals("hello", (holder.receive(hello.single()).second.single() as ZkPassportHolderBridge.Event.Message).method)

        val (_, origin) = holder.receive("""{"method":"ooc","params":{"origin":"https://Verify.Example.org:443/page"}}""")
        assertEquals(listOf<ZkPassportHolderBridge.Event>(ZkPassportHolderBridge.Event.Origin("https://verify.example.org")), origin)
        assertTrue(holder.receive("""{"method":"ooc","params":{"origin":"https://evil.example"}}""").second.isEmpty(), "the first report holds")

        // A frame the bridge marks with another origin is dropped; one with the reported origin is read.
        fun marked(frame: String, from: String) = JsonObject(Json.parseToJsonElement(frame).jsonObject + ("origin" to JsonPrimitive(from))).toString()
        val ask = creator.encrypted("note", buildJsonObject { put("x", 1) }).single()
        assertTrue(holder.receive(marked(ask, "https://evil.example")).second.isEmpty())
        val again = creator.encrypted("note", buildJsonObject { put("x", 2) }).single()
        assertEquals(buildJsonObject { put("x", 2) }, (holder.receive(marked(again, "https://verify.example.org")).second.single() as ZkPassportHolderBridge.Event.Message).params)

        // The holder's chunked messages reach the creator whole.
        val frames = holder.frames("proof", proof(0))
        assertTrue(frames.size > 1)
        val received = frames.flatMap { creator.receive(it, 2).second }
        assertEquals(listOf<ZkPassportBridgeProtocol.Event>(ZkPassportBridgeProtocol.Event.Message("proof", proof(0))), received)
        assertEquals("""{"method":"pong","params":{},"nocache":true}""", holder.receive("""{"method":"ping","params":{}}""").first.single())
    }

    @Test
    fun theRequestersStampedHelloGivesTheOriginWithoutOoc() {
        val creator = ZkPassportBridgeProtocol()
        val holder = ZkPassportHolderBridge(creator.bridgeId)
        val url = holder.connectUrl("wss://bridge.example")
        val moc = java.net.URLDecoder.decode(url.substringAfter("&moc=").substringBefore("&ooc"), "UTF-8")
        val (hello, _) = creator.receive(String(Base64.getDecoder().decode(moc)), 1)
        val stamped = JsonObject(Json.parseToJsonElement(hello.single()).jsonObject + ("origin" to JsonPrimitive("https://Demo.Example.org"))).toString()
        val events = holder.receive(stamped).second
        assertEquals(ZkPassportHolderBridge.Event.Origin("https://demo.example.org"), events.first())
        assertEquals("hello", (events[1] as ZkPassportHolderBridge.Event.Message).method)
        assertEquals("https://demo.example.org", holder.origin)
        // A later ooc does not replace it, and frames stamped with another origin are dropped.
        assertTrue(holder.receive("""{"method":"ooc","params":{"origin":"https://evil.example"}}""").second.isEmpty())
        val other = creator.encrypted("note", buildJsonObject { put("x", 1) }).single()
        assertTrue(holder.receive(JsonObject(Json.parseToJsonElement(other).jsonObject + ("origin" to JsonPrimitive("https://evil.example"))).toString()).second.isEmpty())
    }

    /** A bridge as @obsidion/bridge's server behaves: moc forwarded, ooc answered, the creator's origin added to its frames. */
    private class Relay {
        var creator: DefaultWebSocketServerSession? = null
        var creatorOrigin: String? = null
        val creatorReady = CompletableDeferred<Unit>()
        var holder: DefaultWebSocketServerSession? = null
    }

    @Test
    fun aRequestIsAnsweredOverTheBridge() = runBlocking<Unit> {
        val relay = Relay()
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            install(WebSockets)
            routing {
                webSocket("/") {
                    val q = call.request.queryParameters
                    if ("moc" !in q && "ooc" !in q) {
                        relay.creator = this
                        relay.creatorOrigin = call.request.headers[HttpHeaders.Origin]
                        relay.creatorReady.complete(Unit)
                        for (frame in incoming) {
                            if (frame !is Frame.Text) continue
                            val o = Json.parseToJsonElement(frame.readText()).jsonObject
                            if (o["method"]?.jsonPrimitive?.content == "ping") continue
                            val marked = JsonObject(o + ("origin" to JsonPrimitive(relay.creatorOrigin!!)))
                            relay.holder?.send(Frame.Text(marked.toString()))
                        }
                    } else {
                        relay.creatorReady.await()
                        relay.holder = this
                        if ("ooc" in q) send(Frame.Text(buildJsonObject {
                            put("method", "ooc"); putJsonObject("params") { put("origin", relay.creatorOrigin!!) }
                        }.toString()))
                        q["moc"]?.let { relay.creator!!.send(Frame.Text(String(Base64.getDecoder().decode(it)))) }
                        for (frame in incoming) {
                            if (frame !is Frame.Text) continue
                            val text = frame.readText()
                            if (Json.parseToJsonElement(text).jsonObject["method"]?.jsonPrimitive?.content == "pong") continue
                            relay.creator!!.send(Frame.Text(text))
                        }
                    }
                }
            }
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val base = "ws://127.0.0.1:$port/"
            val http = HttpClient(io.ktor.client.engine.java.Java)
            val verifier = JvmZkPassportVerifier(http, Files.createTempDirectory("zkpassport").toFile(), { null }, { false }, base)
            val session = verifier.open(request, ZkPassportConfig(), this)
            val link = withTimeout(30_000) { session.state.first { it is ZkPassportState.Waiting } as ZkPassportState.Waiting }.url
            val incoming = assertNotNull(ZkPassport.parseLink(link))

            val responder = ZkPassportResponder(http, incoming, base)
            assertEquals("https://verify.example.org", responder.connect())
            assertTrue(responder.originMatches)
            responder.accept()
            withTimeout(30_000) { session.state.first { it !is ZkPassportState.Waiting && it != ZkPassportState.Connecting } }
            responder.send(listOf("proof" to proof(0), "proof" to proof(1), "done" to buildJsonObject { putJsonObject("age") { putJsonObject("gte") { put("result", true) } } }))
            val done = withTimeout(30_000) { session.state.first { it is ZkPassportState.Done || it is ZkPassportState.Failed } }
            responder.close()
            session.close()
            // The verifier got every proof; this JVM has no zkPDF backend, so verification stops there.
            assertEquals(listOf("native_unavailable"), (done as ZkPassportState.Done).result.errors)
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test fun anotherPageOfTheSameSiteIsOnlyACaution() {
        fun incoming(domain: String) = ZkPassportIncoming(domain, "02" + "00".repeat(32), JsonObject(emptyMap()), JsonObject(emptyMap()), "fast", null, false, "")
        assertTrue(incoming("demo.zkpassport.id").sameSite("https://verify.zkpassport.id"))
        assertTrue(incoming("www.example.com.tw").sameSite("https://pay.example.com.tw"))
        assertFalse(incoming("demo.zkpassport.id").sameSite("https://zkpassport.example"))
        assertFalse(incoming("a.example.com.tw").sameSite("https://b.other.com.tw"))
        assertFalse(incoming("demo.zkpassport.id").sameSite("http://verify.zkpassport.id"))
        assertFalse(incoming("demo.zkpassport.id").sameSite(null))
    }
}

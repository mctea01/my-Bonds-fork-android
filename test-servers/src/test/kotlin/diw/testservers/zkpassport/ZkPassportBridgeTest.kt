package diw.testservers.zkpassport

import diw.wallet.core.zkpassport.JvmZkPassportVerifier
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol
import diw.wallet.core.zkpassport.ZkPassportBridgeProtocol.Companion.hex
import diw.wallet.core.zkpassport.ZkPassportConfig
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportRegistry
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportState
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSockets
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.bouncycastle.asn1.sec.SECNamedCurves
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The holder side of the bridge, written from @obsidion/bridge's joiner. */
private class Joiner(private val bridgeId: String) {
    private val curve = SECNamedCurves.getByName("secp256k1")
    private val random = SecureRandom()
    private val d = BigInteger(1, ByteArray(32).also { random.nextBytes(it) }).mod(curve.n)
    private val pub = curve.g.multiply(d).normalize().getEncoded(true)
    private val key = curve.curve.decodePoint(ZkPassportBridgeProtocol.unhex(bridgeId)).multiply(d).normalize().getEncoded(true).copyOf(32)

    private fun aes(mode: Int, data: ByteArray): ByteArray {
        val nonce = MessageDigest.getInstance("SHA-256").digest(bridgeId.encodeToByteArray()).copyOf(12)
        return Cipher.getInstance("AES/GCM/NoPadding").run { init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); doFinal(data) }
    }

    private fun id() = hex(ByteArray(16).also { random.nextBytes(it) })

    fun handshake(): String = buildJsonObject {
        put("jsonrpc", "2.0"); put("id", id()); put("method", "handshake")
        putJsonObject("params") { put("pubkey", hex(pub)); put("greeting", hex(aes(Cipher.ENCRYPT_MODE, "hello".encodeToByteArray()))) }
    }.toString()

    private fun frame(inner: JsonObject): String = buildJsonObject {
        put("jsonrpc", "2.0"); put("id", id()); put("method", "encryptedMessage")
        putJsonObject("params") { put("payload", Base64.getEncoder().encodeToString(aes(Cipher.ENCRYPT_MODE, inner.toString().encodeToByteArray()))) }
    }.toString()

    /** As getEncryptedJsonPayload: base64 zlib JSON split into [size]-character chunks. */
    fun message(method: String, params: JsonElement?, size: Int = 16 * 1024): List<String> {
        if (params == null) return listOf(frame(buildJsonObject { put("method", method); putJsonObject("params") {} }))
        val data = Base64.getEncoder().encodeToString(ZkPassportBridgeProtocol.deflate(params.toString().encodeToByteArray()))
        val pieces = data.chunked(size)
        val chunk = id()
        return pieces.mapIndexed { i, p ->
            frame(buildJsonObject {
                put("method", method); put("params", p)
                putJsonObject("chunk") { put("id", chunk); put("index", i); put("length", pieces.size) }
            })
        }
    }

    fun open(frame: String): JsonObject {
        val payload = Json.parseToJsonElement(frame).jsonObject["params"]!!.jsonObject["payload"]!!.jsonPrimitive.content
        return Json.parseToJsonElement(aes(Cipher.DECRYPT_MODE, Base64.getDecoder().decode(payload)).decodeToString()).jsonObject
    }
}

class ZkPassportBridgeTest {
    private val request = ZkPassportRequest(
        domain = "https://Verify.Example.org:8443/zk?x=1", name = "DIW", purpose = "Age check",
        disclose = setOf(ZkPassportField.FULLNAME), minAge = 18, nationalityIn = listOf("TWN", "JPN"),
        issuingCountryOut = listOf("PRK"), customData = "order-42",
    )

    private fun proof(index: Int) = buildJsonObject {
        put("name", "compare_age"); put("version", "0.21.1"); put("index", index); put("total", 2)
        put("proof", "0x" + hex(ByteArray(30_000).also { java.util.Random(index.toLong()).nextBytes(it) }))
        putJsonObject("committedInputs") { putJsonObject("compare_age") { put("minAge", 18); put("maxAge", 0) } }
    }

    @Test
    fun queryAndLinkFollowTheSdk() {
        assertEquals("verify.example.org", ZkPassport.normalizeDomain(request.domain))
        assertEquals(
            """{"document_type":{"disclose":true},"issuing_country":{"disclose":true,"out":["PRK"]},"fullname":{"disclose":true},""" +
                """"nationality":{"in":["TWN","JPN"]},"age":{"gte":18},"bind":{"custom_data":"order-42"}}""",
            ZkPassport.query(request).toString(),
        )
        val url = ZkPassport.url(request, "02ab", 1_800_000_000)
        assertTrue(url.startsWith("https://zkpassport.id/r?d=verify.example.org&t=02ab&c="), url)
        assertTrue(url.endsWith("&p=02ab&m=fast&v=${ZkPassport.SDK_VERSION}&dt=${1_800_000_000 - ZkPassport.DEFAULT_VALIDITY}&dev=0"), url)
        val c = java.net.URLDecoder.decode(url.substringAfter("&c=").substringBefore("&s="), "UTF-8")
        assertEquals(ZkPassport.query(request), Json.parseToJsonElement(String(Base64.getDecoder().decode(c))))
    }

    @Test
    fun handshakeChunksDuplicatesAndPings() {
        val creator = ZkPassportBridgeProtocol()
        val joiner = Joiner(creator.bridgeId)
        assertEquals(66, creator.bridgeId.length)
        val (pong, none) = creator.receive("""{"method":"ping","params":{}}""", 1)
        assertEquals("pong", Json.parseToJsonElement(pong.single()).jsonObject["method"]!!.jsonPrimitive.content)
        assertTrue(none.isEmpty())

        // Encrypted frames before the handshake are left for the replay.
        val early = joiner.message("accept", null).single()
        assertTrue(creator.receive(early, 2).second.isEmpty())

        val hs = joiner.handshake()
        val (hello, events) = creator.receive(hs, 3)
        assertEquals(listOf<ZkPassportBridgeProtocol.Event>(ZkPassportBridgeProtocol.Event.Handshake), events)
        assertEquals("""{"method":"hello","params":{}}""", joiner.open(hello.single()).toString())
        assertTrue(creator.receive(hs, 4).second.isEmpty(), "a repeated frame id is ignored")

        assertEquals(ZkPassportBridgeProtocol.Event.Message("accept", JsonObject(emptyMap())), creator.receive(early, 5).second.single())
        val frames = joiner.message("proof", proof(0))
        assertTrue(frames.size > 1)
        val received = frames.reversed().flatMap { creator.receive(it, 6).second }
        assertEquals(listOf<ZkPassportBridgeProtocol.Event>(ZkPassportBridgeProtocol.Event.Message("proof", proof(0))), received)

        // A frame for another key does not decrypt and is dropped.
        val stranger = Joiner(creator.bridgeId)
        assertTrue(creator.receive(stranger.message("reject", null).single(), 7).second.isEmpty())
        assertTrue(creator.receive(stranger.handshake(), 8).second.isEmpty(), "the channel keeps its first holder")
        assertEquals("""{"method":"replay","params":{"timestamp":1}}""", creator.replay())
    }

    @Test
    fun sessionRunsTheWholeExchangeOverAWebSocket() = runBlocking {
        val origin = CompletableDeferred<String?>()
        lateinit var joiner: Joiner
        val server = embeddedServer(Netty, port = 0, host = "127.0.0.1") {
            install(WebSockets)
            routing {
                webSocket("/") {
                    origin.complete(call.request.headers[HttpHeaders.Origin])
                    val id = call.request.queryParameters["id"]!!
                    assertEquals("1", call.request.queryParameters["v"])
                    joiner = Joiner(id)
                    send(Frame.Text(joiner.handshake()))
                    val hello = (incoming.receive() as Frame.Text).readText()
                    assertEquals("hello", joiner.open(hello)["method"]!!.jsonPrimitive.content)
                    joiner.message("accept", null).forEach { send(Frame.Text(it)) }
                    for (i in 0..1) joiner.message("proof", proof(i)).forEach { send(Frame.Text(it)) }
                    joiner.message("done", buildJsonObject { putJsonObject("age") { putJsonObject("gte") { put("result", true) } } })
                        .forEach { send(Frame.Text(it)) }
                    for (frame in incoming) Unit
                }
            }
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val dir = Files.createTempDirectory("zkpassport").toFile()
            val verifier = JvmZkPassportVerifier(HttpClient(io.ktor.client.engine.java.Java), dir, { null }, { false }, "ws://127.0.0.1:$port/")
            val session = verifier.open(request, ZkPassportConfig(), this)
            val done = withTimeout(30_000) { session.state.first { it is ZkPassportState.Done || it is ZkPassportState.Failed } }
            session.close()
            assertEquals("https://verify.example.org", origin.await())
            // This JVM has no zkPDF backend, so the bundle reaches verification and stops there.
            val result = (done as ZkPassportState.Done).result
            assertFalse(result.verified)
            assertEquals(listOf("native_unavailable"), result.errors)
        } finally {
            server.stop(100, 1000)
        }
    }

    @Test
    fun registryReadsGzipManifestsAndRootValidity() = runBlocking {
        val manifest = """{"version":"0.21.1","root":"0x07","circuits":{"compare_age":{"hash":"0x10","cid":"Qm","size":3}}}"""
        val gz = ByteArrayOutputStream().also { o -> GZIPOutputStream(o).use { it.write(manifest.encodeToByteArray()) } }.toByteArray()
        val calls = ArrayList<String>()
        val engine = MockEngine { req ->
            calls.add(req.url.toString())
            when {
                req.url.encodedPath.endsWith("/manifest.json") -> respond(gz, HttpStatusCode.OK)
                req.url.encodedPath.endsWith("/0x10.json") -> respond("""{"name":"compare_age","vkey":"AAAA","vkey_hash":"0x10"}""", HttpStatusCode.OK)
                else -> {
                    val body = Json.parseToJsonElement(String(req.body.toByteArray())).jsonObject
                    val data = body["params"]!!.let { (it as kotlinx.serialization.json.JsonArray)[0].jsonObject["data"]!!.jsonPrimitive.content }
                    assertEquals(ZkPassportRegistry.IS_ROOT_VALID + "1".padStart(64, '0') + "7".padStart(64, '0') + "64".padStart(64, '0'), data)
                    respond("""{"jsonrpc":"2.0","id":1,"result":"0x${"1".padStart(64, '0')}"}""", HttpStatusCode.OK,
                        headersOf(HttpHeaders.ContentType, "application/json"))
                }
            }
        }
        val dir = Files.createTempDirectory("zkpassport").toFile()
        val registry = ZkPassportRegistry(HttpClient(engine), dir)
        val m = registry.manifest(ZkPassport.MAINNET, "0.21.1")
        assertEquals("""{"version":"0.21.1","root":"0x07","circuits":{"compare_age":{"hash":"0x10"}}}""", m.toString())
        assertEquals("AAAA", registry.vkey(ZkPassport.MAINNET, "0x10"))
        assertTrue(registry.rootValid(ZkPassport.MAINNET, null, 1, "0x07", 100))
        assertEquals("https://ethereum-rpc.publicnode.com", calls.last().trimEnd('/'))
        registry.remember(ZkPassport.MAINNET, "0.21.1", m, mapOf("compare_age" to "AAAA"), mapOf("compare_age" to "0x10"))
        val before = calls.size
        assertEquals(m, registry.manifest(ZkPassport.MAINNET, "0.21.1"))
        assertEquals("AAAA", registry.vkey(ZkPassport.MAINNET, "0x10"))
        assertEquals(before, calls.size, "remembered data needs no download")
        assertTrue(calls.first().startsWith("https://circuits2.zkpassport.id/mainnet/by-version/0.21.1/"))
        Unit
    }

    private fun certificate(algorithm: String, spec: java.security.spec.AlgorithmParameterSpec?): Pair<ByteArray, java.security.PublicKey> {
        val g = java.security.KeyPairGenerator.getInstance(algorithm, org.bouncycastle.jce.provider.BouncyCastleProvider())
        if (spec != null) g.initialize(spec) else g.initialize(2048)
        val pair = g.generateKeyPair()
        val name = org.bouncycastle.asn1.x500.X500Name("CN=CSCA,C=ZZ")
        val now = System.currentTimeMillis()
        val builder = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name, BigInteger.ONE, java.util.Date(now), java.util.Date(now + 86_400_000), name, pair.public)
        val signer = org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(if (algorithm == "RSA") "SHA256withRSA" else "SHA256withECDSA")
            .setProvider(org.bouncycastle.jce.provider.BouncyCastleProvider()).build(pair.private)
        return builder.build(signer).encoded to pair.public
    }

    /** Anchor keys compare with package keys as zkPassport serialises them, brainpool included. */
    @Test
    fun cscaKeysCompareWithPackageKeys() {
        val (rsaDer, rsa) = certificate("RSA", null)
        val modulus = (rsa as java.security.interfaces.RSAPublicKey).modulus
        val rsaKey = diw.wallet.core.zkpassport.ZkPassportCsca.publicKey(rsaDer)!!
        assertTrue(diw.wallet.core.zkpassport.ZkPassportCsca.same(rsaKey, "0x" + modulus.toString(16)))
        assertFalse(diw.wallet.core.zkpassport.ZkPassportCsca.same(rsaKey, "0x" + modulus.add(BigInteger.TWO).toString(16)))
        val (ecDer, ec) = certificate("EC", java.security.spec.ECGenParameterSpec("brainpoolP384r1"))
        val w = (ec as java.security.interfaces.ECPublicKey).w
        val hex = { b: BigInteger -> b.toString(16).padStart(96, '0') }
        val ecKey = diw.wallet.core.zkpassport.ZkPassportCsca.publicKey(ecDer)!!
        assertTrue(diw.wallet.core.zkpassport.ZkPassportCsca.same(ecKey, "0x" + hex(w.affineX) + hex(w.affineY)))
        assertFalse(diw.wallet.core.zkpassport.ZkPassportCsca.same(ecKey, "0x" + hex(w.affineY) + hex(w.affineX)))
        assertEquals(null, diw.wallet.core.zkpassport.ZkPassportCsca.publicKey(byteArrayOf(1, 2, 3)))
    }

    /** The certificate package is used only when it hashes to the proofs' root, and is then kept by root. */
    @Test
    fun certificatePackagesAreCheckedAgainstTheRoot() = runBlocking {
        val root = "0x" + "ab".repeat(32)
        val calls = ArrayList<String>()
        val engine = MockEngine { req ->
            calls.add(req.url.toString())
            respond("""{"version":1,"certificates":[]}""", HttpStatusCode.OK)
        }
        val registry = ZkPassportRegistry(HttpClient(engine), Files.createTempDirectory("zkpassport").toFile())
        val wrong = runCatching { registry.certificates(ZkPassport.MAINNET, root) { """{"root":"0x01","certificates":[]}""" } }.exceptionOrNull()
        assertEquals("certificates_root", (wrong as ZkPassportRegistry.Unreachable).code)
        val summary = """{"root":"$root","certificates":[{"country":"ZZZ","publicKey":"0a"}]}"""
        assertEquals(Json.parseToJsonElement(summary), registry.certificates(ZkPassport.MAINNET, root) { summary })
        assertEquals("https://certificates.zkpassport.id/mainnet/$root.json", calls.last())
        val before = calls.size
        assertEquals(Json.parseToJsonElement(summary), registry.certificates(ZkPassport.MAINNET, root) { error("not called") })
        assertEquals(before, calls.size, "a checked package needs no second download")
        Unit
    }
}

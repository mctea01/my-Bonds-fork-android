package diw.testservers

import diw.wallet.core.document.sign.MobileMoicaEnvironment
import diw.wallet.core.document.sign.MobileMoicaException
import diw.wallet.core.document.sign.MobileMoicaMode
import diw.wallet.core.document.sign.MobileMoicaSigner
import diw.wallet.core.document.sign.ServerMobileMoicaClient
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.document.sign.TwFidoClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Date
import kotlin.time.Duration.Companion.milliseconds
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.util.Base64

class MobileMoicaTest {
    @Test
    fun checksumAuthenticatesTheEntireResponse() = runBlocking<Unit> {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(12) { (it + 32).toByte() }
        val checksum = TwFidoClient.spChecksum("transaction-result", key, iv)
        assertTrue(TwFidoClient.verifyChecksum(checksum, "transaction-result", key))
        assertFalse(TwFidoClient.verifyChecksum(checksum, "transaction-result-changed", key))
        assertFalse(TwFidoClient.verifyChecksum(checksum, "transaction-result", ByteArray(32)))
        assertFalse(TwFidoClient.verifyChecksum("00", "transaction-result", key))
        assertFalse(TwFidoClient.verifyChecksum(checksum.dropLast(1) + "z", "transaction-result", key))
    }

    @Test
    fun ticketParsingRejectsMissingIdentifiers() = runBlocking<Unit> {
        fun ticket(json: String): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray()) + ".signature"
        val valid = TwFidoClient.parseTicket(ticket("""{"transaction_id":"transaction-1","sp_ticket_id":"ticket-1"}"""))
        assertEquals("transaction-1", valid.transactionId)
        assertEquals("ticket-1", valid.spTicketId)
        assertFailsWith<MobileMoicaException> {
            TwFidoClient.parseTicket(ticket("""{"transaction_id":"transaction-1"}"""))
        }
        assertFailsWith<MobileMoicaException> { TwFidoClient.parseTicket("invalid-ticket") }
        assertTrue(TwFidoClient.isPending("20002:still processing"))
        assertFalse(TwFidoClient.isPending("90001:failure"))
    }

    /** A stand-in for diw-wallet-server's /twfido/sign: one pending poll, then the holder's signature. */
    private class FakeServer(val token: String, val wrongSigner: Boolean = false) {
        val holder = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val cert: ByteArray = JcaX509v3CertificateBuilder(
            X500Name("CN=Test Holder"), BigInteger.TEN, Date(), Date(System.currentTimeMillis() + 86_400_000),
            X500Name("CN=Test Holder"), holder.public,
        ).build(JcaContentSignerBuilder("SHA256withRSA").build(holder.private)).encoded
        val requests = ArrayList<kotlinx.serialization.json.JsonObject>()
        val data = HashMap<String, ByteArray>()
        var polls = 0
        val http = HttpClient(MockEngine { req ->
            val json = headersOf(HttpHeaders.ContentType, "application/json")
            val path = req.url.encodedPath
            when {
                req.method == HttpMethod.Post && path == "/twfido/sign" -> {
                    if (req.headers[HttpHeaders.Authorization] != "Bearer $token") {
                        return@MockEngine respond("""{"error":"unauthorized","error_description":"x"}""", HttpStatusCode.Unauthorized, json)
                    }
                    val o = Json.parseToJsonElement((req.body as TextContent).text).jsonObject
                    requests += o
                    val n = requests.size
                    data["s$n"] = Base64.getDecoder().decode(o["data"]!!.jsonPrimitive.content)
                    val ticket = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("""{"transaction_id":"txn-$n","sp_ticket_id":"t-$n"}""".toByteArray()) + ".digest"
                    respond("""{"sessionId":"s$n","token":"read-$n","spTicket":"$ticket","environment":"UAT","expiresAt":0}""", HttpStatusCode.OK, json)
                }
                req.method == HttpMethod.Get && path.startsWith("/twfido/sign/") -> {
                    val sid = path.substringAfterLast('/')
                    if (req.url.parameters["token"] != "read-" + sid.drop(1)) return@MockEngine respond("{}", HttpStatusCode.NotFound, json)
                    polls++
                    if (polls % 2 == 1) return@MockEngine respond("""{"status":"pending"}""", HttpStatusCode.OK, json)
                    val sig = Signature.getInstance("SHA256withRSA").run {
                        initSign(if (wrongSigner && sid != "s1") other.private else holder.private)
                        update(data[sid]!!)
                        sign()
                    }
                    val b64 = Base64.getEncoder()
                    respond("""{"status":"done","signature":"${b64.encodeToString(sig)}","certificate":"${b64.encodeToString(cert)}","hashedIdNumber":"h"}""",
                        HttpStatusCode.OK, json)
                }
                else -> respond("{}", HttpStatusCode.NotFound, json)
            }
        })
    }

    private fun signer(server: FakeServer, token: String?, mode: MobileMoicaMode = MobileMoicaMode.PUSH, opened: MutableList<String> = ArrayList()) =
        ServerMobileMoicaClient(server.http, "https://diw.example.org/", token).let { client ->
            client to MobileMoicaSigner(
                client, "A123456789", mode, "文件簽署", openApp = { opened += it; true }, returnUrl = "diw://moica",
                pollInterval = 10.milliseconds,
            )
        }

    @Test
    fun theServersSpAccountSignsAndTheWalletChecksTheSignature() = runBlocking<Unit> {
        val server = FakeServer("token-0123456789abcdef")
        val opened = ArrayList<String>()
        val (client, signer) = signer(server, "token-0123456789abcdef", MobileMoicaMode.APP_TO_APP, opened)
        assertTrue(signer.load().contentEquals(server.cert))
        assertEquals(MobileMoicaEnvironment.UAT, client.environment)
        val content = "signed attributes".toByteArray()
        val signature = signer.sign(content)
        assertTrue(Signature.getInstance("SHA256withRSA").run {
            initVerify(server.holder.public)
            update(content)
            verify(signature)
        })
        assertEquals(listOf("app2app", "app2app"), server.requests.map { it["mode"]!!.jsonPrimitive.content })
        assertEquals("A123456789", server.requests.last()["idNumber"]!!.jsonPrimitive.content)
        // The ticket is the service's own, so the official app opens with it as before.
        assertEquals(2, opened.size)
        assertTrue(opened.all { it.startsWith("mobilemoica://moica.moi.gov.tw/a2a/verifySign?sp_ticket=") })
    }

    @Test
    fun aMissingTokenAndAnotherHoldersAnswerAreRefused() = runBlocking<Unit> {
        val server = FakeServer("token-0123456789abcdef", wrongSigner = true)
        val e = assertFailsWith<SigningException> { signer(server, null).second.load() }
        assertTrue("存取權杖" in e.message.orEmpty())
        val (_, signer) = signer(server, "token-0123456789abcdef")
        signer.load()
        // The server could answer with any signature; the wallet checks it against the holder's certificate.
        assertFailsWith<SigningException> { signer.sign("signed attributes".toByteArray()) }
    }
}

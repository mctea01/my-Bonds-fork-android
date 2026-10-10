package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.Oid4vciClient
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.oid4vci.RemoteWalletProvider
import diw.wallet.core.oid4vci.WalletProvider
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.env.TrustEnvironment
import org.multipaz.crypto.X509Cert
import kotlin.test.assertEquals
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.java.Java
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.parameters
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.document.buildDocumentStore
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Interoperability against public test services (Multipaz, EUDI). Needs network access, so it only runs with
 * DIW_INTEROP=1. Results are printed as INTEROP lines for the acceptance report.
 */
class InteropTest {
    companion object {
        const val EUDI_ANCHORS = "https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/main/resources-logic/src/main/res/raw"
    }

    private val enabled = System.getenv("DIW_INTEROP") == "1"
    private var server: io.ktor.server.engine.EmbeddedServer<*, *>? = null

    private val http = HttpClient(Java) {
        followRedirects = false
        engine {
            val proxy = System.getenv("HTTPS_PROXY") ?: System.getenv("https_proxy")
            if (!proxy.isNullOrBlank()) this.proxy = ProxyBuilder.http(Url(proxy))
        }
    }

    private fun report(name: String, ok: Boolean, detail: String) = println("INTEROP ${if (ok) "PASS" else "FAIL"} $name: $detail")

    @AfterTest
    fun stop() {
        server?.stop(100, 500)
    }

    private class Wallet(val http: HttpClient) {
        val storage = EphemeralStorage()
        val env = EnvironmentPolicy(testEnvironmentEnabled = true)
        val trust = TrustRegistry(storage, env)
        lateinit var secureArea: SoftwareSecureArea
        lateinit var documentStore: org.multipaz.document.DocumentStore

        suspend fun init(): Wallet {
            secureArea = SoftwareSecureArea.create(storage)
            documentStore = buildDocumentStore(storage, SecureAreaRepository.Builder().add(secureArea).build()) {}
            return this
        }

        fun keys(count: Int) = KeyRequest(secureArea, { SoftwareCreateKeySettings.Builder().build() }, count, keyStorage = "software")
    }

    /** Walks the Multipaz sample issuer's pre-authorized flow (the fictional "Utopia" registry login) and returns the offer URI. */
    private suspend fun multipazPreAuthorizedOffer(configId: String): String {
        val base = "https://issuer.multipaz.org"
        val r1 = http.get("$base/issuer/authorize?configuration_id=$configId&url_schema=openid-credential-offer" +
            "&request_uri=https%3A%2F%2Fpre-authorize.multipaz.org%2F&tx_kind=none&tx_prompt=x")
        val login = http.get(r1.headers[HttpHeaders.Location]!!).bodyAsText()
        val code = Regex("name=\"authorizationCode\" value=\"([^\"]+)\"").find(login)!!.groupValues[1]
        val persons = Json.parseToJsonElement(Regex("let personMap = (\\{.*?\\});\\s*\\n", RegexOption.DOT_MATCHES_ALL).find(login)!!.groupValues[1]).jsonObject
        val (person, info) = persons.entries.first { it.value.jsonObject["instances"]!!.jsonObject.isNotEmpty() }
        val instance = info.jsonObject["instances"]!!.jsonObject.keys.first()
        val r2 = http.submitForm("$base/records/authorize", parameters {
            append("authorizationCode", code)
            append("person", person)
            append("instance", instance)
        })
        val page = http.get(r2.headers[HttpHeaders.Location]!!).bodyAsText()
        val raw = Regex("(openid-credential-offer://\\?credential_offer=[^\"<\\s]+)").find(page)!!.groupValues[1]
        return raw.replace("&amp;", "&")
    }

    /** Local DIW wallet provider, used where an issuer needs client attestation. */
    private suspend fun localWalletProvider(): WalletProvider {
        val port = ServerSocket(0).use { it.localPort }
        val base = "http://localhost:$port"
        val servers = TestServers(base, TestPki.create()).init()
        server = servers.start(port, wait = false)
        return RemoteWalletProvider(
            HttpClient(Java) { followRedirects = false }, "$base/wallet-provider", "diw-wallet-interop",
            AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), Algorithm.ES256), null, allowInsecureLoopback = true,
        )
    }

    @Test
    fun multipazIssuerPreAuthorizedSdJwt() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = Wallet(http).init()
        val offer = multipazPreAuthorizedOffer("utopia_naturalization")
        val providers = listOf("public client" to PublicClientWalletProvider("diw-wallet-interop"), "DIW test wallet provider" to localWalletProvider())
        var issued = false
        var lastError = ""
        for ((label, provider) in providers) {
            val c = Oid4vciClient(http, w.trust, w.env, provider, w.documentStore)
            try {
                val session = c.startFromOffer(if (issued) multipazPreAuthorizedOffer("utopia_naturalization") else offer)
                report("multipaz metadata", true, "issuer=${session.issuer.credentialIssuer} tier=${session.issuer.trust.tier} labels=${session.issuer.trust.labels}")
                c.authorizePreAuthorized(session, null)
                val r = c.issue(session, "utopia_naturalization", w.keys(2))
                val ok = r is IssuanceResult.Issued
                report("multipaz pre-auth sd-jwt ($label)", ok, if (r is IssuanceResult.Issued) "credentials=${r.credentials.size} tier=${r.trust.tier} labels=${r.trust.labels}" else r.toString())
                issued = issued || ok
                if (ok) break
            } catch (e: Exception) {
                lastError = e.message ?: ""
                report("multipaz pre-auth sd-jwt ($label)", false, "${e::class.simpleName}: ${e.message}")
            }
        }
        // The public Multipaz issuer only accepts client attestations from CAs on its own list (Multipaz Wallet backends).
        // Reaching that check means offer, metadata, token request, DPoP and attestation format were all accepted.
        assertTrue(issued || "CA not registered" in lastError, "Multipaz issuer failed before client authentication: $lastError")
    }

    @Test
    fun eudiIssuerMetadataAndAuthorization() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = Wallet(http).init()
        val c = Oid4vciClient(http, w.trust, w.env, PublicClientWalletProvider("diw-wallet-interop"), w.documentStore)
        val session = c.startWalletInitiated("https://issuer.eudiw.dev", listOf("eu.europa.ec.eudi.pid_vc_sd_jwt"))
        report("eudi metadata", true, "configs=${session.issuer.configurations.size} tier=${session.issuer.trust.tier} labels=${session.issuer.trust.labels}")
        val attested = session.issuer.configurations.values.count { cfg -> cfg.proofTypes.values.any { it.keyAttestationsRequired != null } }
        report("eudi key attestation", true, "$attested of ${session.issuer.configurations.size} configurations require key attestation")
        val url = c.beginAuthorizationCode(session, "diw-wallet://oid4vci/callback")
        assertTrue(Oid4vciClient.isSafeAuthorizationUrl(url, false))
        report("eudi PAR + authorize URL", true, Url(url).host)
    }

    @Test
    fun eudiVerifierRequestValidation() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = Wallet(http).init()
        val source = org.multipaz.presentment.SimplePresentmentSource(
            documentStore = w.documentStore,
            documentTypeRepository = org.multipaz.documenttype.DocumentTypeRepository(),
            domainsMdocSignature = listOf("mdoc"),
            domainsKeyBoundSdJwt = listOf("sdjwt"),
        )
        val holder = Oid4vpHolder(http, w.trust, source, w.env, PresentationPolicy())
        fun describe(req: diw.wallet.core.oid4vp.ValidatedAuthorizationRequest) =
            "client_id=${req.verifier.clientId.raw} name=${req.verifier.displayName} tier=${req.verifier.trust.tier} env=${req.verifier.trust.environment} " +
                "labels=${req.verifier.trust.labels} response_mode=${req.responseMode} verifier_info=${req.verifierInfo.size} warnings=${req.warnings}"

        val unanchored = holder.resolveUri(eudiVerifierRequest())
        report("eudi verifier request (no EUDI anchor)", true, describe(unanchored))
        assertTrue(unanchored.verifier.trust.environment == null)

        // EUDI reference implementation CAs, imported as TEST anchors the way a user would in the test environment.
        for (name in listOf("pidissuerca02_eu", "pidissuerca02_ut")) {
            val pem = http.get("$EUDI_ANCHORS/$name.pem").bodyAsText()
            w.trust.addAnchor(TrustRole.VERIFIER, TrustEnvironment.TEST, X509Cert.fromPem(pem), "EUDI $name", false, EUDI_ANCHORS)
        }
        val anchored = holder.resolveUri(eudiVerifierRequest())
        report("eudi verifier request (EUDI TEST anchor)", anchored.verifier.trust.environment == TrustEnvironment.TEST, describe(anchored))
        assertEquals(TrustEnvironment.TEST, anchored.verifier.trust.environment)
        // The DCQL query parses and runs; with no EUDI PID in the wallet it ends in access_denied, as it should.
        val e = kotlin.test.assertFailsWith<diw.wallet.core.util.ProtocolException> { holder.prepare(anchored) }
        report("eudi verifier DCQL", e.code == "access_denied", "no PID in wallet -> ${e.code}")
    }

    /** Creates a presentation transaction on the EUDI verifier backend (with its test registration certificate) and returns the wallet request URI. */
    private suspend fun eudiVerifierRequest(): String {
        val body = """
            {"nonce":"${java.util.UUID.randomUUID()}","request_uri_method":"get","intended_use_id":"TEST-01",
             "dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
             "claims":[{"path":["family_name"]}]}]}}
        """.trimIndent()
        val resp = http.post("https://verifier-backend.eudiw.dev/ui/presentations/v2") {
            contentType(ContentType.Application.Json)
            setBody(body)
        }
        val o = Json.parseToJsonElement(resp.bodyAsText()).jsonObject
        return o["authorization_request_uri"]?.jsonPrimitive?.content ?: error("EUDI verifier: $o")
    }
}

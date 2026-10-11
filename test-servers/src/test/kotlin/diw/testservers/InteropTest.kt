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
import diw.wallet.core.w3c.addDiwCredentialImplementations
import kotlin.test.assertEquals
import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.request
import io.ktor.http.HttpHeaders
import io.ktor.http.hostWithPort
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

    private fun dialects() = listOf(diw.wallet.core.compat.Draft13Dialect(http, false), diw.wallet.core.compat.TwdiwDialect(http, false))

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
        lateinit var holderIdentities: diw.wallet.core.holder.HolderIdentities

        suspend fun init(): Wallet {
            secureArea = SoftwareSecureArea.create(storage)
            val areas = SecureAreaRepository.Builder().add(secureArea).build()
            documentStore = buildDocumentStore(storage, areas) { addDiwCredentialImplementations(areas) }
            holderIdentities = diw.wallet.core.holder.HolderIdentities(storage, areas)
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

    /** Open-source TWDIW-dialect issuer (twdiw-vc-issuer-lite): token c_nonce, vc+sd-jwt without vct, did:key issuer. */
    @Test
    fun mashbeanTwdiwDialectIssuer() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = Wallet(http).init()
        val created = http.post("https://issuer.mashbean.net/api/offers") {
            contentType(ContentType.Application.Json)
            setBody("""{"cardId":"sandbox_student_card_v1","personaId":"wang-xiaoming","wallet":"bonds"}""")
        }.bodyAsText()
        val offer = Json.parseToJsonElement(created).jsonObject["qr"]!!.jsonPrimitive.content
        val c = Oid4vciClient(http, w.trust, w.env, PublicClientWalletProvider("diw-wallet-interop"), w.documentStore,
            dialects = dialects(), holderIdentities = w.holderIdentities)
        val session = c.startFromOffer(offer)
        c.authorizePreAuthorized(session, null)
        val r = c.issue(session, "sandbox_student_card_v1", w.keys(1))
        report("mashbean twdiw dialect", r is IssuanceResult.Issued, if (r is IssuanceResult.Issued) "tier=${r.trust.tier} labels=${r.trust.labels} reasons=${r.trust.reasons}" else r.toString())
        assertIs<IssuanceResult.Issued>(r)
        val claims = diw.wallet.core.credential.ClaimReader.read(r.credentials.first(), org.multipaz.documenttype.DocumentTypeRepository())
        report("mashbean claims", claims.isNotEmpty(), claims.joinToString { "${it.label}=${it.value}" })
        assertTrue(claims.any { it.label == "student_id" })
    }

    /** The open-source TWDIW-dialect verifier (verifier.mashbean.net): did:key client, signed request, TWDIW and Bonds links. */
    @Test
    fun mashbeanVerifierRequests() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = WalletFixture(trustVerifierRoot = false, trustIssuer = false, httpClient = http, env = EnvironmentPolicy(testEnvironmentEnabled = true)).init()
        val holder = diw.wallet.core.oid4vp.Oid4vpHolder(
            http, w.trust, w.source, w.env, holderIdentities = w.holderIdentities,
            dialects = listOf(diw.wallet.core.oid4vp.compat.TwdiwPresentationDialect(), diw.wallet.core.oid4vp.compat.MsVerifiedIdPresentationDialect()),
        )
        for (family in listOf("twdiw", "bonds")) {
            val created = http.post("https://verifier.mashbean.net/api/presentations") {
                contentType(ContentType.Application.Json)
                setBody("""{"profileId":"identity-name","walletFamily":"$family","credentialSource":"government","ruleParams":{}}""")
            }.bodyAsText()
            val o = Json.parseToJsonElement(created).jsonObject
            val link = o["qr"]!!.jsonPrimitive.content
            val clientId = o["clientId"]!!.jsonPrimitive.content
            val entry = diw.wallet.core.profile.twdiw.TwdiwEntryParser.parse(link) as? diw.wallet.core.profile.twdiw.TwdiwEntry.Presentation
            val request = holder.resolveUri(entry?.uri ?: link, if (entry != null) diw.wallet.core.compat.TwdiwDialect.ENTRY_HINT else null)
            report("mashbean verifier ($family)", true,
                "profile=${request.profile} client=${request.verifier.did} tier=${request.verifier.trust.tier} specs=${request.specs} mode=${request.responseMode}")
            assertEquals(clientId, request.verifier.did)
            assertEquals("twdiw", request.profile)
            // No government card in this wallet: the match fails as access_denied instead of a request error.
            val e = kotlin.test.assertFailsWith<diw.wallet.core.util.ProtocolException> { holder.prepare(request).let { p ->
                if (p is diw.wallet.core.oid4vp.PreparedExtended && p.prepared.chosen.isEmpty()) throw diw.wallet.core.util.ProtocolException("access_denied", "nothing chosen")
            } }
            assertEquals("access_denied", e.code)
        }
    }

    /** The production TWDIW trust list (frontend.wallet.gov.tw) and its Arbitrum One anchors, with the configured agent. */
    @Test
    fun twdiwProductionTrustList() = runBlocking<Unit> {
        assumeTrue(enabled)
        val client = http.config { install(diw.wallet.core.profile.twdiw.TwdiwUserAgent) }
        val list = diw.wallet.core.profile.twdiw.TwdiwTrustList(client)
        val all = list.all()
        report("twdiw trust list", all.isNotEmpty(), "entries=${all.size} issuers=${all.count { 1 in it.orgTypes }} verifiers=${all.count { 2 in it.orgTypes }}")
        assertTrue(all.isNotEmpty())
        val sample = all.filter { it.onChain.isNotEmpty() }.take(3).ifEmpty { all.take(3) }
        var anchored = 0
        for (e in sample) {
            val snap = list.verified(e.did)
            val decision = snap?.let { list.decisionFor(it) }
            report("twdiw anchor ${e.displayName}", snap?.documentVerified == true,
                "anchor=${snap?.anchor} tx=${snap?.txHash} block=${snap?.blockNumber} tier=${decision?.tier} reasons=${decision?.reasons}")
            if (snap?.anchor == diw.wallet.core.profile.twdiw.AnchorState.VERIFIED.name) anchored++
        }
        // Registered organisations verify against the Arbitrum registry (getDocById returns a struct).
        assertTrue(anchored > 0, "no sampled entry verified on chain")
    }

    /**
     * The live telecom card issuer (97179430.wallet.gov.tw) names itself in its metadata without the trailing slash its
     * offers carry. The standard client refuses that; the TWDIW dialect keeps the offer's form for the token endpoint.
     */
    @Test
    fun twdiwTelecomIssuerMetadata() = runBlocking<Unit> {
        assumeTrue(enabled)
        val client = http.config { install(diw.wallet.core.profile.twdiw.TwdiwUserAgent) }
        val w = Wallet(client).init()
        val provider = PublicClientWalletProvider("diw-wallet-interop")
        val issuer = "https://97179430.wallet.gov.tw/oid4vci/api/issuer/97179430/"
        val strict = Oid4vciClient(client, w.trust, w.env, provider, w.documentStore)
        val e = kotlin.test.assertFailsWith<diw.wallet.core.util.ProtocolException> { strict.startWalletInitiated(issuer, emptyList()) }
        report("twdiw telecom metadata (standard client)", e.code == "invalid_issuer_metadata", e.message ?: "")
        assertEquals("invalid_issuer_metadata", e.code)
        val twdiw = Oid4vciClient(client, w.trust, w.env, provider, w.documentStore,
            dialects = listOf(diw.wallet.core.compat.TwdiwDialect(client, false)))
        val session = twdiw.startWalletInitiated(issuer, emptyList())
        report("twdiw telecom metadata (TWDIW dialect)", true,
            "issuer=${session.issuer.credentialIssuer} token=${session.authServer.tokenEndpoint} configs=${session.issuer.configurations.keys}")
        assertEquals(issuer, session.issuer.credentialIssuer)
        assertEquals(issuer + "token", session.authServer.tokenEndpoint)
        assertTrue(session.issuer.configurations.isNotEmpty())
    }

    /** walt.id demo issuer (OpenID4VCI draft 13): offers are created through its issuance API with the API's own examples. */
    private suspend fun waltOffer(path: String, exampleName: String): String {
        val api = Json.parseToJsonElement(http.get("https://issuer.demo.walt.id/api.json").bodyAsText()).jsonObject
        val example = api["paths"]!!.jsonObject[path]!!.jsonObject["post"]!!.jsonObject["requestBody"]!!.jsonObject["content"]!!
            .jsonObject["application/json"]!!.jsonObject["examples"]!!.jsonObject[exampleName]!!.jsonObject["value"]!!
        return http.post("https://issuer.demo.walt.id$path") {
            contentType(ContentType.Application.Json)
            setBody(example.toString())
        }.bodyAsText().trim()
    }

    private fun waltIssue(path: String, example: String, acceptedFailure: String? = null) = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = Wallet(http).init()
        val c = Oid4vciClient(http, w.trust, w.env, PublicClientWalletProvider("diw-wallet-interop"), w.documentStore, dialects = dialects())
        val session = c.startFromOffer(waltOffer(path, example))
        report("walt.id metadata", true, "configs=${session.issuer.configurations.size} unsupported=${session.issuer.unsupported.size} offered=${session.offeredConfigurations.map { it.id }}")
        c.authorizePreAuthorized(session, null)
        val id = session.offeredConfigurations.single().id
        val r = try {
            c.issue(session, id, w.keys(1))
        } catch (e: diw.wallet.core.util.ProtocolException) {
            // The demo API's own example signer can be expired; reaching the credential check proves the protocol path.
            if (acceptedFailure == null || acceptedFailure !in (e.message ?: "")) throw e
            report("walt.id $example", true, "credential received and rejected as expected: ${e.message}")
            return@runBlocking
        }
        val detail = if (r is IssuanceResult.Issued) {
            val claims = diw.wallet.core.credential.ClaimReader.read(r.credentials.first(), org.multipaz.documenttype.DocumentTypeRepository())
            "tier=${r.trust.tier} labels=${r.trust.labels} claims=${claims.size}"
        } else r.toString()
        report("walt.id $example", r is IssuanceResult.Issued, detail)
        assertIs<IssuanceResult.Issued>(r)
    }

    @Test
    fun waltSdJwtVcX509() = waltIssue("/openid4vc/sdjwt/issue", "SD-JWT-VC example")

    @Test
    fun waltSdJwtVcDid() = waltIssue("/openid4vc/sdjwt/issue", "SD-JWT-VC example with issuer DID")

    @Test
    fun waltMdl() = waltIssue("/openid4vc/mdoc/issue", "mDL example - Mandatory fields only", acceptedFailure = "outside its validity period")

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

    /**
     * Walks the EUDI issuer's pages (FormEU test country, PID form, consent) the way a browser would, from [first],
     * until [result] finds what it needs in a redirect location or a page.
     */
    private suspend fun eudiWalk(first: suspend HttpClient.() -> HttpResponse, result: (String) -> String?): String {
        val browser = HttpClient(Java) {
            followRedirects = false
            install(HttpCookies)
            engine {
                val proxy = System.getenv("HTTPS_PROXY") ?: System.getenv("https_proxy")
                if (!proxy.isNullOrBlank()) this.proxy = ProxyBuilder.http(Url(proxy))
            }
        }
        fun unescape(s: String) = s.replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
        var resp = browser.first()
        repeat(25) {
            val location = resp.headers[HttpHeaders.Location]
            if (location != null) {
                result(location)?.let { return it }
                val u = resp.request.url
                resp = browser.get(if (location.startsWith("/")) "${u.protocol.name}://${u.hostWithPort}$location" else location)
                return@repeat
            }
            val page = unescape(resp.bodyAsText())
            result(page)?.let { return it }
            val action = Regex("<form[^>]*action=\"([^\"]+)\"").find(page)?.groupValues?.get(1)
                ?: error("EUDI page without a form (${resp.status}): ${page.take(300)}")
            val payload = Regex("name=\"payload\" value='([^']*)'").find(page)?.groupValues?.get(1)
            resp = browser.submitForm(action, parameters {
                when {
                    payload != null -> append("payload", payload)
                    "name=\"country\"" in page -> { append("country", "FC"); append("proceed", "") }
                    "name=\"given_name\"" in page -> {
                        append("birthdate", "1990-01-01")
                        append("family_name", "Interop")
                        append("given_name", "Diw")
                        append("nationalities[0][country_code]", "TW")
                        append("place_of_birth[0][country]", "TW")
                        append("proceed", "Submit")
                    }
                    "name=\"user_id\"" in page -> {
                        append("user_id", Regex("value=\"([^\"]+)\" name=\"user_id\"").find(page)!!.groupValues[1])
                        append("proceed", "Authorize")
                    }
                    else -> error("Unknown EUDI page at $action: ${page.take(300)}")
                }
            })
        }
        error("EUDI pages did not reach the expected result")
    }

    /** Wallet with the EUDI reference implementation CAs as TEST issuer anchors. */
    private suspend fun eudiWallet(): Wallet {
        val w = Wallet(http).init()
        for (name in listOf("pidissuerca02_eu", "pidissuerca02_ut")) {
            val pem = http.get("$EUDI_ANCHORS/$name.pem").bodyAsText()
            w.trust.addAnchor(TrustRole.ISSUER, TrustEnvironment.TEST, X509Cert.fromPem(pem), "EUDI $name", false, EUDI_ANCHORS)
        }
        return w
    }

    /** Issues [id], polling a deferred credential like the app does, and checks it is stored as a TEST credential. */
    private suspend fun eudiIssue(c: Oid4vciClient, session: diw.wallet.core.oid4vci.IssuanceSession, w: Wallet, id: String): IssuanceResult.Issued {
        var r = c.issue(session, id, w.keys(2))
        var polls = 0
        while (r is IssuanceResult.Deferred && polls++ < 10) {
            kotlinx.coroutines.delay(r.intervalSeconds.coerceIn(1, 10) * 1000)
            r = c.pollDeferred(session, r)
        }
        assertIs<IssuanceResult.Issued>(r)
        val record = diw.wallet.core.oid4vci.IssuanceRecord.decode(r.document.appData)
        report("eudi $id", true, "credentials=${r.credentials.size} tier=${r.trust.tier} env=${r.trust.environment} specs=${record?.specs} polls=$polls")
        assertEquals(TrustEnvironment.TEST, r.trust.environment)
        return r
    }

    /**
     * Authorization code flow with the EUDI issuer and a public client. Its authorization responses carry iss
     * https://issuer.eudiw.dev/oidc while its metadata names https://issuer.eudiw.dev: the standard client rejects
     * that as a mix-up, the EUDI dialect accepts it. PID configurations ask for key attestation, which a public
     * client cannot give; the issuer accepts plain jwt proofs.
     */
    @Test
    fun eudiIssuerAuthorizationCodePid() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = eudiWallet()
        val provider = PublicClientWalletProvider("diw-wallet-interop")
        val strict = Oid4vciClient(http, w.trust, w.env, provider, w.documentStore)
        val eudi = Oid4vciClient(http, w.trust, w.env, provider, w.documentStore, dialects = listOf(diw.wallet.core.compat.EudiDialect()))
        val ids = listOf("eu.europa.ec.eudi.pid_vc_sd_jwt", "eu.europa.ec.eudi.pid_mdoc")
        val session = eudi.startWalletInitiated("https://issuer.eudiw.dev", ids)
        val authorizeUrl = eudi.beginAuthorizationCode(session, "diw-wallet://oid4vci/callback")
        val redirect = eudiWalk({ get(authorizeUrl) }) { it.takeIf { s -> s.startsWith("diw-wallet:") } }
        report("eudi authorization response", true, redirect.substringAfter("iss=").substringBefore('&'))

        val e = kotlin.test.assertFailsWith<diw.wallet.core.util.ProtocolException> { strict.completeAuthorizationCode(session, redirect) }
        report("eudi iss (standard client)", "(mix-up)" in (e.message ?: ""), e.message ?: "")
        assertTrue("(mix-up)" in (e.message ?: ""))

        eudi.completeAuthorizationCode(session, redirect)
        report("eudi token (EUDI dialect)", true, "token_type=${session.accessToken?.type}")
        for (id in ids) {
            val r = eudiIssue(eudi, session, w, id)
            assertTrue("EUDI 參考實作" in diw.wallet.core.oid4vci.IssuanceRecord.decode(r.document.appData)!!.specs)
        }
    }

    /** Pre-authorized offer for the three PID configurations, with a transaction code, from the EUDI offer page. */
    @Test
    fun eudiIssuerPreAuthorizedPid() = runBlocking<Unit> {
        assumeTrue(enabled)
        val w = eudiWallet()
        val ids = listOf("eu.europa.ec.eudi.pid_vc_sd_jwt", "eu.europa.ec.eudi.pid_mdoc", "eu.europa.ec.eudi.pid_mdoc_deferred")
        val page = eudiWalk({
            submitForm("https://backend.issuer.eudiw.dev//credential_offer", parameters {
                ids.forEach { append(it, it) }
                append("Authorization Code Grant", "pre_auth_code")
                append("credential_offer_URI", "openid-credential-offer://")
                append("proceed", "Submit")
            })
        }) { it.takeIf { s -> "\"url_data\"" in s } }
        val offer = Regex("\"url_data\": \"([^\"]+)\"").find(page)!!.groupValues[1]
        val txCode = Regex("\"tx_code\": (\\d+)").find(page)!!.groupValues[1]
        val c = Oid4vciClient(http, w.trust, w.env, PublicClientWalletProvider("diw-wallet-interop"), w.documentStore)
        val session = c.startFromOffer(offer)
        report("eudi pre-auth offer", true, "configs=${session.offeredConfigurations.map { it.id }} tx_code length=${session.txCode?.length}")
        c.authorizePreAuthorized(session, txCode)
        for (id in ids) eudiIssue(c, session, w, id)
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

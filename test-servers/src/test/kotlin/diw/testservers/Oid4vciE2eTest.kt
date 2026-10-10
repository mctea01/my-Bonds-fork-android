package diw.testservers

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.Oid4vciClient
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.oid4vci.RemoteWalletProvider
import diw.wallet.core.oid4vci.WalletProvider
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.sdjwt.credential.KeylessSdJwtVcCredential
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import java.net.ServerSocket
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Oid4vciE2eTest {
    private val port = ServerSocket(0).use { it.localPort }
    private val base = "http://localhost:$port"
    private lateinit var servers: TestServers
    private var server: io.ktor.server.engine.EmbeddedServer<*, *>? = null

    private fun start(options: IssuerOptions = IssuerOptions()) = runBlocking {
        servers = TestServers(base, TestPki.create(), options).init()
        server = servers.start(port, wait = false)
    }

    @AfterTest
    fun stop() {
        server?.stop(100, 500)
    }

    private suspend fun offer(configs: List<String>, grant: String = "pre-authorized", txCode: String? = null, byReference: Boolean = false): String {
        val text = servers.httpClient.post("$base/issuer/offers") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                putJsonArray("configuration_ids") { configs.forEach { add(it) } }
                put("grant", grant)
                txCode?.let { put("tx_code", it) }
                put("by_reference", byReference)
            }.toString())
        }.bodyAsText()
        return DiwJson.parseToJsonElement(text).jsonObject["offer_uri"]!!.jsonPrimitive.content
    }

    private suspend fun remoteProvider(w: WalletFixture): WalletProvider = RemoteWalletProvider(
        httpClient = w.httpClient,
        baseUrl = "$base/wallet-provider",
        clientId = "diw-wallet-test",
        instanceKey = AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), Algorithm.ES256),
        instanceKeyAttestation = null,
        allowInsecureLoopback = true,
    )

    private fun client(
        w: WalletFixture,
        provider: WalletProvider = PublicClientWalletProvider("diw-wallet-test"),
        dialects: List<diw.wallet.core.compat.IssuanceDialect> = emptyList(),
    ) = Oid4vciClient(w.httpClient, w.trust, w.env, provider, w.documentStore, dialects = dialects)

    private fun keys(w: WalletFixture, count: Int = 1) = KeyRequest(
        secureArea = w.secureArea,
        createKeySettings = { SoftwareCreateKeySettings.Builder().build() },
        count = count,
        keyStorage = "software",
    )

    private suspend fun wallet(trustIssuer: Boolean = true) = WalletFixture(trustIssuer = trustIssuer).init(servers.pki)

    @Test
    fun preAuthorizedWithTxCodeBatchSdJwt() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt"), txCode = "493536"))
        assertEquals(6, session.txCode?.length)
        c.authorizePreAuthorized(session, "493536")
        val r = c.issue(session, "pid_sd_jwt", keys(w, count = 2))
        assertTrue(r is IssuanceResult.Issued)
        assertEquals(2, r.credentials.size)
        assertTrue(r.credentials.all { it is KeyBoundSdJwtVcCredential && it.isCertified })
        assertEquals(TrustEnvironment.TEST, r.trust.environment)
        assertEquals(TrustTier.T3, r.trust.tier)
        assertFalse(r.trust.mayShowAsVerified)
        val record = r.document.issuanceRecord!!
        assertTrue(record.isTestEnvironment)
        assertEquals("測試身分憑證", r.document.displayName)
        assertTrue(c.notify(session, r.notificationId!!, "credential_accepted"))
        assertEquals("credential_accepted", servers.issuer.notifications.single()["event"]!!.jsonPrimitive.content)
    }

    @Test
    fun wrongTxCodeIsRejected() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt"), txCode = "1234"))
        val e = assertFailsWith<ProtocolException> { c.authorizePreAuthorized(session, "9999") }
        assertEquals("invalid_grant", e.code)
    }

    @Test
    fun authorizationCodeParPkceDpopMdocByReference() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("mdl_mdoc"), grant = "authorization_code", byReference = true))
        val authUrl = c.beginAuthorizationCode(session, "diw-wallet://oid4vci/callback")
        assertTrue(authUrl.contains("request_uri="), "PAR must be used: $authUrl")
        val location = w.httpClient.get(authUrl).headers["Location"]!!
        c.completeAuthorizationCode(session, location)
        assertEquals("DPoP", session.accessToken!!.type)
        val r = c.issue(session, "mdl_mdoc", keys(w)) as IssuanceResult.Issued
        assertTrue(r.credentials.single() is MdocCredential)
        assertEquals(TrustEnvironment.TEST, r.trust.environment)
    }

    @Test
    fun authorizationResponseWithWrongStateIsRejected() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt"), grant = "authorization_code"))
        val authUrl = c.beginAuthorizationCode(session, "diw-wallet://oid4vci/callback")
        val location = w.httpClient.get(authUrl).headers["Location"]!!
        val forged = location.replace(Regex("state=[^&]+"), "state=forged")
        val e = assertFailsWith<ProtocolException> { c.completeAuthorizationCode(session, forged) }
        assertEquals("invalid_state", e.code)
    }

    @Test
    fun keyAttestationAndClientAttestationViaWalletProvider() = runBlocking {
        start(IssuerOptions(requireClientAttestation = true))
        val w = wallet()
        val c = client(w, remoteProvider(w))
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt_attested")))
        c.authorizePreAuthorized(session, null)
        val r = c.issue(session, "pid_sd_jwt_attested", keys(w, count = 3)) as IssuanceResult.Issued
        assertEquals(3, r.credentials.size)
    }

    @Test
    fun clientAttestationRequiredRejectsPublicClient() = runBlocking {
        start(IssuerOptions(requireClientAttestation = true))
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt")))
        val e = assertFailsWith<ProtocolException> { c.authorizePreAuthorized(session, null) }
        assertEquals("invalid_client", e.code)
    }

    @Test
    fun attestationProofType() = runBlocking {
        start()
        val w = wallet()
        val c = client(w, remoteProvider(w))
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt_attestation_proof")))
        c.authorizePreAuthorized(session, null)
        val r = c.issue(session, "pid_sd_jwt_attestation_proof", keys(w, count = 2)) as IssuanceResult.Issued
        assertEquals(2, r.credentials.size)
    }

    @Test
    fun publicClientCannotSatisfyKeyAttestation() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt_attested")))
        c.authorizePreAuthorized(session, null)
        val e = assertFailsWith<ProtocolException> { c.issue(session, "pid_sd_jwt_attested", keys(w)) }
        assertEquals("key_attestation_unavailable", e.code)
        assertTrue(w.documentStore.listDocuments().isEmpty(), "failed issuance must not leave a document")
    }

    @Test
    fun encryptionRequired() = runBlocking {
        start(IssuerOptions(encryptionRequired = true))
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt")))
        c.authorizePreAuthorized(session, null)
        assertTrue(c.issue(session, "pid_sd_jwt", keys(w)) is IssuanceResult.Issued)
    }

    @Test
    fun deferredIssuance() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt_deferred")))
        c.authorizePreAuthorized(session, null)
        var r = c.issue(session, "pid_sd_jwt_deferred", keys(w))
        assertTrue(r is IssuanceResult.Deferred)
        assertTrue(r.document.issuanceRecord!!.pendingTransactionId != null)
        r = c.pollDeferred(session, r)
        assertTrue(r is IssuanceResult.Deferred)
        r = c.pollDeferred(session, r)
        assertTrue(r is IssuanceResult.Issued)
        assertTrue(r.credentials.single().isCertified)
        assertEquals(null, r.document.issuanceRecord!!.pendingTransactionId)
    }

    @Test
    fun keylessSdJwt() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt_keyless")))
        c.authorizePreAuthorized(session, null)
        val r = c.issue(session, "pid_sd_jwt_keyless", keys(w)) as IssuanceResult.Issued
        assertTrue(r.credentials.single() is KeylessSdJwtVcCredential)
    }

    @Test
    fun legacyW3cSdJwtWithoutVctAndJkuKey() = runBlocking<Unit> {
        start()
        val w = wallet()
        // The standard client does not accept a TWDIW-style configuration; nothing of the dialect leaks into it.
        val standard = client(w)
        val s0 = standard.startFromOffer(offer(listOf("w3c_sd_jwt_legacy")))
        standard.authorizePreAuthorized(s0, null)
        val rejected = assertFailsWith<ProtocolException> { standard.issue(s0, "w3c_sd_jwt_legacy", keys(w)) }
        assertEquals("invalid_issuer_metadata", rejected.code)

        val c = client(w, dialects = listOf(
            diw.wallet.core.compat.Draft13Dialect(w.httpClient, true),
            diw.wallet.core.compat.TwdiwDialect(w.httpClient, true),
        ))
        val session = c.startFromOffer(offer(listOf("w3c_sd_jwt_legacy")))
        c.authorizePreAuthorized(session, null)
        val r = c.issue(session, "w3c_sd_jwt_legacy", keys(w)) as IssuanceResult.Issued
        val cred = r.credentials.single() as KeyBoundSdJwtVcCredential
        assertEquals("TestCard", cred.vct)
        // Multipaz cannot read claims of SD-JWTs without x5c; the wallet decodes them itself.
        val claims = diw.wallet.core.credential.ClaimReader.read(cred, w.documentTypes).associate { it.label to it.value }
        assertEquals("林哲全", claims["name"])
        assertEquals("A123", claims["cardNumber"])
        assertEquals(TrustTier.T3, r.trust.tier)
        assertTrue(TrustLabel.UNKNOWN_ANCHOR in r.trust.labels)
        assertTrue(TrustLabel.NON_STANDARD in r.trust.labels, "labels: ${r.trust.labels}")
    }

    @Test
    fun unsignedMetadataIsLabelled() = runBlocking {
        start()
        val w = wallet()
        val session = client(w).startFromOffer(offer(listOf("pid_sd_jwt")))
        assertTrue(TrustLabel.UNSIGNED_METADATA in session.issuer.trust.labels)
    }

    @Test
    fun signedMetadataIsVerified() = runBlocking {
        start(IssuerOptions(signedMetadata = true))
        val w = wallet()
        val session = client(w).startFromOffer(offer(listOf("pid_sd_jwt")))
        assertEquals(TrustEnvironment.TEST, session.issuer.trust.environment)
        assertFalse(TrustLabel.UNSIGNED_METADATA in session.issuer.trust.labels)
    }

    @Test
    fun unanchoredIssuerIsT3UnknownAnchor() = runBlocking {
        start()
        val w = wallet(trustIssuer = false)
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt")))
        c.authorizePreAuthorized(session, null)
        val r = c.issue(session, "pid_sd_jwt", keys(w)) as IssuanceResult.Issued
        assertEquals(TrustTier.T3, r.trust.tier)
        assertTrue(TrustLabel.UNKNOWN_ANCHOR in r.trust.labels)
        assertEquals(null, r.trust.environment)
    }

    @Test
    fun tokenStatusListRevocation() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt", "mdl_mdoc")))
        c.authorizePreAuthorized(session, null)
        val sd = (c.issue(session, "pid_sd_jwt", keys(w)) as IssuanceResult.Issued).credentials.single()
        val md = (c.issue(session, "mdl_mdoc", keys(w)) as IssuanceResult.Issued).credentials.single()
        val checker = CredentialStatusChecker(w.httpClient, w.trust)
        val before = checker.check(sd)
        assertEquals(RevocationCheckState.VALID, before.state, before.detail)
        assertTrue(before.usable)
        assertEquals(RevocationCheckState.VALID, checker.check(md).state)

        val (sdList, sdIdx) = servers.issuer.issuedStatus.first { it.first == "sdjwt" }
        servers.issuer.setStatus(sdList, sdIdx, 2)
        assertEquals(RevocationCheckState.SUSPENDED, checker.check(sd, bypassCache = true).state)
        val (mdList, mdIdx) = servers.issuer.issuedStatus.first { it.first == "mdoc" }
        servers.issuer.setStatus(mdList, mdIdx, 1)
        assertEquals(RevocationCheckState.INVALID, checker.check(md, bypassCache = true).state)
    }

    @Test
    fun statusListFromUntrustedSignerIsNotUsable() = runBlocking {
        start()
        val w = wallet(trustIssuer = false)
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt")))
        c.authorizePreAuthorized(session, null)
        val sd = (c.issue(session, "pid_sd_jwt", keys(w)) as IssuanceResult.Issued).credentials.single()
        val s = CredentialStatusChecker(w.httpClient, w.trust).check(sd)
        assertEquals(RevocationCheckState.UNKNOWN, s.state)
        assertFalse(s.usable)
    }

    @Test
    fun issuedCredentialPresentsToTestVerifier() = runBlocking {
        start()
        val w = wallet()
        val c = client(w)
        val session = c.startFromOffer(offer(listOf("pid_sd_jwt")))
        c.authorizePreAuthorized(session, null)
        c.issue(session, "pid_sd_jwt", keys(w))
        val text = servers.httpClient.post("$base/verifier/sessions") {
            contentType(ContentType.Application.Json); setBody(buildJsonObject { put("client_id_prefix", "x509_san_dns") }.toString())
        }.bodyAsText()
        val o: JsonObject = DiwJson.parseToJsonElement(text).jsonObject
        val req = w.holder.resolveUri(o["uri"]!!.jsonPrimitive.content)
        val prepared = w.holder.prepare(req)
        assertTrue(w.holder.respond(prepared, prepared.queryResult.select(emptyList())) is PresentationOutcome.Posted)
        val result = DiwJson.parseToJsonElement(
            servers.httpClient.get("$base/verifier/sessions/${o["id"]!!.jsonPrimitive.content}").bodyAsText()
        ).jsonObject
        assertEquals("passed", result["status"]!!.jsonPrimitive.content, "verifier result: $result")
    }
}

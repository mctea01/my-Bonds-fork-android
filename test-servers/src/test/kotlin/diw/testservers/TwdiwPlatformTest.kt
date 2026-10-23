package diw.testservers

import diw.wallet.core.compat.Draft11Dialect
import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsFrameCollector
import diw.wallet.core.profile.bonds.BondsLinkCollector
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.util.QrEncoder
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.Oid4vciClient
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.PreparedExtended
import diw.wallet.core.oid4vp.pe.DescriptorMatch
import diw.wallet.core.oid4vp.pe.PresentationExchange
import diw.wallet.core.jose.Jws
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import diw.wallet.core.oid4vp.compat.MsVerifiedIdPresentationDialect
import diw.wallet.core.oid4vp.compat.TwdiwPresentationDialect
import diw.wallet.core.profile.twdiw.TwdiwEntry
import diw.wallet.core.profile.twdiw.TwdiwEntryParser
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.HeldMoicaCard
import diw.wallet.core.profile.bonds.NationalIdFields
import diw.wallet.core.oid4vp.PreparedMoica
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.profile.twdiw.TwdiwPlatform
import diw.wallet.core.profile.twdiw.TwdiwServices
import diw.wallet.core.profile.twdiw.TwdiwTrustList
import diw.wallet.core.profile.twdiw.TwdiwUserAgent
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.StatusAssurance
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.w3c.W3cVcCredential
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import kotlin.test.Test
import kotlin.test.assertEquals
import io.ktor.client.request.get
import io.ktor.client.statement.readRawBytes
import diw.wallet.core.credential.CardImages
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The TWDIW official issuance, status, trust list, presentation and offline barcode flows against [TwdiwPlatformMock]. */
class TwdiwPlatformTest {
    private class Setup(val mock: TwdiwPlatformMock, val w: WalletFixture) {
        val platform = TwdiwPlatform(frontendUrl = TwdiwPlatformMock.FRONTEND, test = true)
        val trustList = TwdiwTrustList(w.httpClient, platform, storage = w.storage)
        val didTrust = DidTrust(listOf(trustList))
        val services = TwdiwServices(w.httpClient, trustList, platform)
        val presentation = TwdiwPresentationDialect { did, host -> trustList.hostRegistered(did, host) }
        val holder = Oid4vpHolder(
            w.httpClient, w.trust, w.source, w.env, holderIdentities = w.holderIdentities, didTrust = didTrust,
            dialects = listOf(presentation, MsVerifiedIdPresentationDialect()),
        )

        fun client() = Oid4vciClient(
            w.httpClient, w.trust, w.env, PublicClientWalletProvider("diw-wallet"), w.documentStore,
            dialects = listOf(
                TwdiwDialect(w.httpClient, false),
                Draft13Dialect(w.httpClient, false),
                Draft11Dialect(),
            ),
            holderIdentities = w.holderIdentities,
            didTrust = didTrust,
        )

        fun keys() = KeyRequest(
            secureArea = w.secureArea,
            createKeySettings = { SoftwareCreateKeySettings.Builder().build() },
            count = 1,
            keyStorage = "software",
        )

        /** Receives the mock card from the official deep link, as the wallet does for a scanned QR code. */
        suspend fun receive(): IssuanceResult.Issued {
            val entry = TwdiwEntryParser.parse(mock.offerDeepLink()) as TwdiwEntry.Offer
            val c = client()
            val session = c.startFromOffer(entry.uri, TwdiwDialect.ENTRY_HINT)
            c.authorizePreAuthorized(session, null)
            return c.issue(session, TwdiwPlatformMock.CONFIG_ID, keys()) as IssuanceResult.Issued
        }
    }

    private fun setup(): Setup = runBlocking {
        val mock = TwdiwPlatformMock.create()
        val http = HttpClient(mock.engine) {
            followRedirects = false
            install(TwdiwUserAgent) { userAgent = { TwdiwPlatform.DEFAULT_USER_AGENT } }
        }
        val w = WalletFixture(
            trustVerifierRoot = false,
            trustIssuer = false,
            httpClient = http,
            env = EnvironmentPolicy(testEnvironmentEnabled = true),
        ).init()
        Setup(mock, w)
    }

    @Test
    fun officialIssuanceAndStatus() = runBlocking<Unit> {
        val s = setup()
        val r = s.receive()
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        val cred = r.credentials.single() as W3cVcCredential
        // Announced as jwt_vc_json, delivered as an SD-JWT bound to the wallet's TWDIW holder DID.
        val holderKey = assertNotNull(s.w.holderIdentities.find(HolderIdentities.TWDIW))
        assertEquals(holderKey.did, cred.holderDid)
        assertTrue(holderKey.did!!.startsWith("did:key:z"))
        val claims = ClaimReader.read(cred, s.w.documentTypes).associate { it.label to it.value }
        assertEquals("林哲全", claims["name"])
        assertEquals("A123456789", claims["cardNumber"])
        // Listed in the (test) TWDIW trust list: a test-environment issuer, never official.
        assertEquals(TrustEnvironment.TEST, r.trust.environment)
        assertEquals(TrustTier.T3, r.trust.tier)
        assertTrue(TrustLabel.TEST_ANCHOR in r.trust.labels, "labels: ${r.trust.labels}")
        assertEquals("模擬發證機關", r.trust.anchorName)
        val record = r.document.issuanceRecord!!
        assertEquals("twdiw", record.profile)
        assertTrue("TWDIW" in record.specs, "specs: ${record.specs}")
        assertEquals("${TwdiwPlatformMock.ISSUER_ORIGIN}/logo.png", record.logoUri)
        assertEquals("#1A4C8B", record.backgroundColor)
        // Every request to wallet.gov.tw carried the configured agent (their Cloudflare front rejects library agents).
        assertTrue(s.mock.userAgents.all { it.second == TwdiwPlatform.DEFAULT_USER_AGENT }, "agents: ${s.mock.userAgents}")

        // StatusList2021: revocation and suspension lists wrapped as {statusList: jwt}. TWDIW signs them with key-2,
        // published only at the jku. The key set is on the platform, bound to the listed issuer: the result is trusted.
        val checker = CredentialStatusChecker(s.w.httpClient, s.w.trust, didTrust = s.didTrust)
        val bound = checker.check(cred, bypassCache = true)
        assertEquals(RevocationCheckState.VALID, bound.state, "detail: ${bound.detail}")
        assertTrue(bound.trusted, "detail: ${bound.detail}")
        assertEquals(StatusAssurance.TRUSTED, bound.assurance)
        assertTrue(bound.detail?.contains("jku") == true, "detail: ${bound.detail}")
        // A key set on a host nothing ties to the issuer still verifies the list, downgraded to TLS only.
        s.mock.statusJkuHost = "keys.example.org"
        val tlsOnly = checker.check(cred, bypassCache = true)
        assertEquals(RevocationCheckState.VALID, tlsOnly.state, "detail: ${tlsOnly.detail}")
        assertTrue(!tlsOnly.trusted)
        assertEquals(StatusAssurance.TLS_ONLY, tlsOnly.assurance, "detail: ${tlsOnly.detail}")
        s.mock.statusJkuHost = TwdiwPlatformMock.ISSUER_HOST
        // A list signed by the issuer DID is trusted like the card.
        s.mock.statusListSignedByIssuerDid = true
        val valid = checker.check(cred, bypassCache = true)
        assertEquals(RevocationCheckState.VALID, valid.state, "detail: ${valid.detail}")
        assertTrue(valid.trusted)
        assertEquals(2, valid.w3cEntries.size)
        s.mock.suspension[s.mock.issuedIndex] = true
        assertEquals(RevocationCheckState.SUSPENDED, checker.check(cred, bypassCache = true).state)
        s.mock.revocation[s.mock.issuedIndex] = true
        assertEquals(RevocationCheckState.INVALID, checker.check(cred, bypassCache = true).state)
    }

    /**
     * The live telecom card issuer's metadata names the issuer without the offer's trailing slash. OpenID4VCI 1.0
     * requires the two to be identical, so the standard client refuses; the TWDIW dialect accepts the slash
     * difference for its own sessions and keeps the offer's form for the token endpoint and the proof aud.
     */
    /** A sandbox listing is stored apart: offline, the official list never reads it back as an official entry. */
    @Test
    fun sandboxSnapshotsStayOutOfTheOfficialList() = runBlocking<Unit> {
        val s = setup()
        val did = s.mock.issuerDid
        assertNotNull(s.trustList.verified(did))
        assertEquals(TrustEnvironment.TEST, s.trustList.decide(did, TrustRole.ISSUER)?.environment)
        val offline = HttpClient(io.ktor.client.engine.mock.MockEngine { throw java.io.IOException("offline") })
        val official = TwdiwTrustList(offline, TwdiwPlatform(frontendUrl = TwdiwPlatformMock.FRONTEND), storage = s.w.storage)
        assertNull(official.verified(did))
        assertNotNull(TwdiwTrustList(offline, s.platform, storage = s.w.storage).verified(did), "the sandbox snapshot is still there")
    }

    @Test
    fun issuerMetadataWithoutTrailingSlash() = runBlocking<Unit> {
        val s = setup()
        s.mock.metadataIssuerWithoutSlash = true
        val standard = Oid4vciClient(s.w.httpClient, s.w.trust, s.w.env, PublicClientWalletProvider("diw-wallet"), s.w.documentStore)
        val uri = (TwdiwEntryParser.parse(s.mock.offerDeepLink()) as TwdiwEntry.Offer).uri
        val refused = assertFailsWith<ProtocolException> { standard.startFromOffer(uri) }
        assertEquals("invalid_issuer_metadata", refused.code)

        val r = s.receive()
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        assertEquals(TwdiwPlatformMock.ISSUER, r.document.issuanceRecord!!.credentialIssuer)
        assertEquals("twdiw", r.document.issuanceRecord!!.profile)
    }

    /**
     * Card faces as the official wallet shows them: background_image is kept on the record (an empty uri is none), a
     * card stored before reads the display again, and the platform's text/plain data URI bodies decode to the image,
     * for card faces and catalog logos alike.
     */
    @Test
    fun cardFaceAndCatalogLogo() = runBlocking<Unit> {
        val s = setup()
        s.mock.cardFaceInMetadata = false
        val plain = s.receive().document.issuanceRecord!!
        assertNull(plain.backgroundImageUri)
        assertNotNull(plain.displayCheckedAt)

        s.mock.cardFaceInMetadata = true
        val display = assertNotNull(s.client().credentialDisplay(TwdiwPlatformMock.ISSUER, TwdiwPlatformMock.CONFIG_ID, plain.profile))
        assertEquals(TwdiwPlatformMock.COVER_URL, display.backgroundImageUri)
        assertEquals(TwdiwPlatformMock.COVER_URL, s.receive().document.issuanceRecord!!.backgroundImageUri)

        val face = s.w.httpClient.get(TwdiwPlatformMock.COVER_URL).readRawBytes()
        assertTrue(!CardImages.isImage(face), "the platform sends text, not the image")
        assertContentEquals(s.mock.png(), CardImages.fromBody(face))
        val card = s.services.cardServices().single()
        assertEquals(TwdiwPlatformMock.LOGO_URL, card.logoUrl)
        assertContentEquals(s.mock.png(), CardImages.fromBody(s.w.httpClient.get(card.logoUrl!!).readRawBytes()))
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
    }

    /**
     * Newer TWDIW issuers publish a nonce_endpoint and, in the 2026-10-16 issuer probe, take only proofs over its
     * nonce: a proof over the token's c_nonce is refused with HTTP 400 (resp_code 11016, invalid_proof).
     */
    @Test
    fun proofUsesNonceEndpoint() = runBlocking<Unit> {
        val s = setup()
        s.mock.nonceEndpointPublished = true
        val r = s.receive()
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        assertEquals(1, s.mock.endpointNonces)
        assertEquals(1, r.credentials.size)
    }

    @Test
    fun proofUsesNonceEndpointWithoutTokenNonce() = runBlocking<Unit> {
        val s = setup()
        s.mock.nonceEndpointPublished = true
        s.mock.tokenNonceIncluded = false
        val r = s.receive()
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        assertEquals(1, s.mock.endpointNonces)
        assertEquals(1, s.mock.credentialRequests)
        assertEquals(1, r.credentials.size)
    }

    /** Reproduces the partner card's response shape without replaying a credential POST or discarding its code. */
    @Test
    fun credential11021IsPreservedWithoutRetrying() = runBlocking<Unit> {
        val s = setup()
        s.mock.nonceEndpointPublished = true
        s.mock.tokenNonceIncluded = false
        s.mock.credentialServiceFailure = 11021 to "VC Server error"
        val initialIndex = s.mock.issuedIndex
        val e = assertFailsWith<ProtocolException> { s.receive() }
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        assertEquals("server_error", e.code)
        assertEquals("Credential request failed (500): TWDIW resp_code 11021 (VC Server error)", e.message)
        assertEquals(1, s.mock.endpointNonces)
        assertEquals(1, s.mock.credentialRequests)
        assertEquals(initialIndex, s.mock.issuedIndex)
        assertTrue(s.w.documentStore.listDocuments().isEmpty())
    }

    /**
     * The official handler reports a failed credential service as HTTP 500 with {resp_code, resp_message} and no OAuth
     * error. The wallet's message keeps the platform's code so the failing step can be told apart.
     */
    @Test
    fun credentialServiceFailureShowsPlatformCode() = runBlocking<Unit> {
        val s = setup()
        s.mock.credentialServiceFailure = 61010 to "fail to get holder's data"
        val e = assertFailsWith<ProtocolException> { s.receive() }
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        assertEquals("server_error", e.code)
        assertEquals("Credential request failed (500): TWDIW resp_code 61010 (fail to get holder's data)", e.message)
    }

    @Test
    fun officialPresentationDisclosesOnlyRequestedClaims() = runBlocking<Unit> {
        val s = setup()
        s.receive()
        val entry = TwdiwEntryParser.parse(s.mock.presentationDeepLink(listOf("name"))) as TwdiwEntry.Presentation
        val request = s.holder.resolveUri(entry.uri, TwdiwDialect.ENTRY_HINT)
        assertEquals("twdiw", request.profile)
        assertEquals(s.mock.verifierDid, request.verifier.did)
        assertEquals(TrustEnvironment.TEST, request.verifier.trust.environment)
        assertEquals("模擬驗證機關", request.verifier.trust.anchorName)
        assertTrue(request.warnings.none { "not a service registered" in it }, "warnings: ${request.warnings}")
        val prepared = s.holder.prepare(request) as PreparedExtended
        assertEquals(listOf("name"), prepared.prepared.lines.single().claims)
        val outcome = s.holder.respond(prepared)
        assertTrue(outcome is PresentationOutcome.Posted, "outcome: $outcome")
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        val got = s.mock.received.single()
        assertEquals(listOf("name"), got.disclosedNames)
        // The VP lives 30 days like the official wallet's.
        val nbf = (got.vpPayload["nbf"] as JsonPrimitive).content.toLong()
        val exp = (got.vpPayload["exp"] as JsonPrimitive).content.toLong()
        assertEquals(TwdiwPresentationDialect.VP_LIFETIME_SECONDS, exp - nbf)

        // Scanned as a plain openid4vp:// link, the official request shape is still recognised as TWDIW.
        val plain = s.holder.resolveUri(s.mock.presentationUri(listOf("name", "birthDate")))
        assertEquals("twdiw", plain.profile)
        val second = s.holder.prepare(plain) as PreparedExtended
        assertEquals(listOf("name", "birthDate"), second.prepared.lines.single().claims)
        assertTrue(s.holder.respond(second) is PresentationOutcome.Posted)
        assertEquals(listOf("name", "birthDate"), s.mock.received.last().disclosedNames)
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
    }

    @Test
    fun presentationChangesCredentialAndShowsConsentTerms() = runBlocking<Unit> {
        val s = setup()
        s.receive()
        s.receive()
        val request = s.holder.resolveUri(s.mock.presentationUri(listOf("name")))

        // The official verifier packs the recipient, occasion, purpose and terms page into presentation_definition.purpose.
        val terms = assertNotNull(s.holder.consentTerms(request))
        assertEquals("模擬驗證機關", terms.recipient)
        assertEquals("皮夾夥伴卡驗證", terms.scenario)
        assertEquals("確認會員身分", terms.purpose)
        assertEquals(TwdiwPlatformMock.TERMS_URL, terms.termsUri)
        assertEquals("一般用途", TwdiwPresentationDialect.terms("一般用途")?.purpose)
        assertNull(TwdiwPresentationDialect.terms("{\"terms_uri\":\"http://plain.example/terms\"}"))

        // Two cards answer the request: the holder swaps the first choice for the other one.
        val prepared = s.holder.prepare(request) as PreparedExtended
        val first = prepared.prepared.chosen.single().credential
        val other = prepared.prepared.alternatives(0).single()
        assertNotEquals(first.document.identifier, other.document.identifier)
        val changed = s.holder.replace(prepared, 0, other)
        assertEquals(other.document.identifier, changed.prepared.chosen.single().credential.document.identifier)
        assertEquals(listOf("name"), changed.lines.single().claims)
        assertEquals(first.document.identifier, changed.prepared.alternatives(0).single().document.identifier)
        assertFails { s.holder.replace(changed, 0, other) }
        assertTrue(s.holder.respond(changed) is PresentationOutcome.Posted)
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        assertEquals(Jws.parse(other.raw.substringBefore('~')).payload, s.mock.received.single().card)

        // "pick, max 1" over a group: one card of either descriptor meets the request, two or none do not.
        val def = changed.prepared.definition!!
        val mine = def.descriptors.single { it.id == TwdiwPlatformMock.CONFIG_ID + "_2" }
        val another = def.descriptors.single { it.id != mine.id }
        assertTrue(PresentationExchange.satisfies(def, mapOf(mine.id to DescriptorMatch(mine, other, emptyList()))))
        assertTrue(PresentationExchange.satisfies(def, mapOf(another.id to DescriptorMatch(another, other, emptyList()))))
        assertFalse(PresentationExchange.satisfies(def, mapOf(mine.id to DescriptorMatch(mine, other, emptyList()), another.id to DescriptorMatch(another, first, emptyList()))))
        assertFalse(PresentationExchange.satisfies(def, emptyMap()))
        assertFalse(PresentationExchange.satisfies(def, mapOf(another.id to DescriptorMatch(mine, other, emptyList()))))
    }

    @Test
    fun verifierSigningWithFragmentZero() = runBlocking<Unit> {
        val s = setup()
        s.receive()
        s.mock.requestKid = s.mock.verifierDid + "#0"
        val request = s.holder.resolveUri(s.mock.presentationUri(listOf("name")))
        assertEquals("twdiw", request.profile)
        assertEquals(s.mock.verifierDid, request.verifier.did)
        val prepared = s.holder.prepare(request) as PreparedExtended
        assertTrue(s.holder.respond(prepared) is PresentationOutcome.Posted)
        assertEquals(listOf("name"), s.mock.received.single().disclosedNames)

        // A kid naming another DID is still refused.
        s.mock.requestKid = DidKeys.didKeyJwkJcs(Crypto.createEcPrivateKey(EcCurve.P256).publicKey) + "#0"
        assertFails { s.holder.resolveUri(s.mock.presentationUri(listOf("name"))) }
    }

    /** A citizen certificate card signer under a throwaway MOICA-like chain (the verifier mock does not check it). */
    private fun citizenCard(name: String): DocumentSigner {
        val gen = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val caKey = gen.generateKeyPair()
        val key = gen.generateKeyPair()
        val now = System.currentTimeMillis()
        val holderCert = org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(
            org.bouncycastle.asn1.x500.X500Name("CN=Test MOICA"), java.math.BigInteger.valueOf(now), java.util.Date(now - 86_400_000),
            java.util.Date(now + 86_400_000L * 365), org.bouncycastle.asn1.x500.X500Name("CN=$name,C=TW"), key.public,
        ).build(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(caKey.private))
        return object : DocumentSigner {
            override val certificateChain = listOf(holderCert.encoded)
            override val keyType = SignerKeyType.RSA
            override val source = SignerSource.SMART_CARD
            override suspend fun sign(data: ByteArray): ByteArray =
                java.security.Signature.getInstance("SHA256withRSA").run { initSign(key.private); update(data); sign() }
        }
    }

    @Test
    fun bondsSelfIssuedCardOnline() = runBlocking<Unit> {
        val s = setup()
        val self = s.w.holderIdentities.getOrCreate(HolderIdentities.BONDS_SELF_ISSUED, "did:key", s.w.secureArea, SoftwareCreateKeySettings.Builder().build())
        val card = BondsNationalId.issue(NationalIdFields("A123456789", "測試人員", "民國 083年03月06日", "臺北市"), self, citizenCard("測試人員"))
        var held = emptyList<HeldMoicaCard>()
        val holder = Oid4vpHolder(
            s.w.httpClient, s.w.trust, s.w.source, s.w.env, holderIdentities = s.w.holderIdentities, didTrust = s.didTrust,
            dialects = listOf(s.presentation), moicaCards = { held }, moicaHolder = { s.w.holderIdentities.find(HolderIdentities.BONDS_SELF_ISSUED) },
        )
        val request = holder.resolveUri(s.mock.moicaPresentationUri(listOf("name", "birthdate")))
        assertEquals("twdiw", request.profile)
        // Without a self-issued card the request is refused; government cards never answer a vc+moica descriptor.
        s.receive()
        val e = assertFailsWith<ProtocolException> { holder.prepare(request) }
        assertTrue(e.message!!.contains("vc+moica"), e.message)

        held = listOf(HeldMoicaCard("f1", "國民身分證", card))
        val prepared = holder.prepare(holder.resolveUri(s.mock.moicaPresentationUri(listOf("name", "birthdate")))) as PreparedMoica
        assertEquals(listOf("name", "birthdate"), prepared.matches.single().claims)
        val outcome = holder.respond(prepared)
        assertTrue(outcome is PresentationOutcome.Posted, "outcome: $outcome")
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
        // Only the requested disclosures travel; the ID number and address stay on the phone.
        assertEquals(setOf("name", "birthdate"), s.mock.received.single().disclosedNames.toSet())
    }

    @Test
    fun offlinePickupBarcode() = runBlocking<Unit> {
        val s = setup()
        s.receive()
        val service = s.services.offlineServices().single()
        assertEquals(TwdiwPlatformMock.VP_UID_PICKUP, service.vpUid)
        val session = s.services.startOffline(service)
        assertEquals("phone", session.fields.single().ename)
        val request = s.holder.resolveUri(session.entry.uri, TwdiwDialect.ENTRY_HINT)
        s.services.checkOfflineRequest(session, request)
        s.presentation.attachCustomData(request.nonce, session.fields.map { it.copy(value = "0912345678") })
        val outcome = s.holder.respondDefault(s.holder.prepare(request))
        assertTrue(outcome is PresentationOutcome.Posted, "outcome: $outcome")
        val got = s.mock.received.single()
        assertEquals("0912345678", (got.customData.single()["value"] as JsonPrimitive).content)
        val holderKey = assertNotNull(s.w.holderIdentities.find(HolderIdentities.TWDIW))
        val barcode = s.services.barcode(session, holderKey)
        assertTrue(barcode.png.size > 8)
        assertTrue(s.mock.lastTransactionCompleted)
        assertTrue(s.mock.errors.isEmpty(), "mock errors: ${s.mock.errors}")
    }

    @Test
    fun bondsOfflinePresentationOverQrAndLink() = runBlocking<Unit> {
        val s = setup()
        val cred = s.receive().credentials.single() as W3cVcCredential
        val holderKey = assertNotNull(s.w.holderIdentities.find(HolderIdentities.TWDIW))
        val resolver = DidResolver(s.w.httpClient)
        // The verifier shows its challenge as a JSON QR; the holder reads it as untrusted text.
        val request = BondsPresentationRequest.generate("會員身分查驗", BondsCredentialSource.TWDIW, audience = "櫃台 1")
        val scanned = request.encode()
        assertTrue(BondsPresentationRequest.looksLike(scanned))
        val parsed = BondsPresentationRequest.parse(scanned)
        assertEquals(request, parsed)
        assertEquals(listOf("name", "birthDate", "cardNumber"), BondsOfflinePresentation.disclosableClaims(cred).map { it.first })
        val jws = BondsOfflinePresentation.present(parsed, cred, holderKey, resolver, disclosing = setOf("name"))
        val verifier = BondsOfflineVerifier(resolver)

        // Rotating QR frames, scanned out of order and with repeats; every frame fits a QR code at ECC Q.
        val frames = BondsOfflinePresentation.qrFrames(jws)
        frames.forEach { QrEncoder.encode(it, QrEncoder.Ecc.Q) }
        val collector = BondsFrameCollector()
        var payload: ByteArray? = null
        for (f in (frames.reversed() + frames)) {
            val r = collector.accept(f)
            if (r is BondsReception.Completed) { payload = r.payload; break }
        }
        val viaQr = verifier.verify(assertNotNull(payload).decodeToString(), request)
        assertEquals(mapOf("name" to "林哲全"), viaQr.claims)
        assertEquals(s.mock.issuerDid, viaQr.issuer)
        assertEquals(holderKey.did, viaQr.holder)
        assertTrue(viaQr.boundToAudience)

        // BLE link frames at a 185 byte MTU, delivered in reverse.
        val link = BondsLinkCollector()
        var linked: ByteArray? = null
        for (f in BondsOfflinePresentation.linkFrames(jws, 185 - 3).reversed()) {
            assertTrue(f.size <= 182)
            val r = link.accept(f)
            if (r is BondsReception.Completed) linked = r.payload
        }
        assertEquals(jws, assertNotNull(linked).decodeToString())

        // A presentation answers only the challenge it was made for.
        val other = BondsPresentationRequest.generate("會員身分查驗", BondsCredentialSource.TWDIW, audience = "櫃台 1")
        assertFailsWith<ProtocolException> { verifier.verify(jws, other) }
        // Self-issued (vc+moica) cards are P5; the wallet says so instead of answering with another card.
        val selfIssued = BondsPresentationRequest.generate("會員身分查驗", BondsCredentialSource.SELF_ISSUED)
        assertFailsWith<ProtocolException> { BondsOfflinePresentation.present(selfIssued, cred, holderKey, resolver) }
    }

    @Test
    fun offlineModuleOutsideTrustListIsRefused() = runBlocking<Unit> {
        val s = setup()
        val stranger = diw.wallet.core.profile.twdiw.TwdiwOfflineService("x", "x", "https://counter.example.org", null)
        val e = assertFailsWith<ProtocolException> { s.services.startOffline(stranger) }
        assertEquals("untrusted_verifier", e.code)
        assertEquals(TrustTier.T4, s.services.offlineModuleDecision("counter.example.org").tier)
    }

    /**
     * On the production platform a listed module whose Arbitrum anchor cannot be confirmed is T2, and a module the
     * platform hosts for an organisation (a tax ID subdomain of wallet.gov.tw) is T2 too: both are highly trusted
     * and open without the risk confirmation that a T4 host needs.
     */
    @Test
    fun offlineModuleT2IsNotTreatedAsUnknown() = runBlocking<Unit> {
        val s = setup()
        val production = TwdiwPlatform(frontendUrl = TwdiwPlatformMock.FRONTEND, test = false)
        val services = TwdiwServices(s.w.httpClient, TwdiwTrustList(s.w.httpClient, production, storage = s.w.storage), production)
        val listed = services.offlineModuleDecision(TwdiwPlatformMock.VERIFIER_HOST)
        assertEquals(TrustTier.T2, listed.tier, "reasons: ${listed.reasons}")
        val hosted = services.offlineModuleDecision("52005408.wallet.gov.tw")
        assertEquals(TrustTier.T2, hosted.tier)
        assertEquals(TrustTier.T4, services.offlineModuleDecision("52005408.wallet.gov.tw.example.org").tier)
        services.startOffline(services.offlineServices().single())
    }
}

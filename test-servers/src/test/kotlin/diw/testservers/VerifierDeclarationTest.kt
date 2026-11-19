package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.oid4vp.AttestationVerdict
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.VerifierAttestation
import diw.wallet.core.oid4vp.VerifierInfoChecker
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.verifier.CheckStatus
import diw.wallet.core.verifier.CredentialVerification
import diw.wallet.core.verifier.PresentationVerifier
import diw.wallet.core.verifier.RequestObjectBuilder
import diw.wallet.core.verifier.VerificationPolicy
import diw.wallet.core.verifier.AssuranceLevel
import diw.wallet.core.verifier.VerifierRequestSpec
import diw.wallet.core.verifier.declaration.CertificateJwsSigner
import diw.wallet.core.verifier.declaration.DeclarationContent
import diw.wallet.core.verifier.declaration.DeclarationEvidence
import diw.wallet.core.verifier.declaration.DidJwsSigner
import diw.wallet.core.verifier.declaration.EvidenceVerifier
import diw.wallet.core.verifier.declaration.JwsSigner
import diw.wallet.core.verifier.declaration.MandateContent
import diw.wallet.core.verifier.declaration.PartyId
import diw.wallet.core.verifier.declaration.VerifierAgent
import diw.wallet.core.verifier.declaration.VerifierDeclaration
import diw.wallet.core.verifier.declaration.VerifierDeclarationCheck
import diw.wallet.core.verifier.declaration.VerifierKind
import diw.wallet.core.verifier.declaration.VerifierMandate
import diw.wallet.core.verifier.declaration.VerifierParty
import diw.wallet.core.verifier.declaration.VerifierPurpose
import io.ktor.http.encodeURLParameter
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.asn1.ASN1Integer
import org.multipaz.asn1.ASN1String
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509CertChain
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.mdoc.util.MdocUtil
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.pgp.OpenPgpTapSigner
import diw.wallet.core.document.pgp.OpenPgpTrust
import diw.wallet.core.document.pgp.OpenPgpTrustedKey
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.verifier.declaration.InspectorOpenPgpEvidenceVerifier
import org.multipaz.crypto.X509Cert
import org.multipaz.util.toBase64
import kotlin.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/** Verifier declarations, evidence presentations and mandates (docs/design/p5-verifier.md sections 4 and 5). */
class VerifierDeclarationTest {
    private val party = VerifierParty(legal = true, name = "Example Co", id = PartyId(PartyId.TW_UBN, "12345678"))
    private val agent = VerifierAgent("Lin Che-Chuan", "Inspector")
    private val purpose = VerifierPurpose("Age check at the counter", "en", "legal_obligation", "none", "https://example.invalid/privacy")

    /** An mDL age query, and the same credential declared by the verifier. */
    private val ageQuery = buildJsonObject {
        putJsonArray("credentials") {
            addJsonObject {
                put("id", "mdl"); put("format", "mso_mdoc")
                putJsonObject("meta") { put("doctype_value", DrivingLicense.MDL_DOCTYPE) }
                putJsonArray("claims") { addJsonObject { putJsonArray("path") { add(DrivingLicense.MDL_NAMESPACE); add("age_over_18") } } }
            }
        }
    }
    private val declaredAge: JsonArray = buildJsonArray {
        addJsonObject {
            put("format", "mso_mdoc")
            putJsonObject("meta") { put("doctype_value", DrivingLicense.MDL_DOCTYPE) }
            putJsonArray("claim") { addJsonObject { putJsonArray("path") { add(DrivingLicense.MDL_NAMESPACE); add("age_over_18") } } }
        }
    }
    private val pidQuery = buildJsonObject {
        put("id", "agent"); put("format", "dc+sd-jwt")
        putJsonObject("meta") { putJsonArray("vct_values") { add(EUPersonalID.EUPID_VCT) } }
        putJsonArray("claims") {
            addJsonObject { putJsonArray("path") { add("given_name") } }
            addJsonObject { putJsonArray("path") { add("family_name") } }
        }
    }

    private class Setup(val pki: TestPki, val holder: WalletFixture, val verifierWallet: WalletFixture)

    private suspend fun setup(): Setup {
        val pki = TestPki.create()
        val holder = WalletFixture().init(pki)
        holder.issueMdl(pki)
        val verifierWallet = WalletFixture().init(pki)
        verifierWallet.issueSdJwtPid(pki)
        return Setup(pki, holder, verifierWallet)
    }

    private suspend fun didSigner(): DidJwsSigner {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val did = DidKeys.didKey(key.publicKey)
        return DidJwsSigner(AsymmetricKey.anonymous(key, Algorithm.ES256), did, DidKeys.verificationMethod(did))
    }

    /** A certificate for an organisation (organizationIdentifier NTRTW-<id>) chained to the test reader root. */
    private suspend fun organizationSigner(pki: TestPki, name: String, ubn: String): DocumentSigner {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val root = pki.readerRootCert
        val subject = X500Name(linkedMapOf(
            "2.5.4.6" to ASN1String("TW"),
            "2.5.4.10" to ASN1String(name),
            "2.5.4.97" to ASN1String("NTRTW-$ubn"),
            "2.5.4.3" to ASN1String("$name verifier"),
        ))
        val cert = MdocUtil.generateReaderCertificate(
            readerRootKey = pki.readerRoot,
            readerKey = key.publicKey,
            subject = subject,
            dnsName = "verifier.example.invalid",
            serial = ASN1Integer.fromRandom(128),
            validFrom = root.validityNotBefore,
            validUntil = root.validityNotAfter,
        )
        val chain = X509CertChain(listOf(cert, root))
        return object : DocumentSigner {
            override val certificateChain: List<ByteArray> = chain.certificates.map { it.encoded.toByteArray() }
            override val keyType = SignerKeyType.EC_P256
            override val source = SignerSource.PKCS12
            override suspend fun sign(data: ByteArray): ByteArray = (Crypto.sign(key, Algorithm.ES256, data)).toDerEncoded()
        }
    }

    private suspend fun request(signer: JwsSigner, nonce: String, verifierInfo: List<JsonObject>, dcql: JsonObject = ageQuery): String {
        val spec = VerifierRequestSpec(
            clientId = signer.clientId,
            responseMode = "direct_post",
            nonce = nonce,
            dcqlQuery = dcql,
            responseUri = "http://127.0.0.1:9/response",
            state = "s1",
            verifierInfo = JsonArray(verifierInfo),
        )
        val jws = RequestObjectBuilder.sign(spec, signer)
        return "openid4vp://?client_id=${signer.clientId.encodeURLParameter()}&request=$jws"
    }

    private fun checker(w: WalletFixture): VerifierInfoChecker {
        val presentations = PresentationVerifier(w.trust, w.documentTypes, null, didResolver = DidResolver(w.httpClient, true))
        val evidence = EvidenceVerifier { q, t, c, n -> presentations.verifyEvidence(q, t, c, n) }
        return VerifierInfoChecker(w.trust, null, VerifierDeclarationCheck(w.trust, DidResolver(w.httpClient, true), DidTrust.NONE, evidence))
    }

    private suspend fun checked(w: WalletFixture, uri: String): Pair<ValidatedAuthorizationRequest, VerifierAttestation> {
        val validated = w.holder.resolveUri(uri)
        val list = checker(w).check(validated)
        return validated to list.single { it.format == VerifierDeclaration.FORMAT }
    }

    private suspend fun mandate(pki: TestPki, clientId: String, principalName: String = party.name, ubn: String = "12345678"): String {
        val now = Clock.System.now()
        return VerifierMandate.sign(
            MandateContent(VerifierParty(true, principalName, PartyId(PartyId.TW_UBN, ubn)), agent, listOf(clientId),
                purposes = listOf(purpose.text), credentials = declaredAge, notBefore = now - 1.days, expiresAt = now + 30.days),
            CertificateJwsSigner(organizationSigner(pki, principalName, ubn)),
            issuer = "NTRTW-$ubn",
        )
    }

    @Test
    fun agentForLegalPersonWithMandateAndPid() = runBlocking<Unit> {
        val s = setup()
        val signer = didSigner()
        val nonce = "n-" + Clock.System.now().toEpochMilliseconds() + "-declaration"
        val vp = s.verifierWallet.holder.evidence(signer.clientId, nonce, pidQuery)
        val declaration = VerifierDeclaration.sign(
            DeclarationContent(VerifierKind.FOR_LEGAL_PERSON, party, agent, purpose, declaredAge),
            signer.clientId, nonce,
            listOf(DeclarationEvidence.Presentation(DeclarationEvidence.ROLE_AGENT, pidQuery, vp), DeclarationEvidence.Mandate(mandate(s.pki, signer.clientId))),
            signer,
        )
        val (_, a) = checked(s.holder, request(signer, nonce, listOf(VerifierDeclaration.entry(declaration))))
        val id = assertNotNull(a.identity)
        assertTrue(id.bound, id.problems.toString())
        assertEquals(VerifierKind.FOR_LEGAL_PERSON, id.content?.kind)
        assertEquals("Example Co", a.name)
        assertEquals(listOf(purpose.text), a.purposes)
        assertEquals(2, id.evidence.size)
        assertTrue(id.evidence.all { it.passed }, id.evidence.toString())
        assertTrue(id.checks.any { it.name.isNotEmpty() && it.status == CheckStatus.PASS && it.detail == EUPersonalID.EUPID_VCT }, id.checks.toString())
        assertTrue(id.checks.none { it.status == CheckStatus.FAIL }, id.checks.toString())
        assertEquals(emptyList(), id.outsideDeclaration)
        // A DID request signature is T3, so the identity is never shown above that.
        assertEquals(TrustTier.T3, id.tier)
        assertEquals(AttestationVerdict.PARTIAL, a.verdict)
    }

    @Test
    fun declarationOfAnotherRequestIsNotBound() = runBlocking<Unit> {
        val s = setup()
        val signer = didSigner()
        val content = DeclarationContent(VerifierKind.LEGAL_PERSON, party, null, purpose, declaredAge)
        val otherNonce = VerifierDeclaration.sign(content, signer.clientId, "other-nonce-0123456789", emptyList(), signer)
        val (_, a) = checked(s.holder, request(signer, "this-nonce-0123456789", listOf(VerifierDeclaration.entry(otherNonce))))
        assertEquals(AttestationVerdict.INVALID, a.verdict)
        assertFalse(a.identity!!.bound)

        val otherKey = didSigner()
        val foreign = VerifierDeclaration.sign(content, signer.clientId, "this-nonce-0123456789", emptyList(), otherKey)
        val (_, b) = checked(s.holder, request(signer, "this-nonce-0123456789", listOf(VerifierDeclaration.entry(foreign))))
        assertEquals(AttestationVerdict.INVALID, b.verdict)
        assertFalse(b.identity!!.bound)
    }

    @Test
    fun requestBeyondTheDeclarationIsListed() = runBlocking<Unit> {
        val s = setup()
        val signer = didSigner()
        val nonce = "nonce-beyond-0123456789"
        val wider = buildJsonObject {
            putJsonArray("credentials") {
                addJsonObject {
                    put("id", "mdl"); put("format", "mso_mdoc")
                    putJsonObject("meta") { put("doctype_value", DrivingLicense.MDL_DOCTYPE) }
                    putJsonArray("claims") {
                        addJsonObject { putJsonArray("path") { add(DrivingLicense.MDL_NAMESPACE); add("age_over_18") } }
                        addJsonObject { putJsonArray("path") { add(DrivingLicense.MDL_NAMESPACE); add("family_name") } }
                    }
                }
            }
        }
        val d = VerifierDeclaration.sign(DeclarationContent(VerifierKind.LEGAL_PERSON, party, null, purpose, declaredAge), signer.clientId, nonce, emptyList(), signer)
        val (_, a) = checked(s.holder, request(signer, nonce, listOf(VerifierDeclaration.entry(d)), wider))
        val outside = assertNotNull(a.identity?.outsideDeclaration)
        assertEquals(1, outside.size, outside.toString())
        assertTrue("family_name" in outside.single())
        assertEquals(AttestationVerdict.PARTIAL, a.verdict)
    }

    @Test
    fun mandateForAnotherKeyOrPartyFails() = runBlocking<Unit> {
        val s = setup()
        val signer = didSigner()
        val nonce = "nonce-mandate-0123456789"
        val other = didSigner()
        val content = DeclarationContent(VerifierKind.FOR_LEGAL_PERSON, party, agent, purpose, declaredAge)
        val d = VerifierDeclaration.sign(content, signer.clientId, nonce,
            listOf(DeclarationEvidence.Mandate(mandate(s.pki, other.clientId))), signer)
        val (_, a) = checked(s.holder, request(signer, nonce, listOf(VerifierDeclaration.entry(d))))
        val m = a.identity!!.evidence.single()
        assertTrue(m.mandate)
        assertFalse(m.passed)

        val d2 = VerifierDeclaration.sign(content, signer.clientId, nonce,
            listOf(DeclarationEvidence.Mandate(mandate(s.pki, signer.clientId, "Other Co", "87654321"))), signer)
        val (_, b) = checked(s.holder, request(signer, nonce, listOf(VerifierDeclaration.entry(d2))))
        assertFalse(b.identity!!.evidence.single().passed)
    }

    @Test
    fun accessCertificateNamesTheLegalPerson() = runBlocking<Unit> {
        val s = setup()
        val signer = CertificateJwsSigner(organizationSigner(s.pki, "Example Co", "12345678"))
        assertTrue(signer.clientId.startsWith("x509_hash:"))
        val nonce = "nonce-x509-0123456789"
        val d = VerifierDeclaration.sign(DeclarationContent(VerifierKind.LEGAL_PERSON, party, null, purpose, declaredAge), signer.clientId, nonce, emptyList(), signer)
        val (validated, a) = checked(s.holder, request(signer, nonce, listOf(VerifierDeclaration.entry(d))))
        val id = a.identity!!
        assertTrue(id.bound, id.problems.toString())
        assertTrue(id.checks.any { it.status == CheckStatus.PASS }, id.checks.toString())
        assertEquals(validated.verifier.trust.tier, id.tier)

        val wrong = VerifierDeclaration.sign(
            DeclarationContent(VerifierKind.LEGAL_PERSON, party.copy(id = PartyId(PartyId.TW_UBN, "99999999")), null, purpose, declaredAge),
            signer.clientId, nonce, emptyList(), signer)
        val (_, b) = checked(s.holder, request(signer, nonce, listOf(VerifierDeclaration.entry(wrong))))
        assertTrue(b.identity!!.checks.any { it.status == CheckStatus.FAIL }, b.identity!!.checks.toString())
    }

    @Test
    fun openPgpCardSignsTheRequest() = runBlocking<Unit> {
        val s = setup()
        val signer = didSigner()
        val nonce = "nonce-openpgp-0123456789"
        val sim = OpenPgpCardSim(SimKey.ED25519, null)
        val card = OpenPgpTapSigner(sim.reader(), sim.pin)
        card.load(x509 = false)
        val asc = card.signDetached(DeclarationEvidence.openPgpStatement(signer.clientId, nonce)).decodeToString()
        val cert = sim.certificate.getEncoded(true)
        val person = VerifierParty(legal = false, name = "Chu Lin")
        suspend fun declaration(signature: String, sent: ByteArray?) = VerifierDeclaration.sign(
            DeclarationContent(VerifierKind.NATURAL_PERSON, person, null, purpose, declaredAge), signer.clientId, nonce,
            listOf(DeclarationEvidence.OpenPgp(DeclarationEvidence.ROLE_PARTY, signature, sent?.toBase64())), signer,
        )
        suspend fun identity(listed: List<OpenPgpTrustedKey>, declaration: String): diw.wallet.core.verifier.declaration.VerifierIdentity {
            val source = object : DocumentTrustSource {
                override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant) = TrustDecision(TrustTier.T4, null, false, null, emptySet())
                override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
                override suspend fun openPgpKeys(): List<OpenPgpTrustedKey> = listed
            }
            val w = s.holder
            val check = VerifierDeclarationCheck(w.trust, DidResolver(w.httpClient, true), DidTrust.NONE, null, InspectorOpenPgpEvidenceVerifier(source))
            val validated = w.holder.resolveUri(request(signer, nonce, listOf(VerifierDeclaration.entry(declaration))))
            return VerifierInfoChecker(w.trust, null, check).check(validated).single { it.format == VerifierDeclaration.FORMAT }.identity!!
        }

        // The holder verified this key: the signature names the person, at T2.
        val verified = identity(listOf(OpenPgpTrustedKey(cert, "Chu Lin", OpenPgpTrust.VERIFIED)), declaration(asc, null))
        val e = verified.evidence.single()
        assertTrue(e.passed, e.toString())
        assertEquals(TrustTier.T2, e.trust?.tier)
        assertEquals("Chu Lin", e.claims["name"])
        assertEquals("chu@example.org", e.claims["email"])
        assertTrue(verified.checks.any { it.status == CheckStatus.PASS && it.detail == e.title }, verified.checks.toString())

        // Not in the holder's list: the sent certificate checks the signature, but only as unverified (T3).
        val sent = identity(emptyList(), declaration(asc, cert)).evidence.single()
        assertTrue(sent.passed, sent.toString())
        assertEquals(TrustTier.T3, sent.trust?.tier)

        // Neither listed nor sent: nothing to check it with.
        assertFalse(identity(emptyList(), declaration(asc, null)).evidence.single().passed)

        // A signature over another request's nonce does not verify.
        val other = card.signDetached(DeclarationEvidence.openPgpStatement(signer.clientId, "another-nonce-0123456789")).decodeToString()
        assertFalse(identity(listOf(OpenPgpTrustedKey(cert, "Chu Lin", OpenPgpTrust.VERIFIED)), declaration(other, null)).evidence.single().passed)

        // A key the holder refused is not accepted.
        assertFalse(identity(listOf(OpenPgpTrustedKey(cert, "Chu Lin", OpenPgpTrust.DISTRUSTED)), declaration(asc, null)).evidence.single().passed)
    }

    @Test
    fun policyAssuranceLevels() {
        fun cv(trust: TrustDecision, derived: Boolean = false, zk: Boolean = false) =
            CredentialVerification("q", "dc+sd-jwt", "t", emptyMap(), emptyList(), trust, derived = derived, zkProof = zk)
        val t2 = TrustDecision(TrustTier.T2, diw.wallet.core.env.TrustEnvironment.PRODUCTION, false, "root", emptySet())
        val test = TrustDecision(TrustTier.T3, diw.wallet.core.env.TrustEnvironment.TEST, false, "test", emptySet())
        val user = TrustDecision(TrustTier.T3, diw.wallet.core.env.TrustEnvironment.USER, false, "wallet", emptySet())
        assertEquals(AssuranceLevel.TRUSTED_ISSUER, VerificationPolicy.assurance(cv(t2)))
        assertEquals(AssuranceLevel.SANDBOX, VerificationPolicy.assurance(cv(test)))
        assertEquals(AssuranceLevel.HOLDER_DERIVED, VerificationPolicy.assurance(cv(user, derived = true)))
        assertEquals(AssuranceLevel.DOCUMENT_DERIVED, VerificationPolicy.assurance(cv(user, derived = true, zk = true)))
        val policy = VerificationPolicy()
        assertEquals(CheckStatus.PASS, policy.evaluate(cv(t2)).status)
        assertEquals(CheckStatus.FAIL, policy.evaluate(cv(user, derived = true)).status)
        assertEquals(CheckStatus.FAIL, VerificationPolicy(requireZeroKnowledge = true).evaluate(cv(t2)).status)
    }
}

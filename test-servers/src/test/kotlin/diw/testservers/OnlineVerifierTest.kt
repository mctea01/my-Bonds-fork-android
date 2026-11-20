package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.sign.SignedDataHttp
import diw.wallet.core.oid4vp.AttestationVerdict
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.VerifierInfoChecker
import diw.wallet.core.profile.bonds.SocketBondsLanLink
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.verifier.AssuranceLevel
import diw.wallet.core.verifier.CheckStatus
import diw.wallet.core.verifier.OnlineVerifierRequests
import diw.wallet.core.verifier.PresentationVerifier
import diw.wallet.core.verifier.VerificationPolicy
import diw.wallet.core.verifier.declaration.DeclarationContent
import diw.wallet.core.verifier.declaration.DeclarationEvidence
import diw.wallet.core.verifier.declaration.DidJwsSigner
import diw.wallet.core.verifier.declaration.EvidenceQueries
import diw.wallet.core.verifier.declaration.EvidenceVerifier
import diw.wallet.core.verifier.declaration.VerifierDeclaration
import diw.wallet.core.verifier.declaration.VerifierDeclarationCheck
import diw.wallet.core.verifier.declaration.VerifierKind
import diw.wallet.core.verifier.declaration.VerifierParty
import diw.wallet.core.verifier.declaration.VerifierPurpose
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Two wallets, one verifying the other online (docs/design/p5-verifier.md section 6): a signed direct_post.jwt
 * request with a declaration and evidence, served and answered on the local network, then judged by a policy.
 */
class OnlineVerifierTest {
    private val ageQuery = buildJsonObject {
        putJsonArray("credentials") {
            addJsonObject {
                put("id", "mdl"); put("format", "mso_mdoc")
                putJsonObject("meta") { put("doctype_value", DrivingLicense.MDL_DOCTYPE) }
                putJsonArray("claims") { addJsonObject { putJsonArray("path") { add(DrivingLicense.MDL_NAMESPACE); add("age_over_18") } } }
            }
        }
    }

    private suspend fun didSigner(): DidJwsSigner {
        val key = Crypto.createEcPrivateKey(EcCurve.P256)
        val did = DidKeys.didKey(key.publicKey)
        return DidJwsSigner(AsymmetricKey.anonymous(key, Algorithm.ES256), did, DidKeys.verificationMethod(did))
    }

    private fun verifierOf(w: WalletFixture) = PresentationVerifier(w.trust, w.documentTypes, null, didResolver = DidResolver(w.httpClient, true))

    @Test
    fun twoWalletsOnTheLocalNetwork() = runBlocking<Unit> {
        val pki = TestPki.create()
        val link = SocketBondsLanLink()
        val lanHttp = SignedDataHttp { url, body, type, accept -> link.exchange(url, body, type, accept, 10.seconds) }
        // Loopback http is otherwise allowed in tests; off here so the request takes the local network route only.
        val holder = WalletFixture(policy = PresentationPolicy(allowLanEndpoints = true), lanHttp = lanHttp,
            env = diw.wallet.core.env.EnvironmentPolicy(testEnvironmentEnabled = true, allowInsecureLoopbackHttp = false)).init(pki)
        holder.issueMdl(pki)
        val verifierWallet = WalletFixture().init(pki)
        verifierWallet.issueSdJwtPid(pki)
        val signer = didSigner()

        // The evidence query of the verifier's own PID discloses its names only.
        val pidDoc = verifierWallet.documentStore.listDocuments()
            .first { d -> d.getCertifiedCredentials().any { it is org.multipaz.sdjwt.credential.SdJwtVcCredential } }
        val pidQuery = assertNotNull(EvidenceQueries.forCredential("agent0", pidDoc.getCertifiedCredentials().first(), verifierWallet.documentTypes))
        val paths = (pidQuery["claims"] as kotlinx.serialization.json.JsonArray).map { it.toString() }
        assertTrue(paths.any { "given_name" in it } && paths.none { "birth" in it }, paths.toString())

        val secret = "s3cret"
        val requestPath = OnlineVerifierRequests.LAN_REQUEST + "/" + secret
        val listening = CompletableDeferred<String>()
        val built = CompletableDeferred<String>()
        val served = async {
            link.serve(listOf("127.0.0.1"), OnlineVerifierRequests.LAN_RESPONSE + "/" + secret, 4 shl 20,
                onListening = { listening.complete(it.single()) },
                get = { target -> if (target == requestPath) "application/oauth-authz-req+jwt" to built.await().encodeToByteArray() else null },
            ) { "{}".encodeToByteArray() to true }
        }
        val responseUri = listening.await()
        val requestUri = responseUri.substringBefore(OnlineVerifierRequests.LAN_RESPONSE) + requestPath
        val request = OnlineVerifierRequests.build(signer, ageQuery, requestUri, responseUri) { clientId, nonce ->
            val content = DeclarationContent(
                VerifierKind.NATURAL_PERSON,
                VerifierParty(legal = false, name = "Che-Chuan Lin"),
                null,
                VerifierPurpose("Age check", "en", "consent", "none"),
                null,
            )
            val vp = verifierWallet.holder.evidence(clientId, nonce, pidQuery, pidDoc.identifier)
            listOf(VerifierDeclaration.entry(VerifierDeclaration.sign(content, clientId, nonce,
                listOf(DeclarationEvidence.Presentation(DeclarationEvidence.ROLE_PARTY, pidQuery, vp)), signer)))
        }
        built.complete(request.requestObject)
        assertTrue(request.invocation.startsWith("openid4vp://?client_id=decentralized_identifier"))

        val validated = holder.holder.resolveUri(request.invocation)
        assertTrue(validated.warnings.isNotEmpty(), "the holder is told the response stays on the local network")
        val evidence = verifierOf(holder).let { v -> EvidenceVerifier { q, t, c, n -> v.verifyEvidence(q, t, c, n) } }
        val attestation = VerifierInfoChecker(holder.trust, null, VerifierDeclarationCheck(holder.trust, DidResolver(holder.httpClient, true), DidTrust.NONE, evidence))
            .check(validated).single()
        val identity = assertNotNull(attestation.identity)
        // Bound and backed by its evidence; a did:key verifier and a test issuer keep it below the confirmed tiers.
        assertTrue(identity.bound && identity.evidence.single().passed, identity.toString())
        assertTrue(identity.checks.all { it.status == CheckStatus.PASS }, identity.checks.toString())
        assertEquals(AttestationVerdict.PARTIAL, attestation.verdict)
        assertEquals("Che-Chuan Lin", attestation.name)

        val outcome = holder.holder.respondDefault(holder.holder.prepare(validated))
        assertTrue(outcome is PresentationOutcome.Posted)
        val body = withTimeout(10.seconds) { served.await() }
        val form = OnlineVerifierRequests.form(body)
        assertNotNull(form["response"], "the response is encrypted (direct_post.jwt)")

        val result = verifierOf(verifierWallet).verifyDirectPost(form, request.session)
        assertTrue(result.passed, result.toString())
        val c = result.credentials.single()
        assertEquals("true", c.claims.values.single().trim('"'))
        assertEquals(AssuranceLevel.SANDBOX, VerificationPolicy.assurance(c))
        assertEquals(CheckStatus.FAIL, VerificationPolicy().evaluate(c).status, "a test issuer is not accepted by default")
        assertEquals(CheckStatus.PASS, VerificationPolicy(setOf(AssuranceLevel.SANDBOX)).evaluate(c).status)
    }

    @Test
    fun localNetworkRequestsNeedThePolicy() = runBlocking<Unit> {
        val pki = TestPki.create()
        val link = SocketBondsLanLink()
        val holder = WalletFixture(lanHttp = { url, body, type, accept -> link.exchange(url, body, type, accept, 5.seconds) },
            env = diw.wallet.core.env.EnvironmentPolicy(testEnvironmentEnabled = true, allowInsecureLoopbackHttp = false)).init(pki)
        val signer = didSigner()
        val request = OnlineVerifierRequests.build(signer, ageQuery, "http://192.168.1.20:8123/diw-oid4vp/request/x", "http://192.168.1.20:8123/diw-oid4vp/response/x")
        assertFailsWith<Exception> { holder.holder.resolveUri(request.invocation) }
        // Not a LAN address shape: an http response_uri elsewhere is refused even with the policy on.
        val lanHolder = WalletFixture(policy = PresentationPolicy(allowLanEndpoints = true)).init(pki)
        val outside = OnlineVerifierRequests.invocation(signer.clientId, "http://203.0.113.5/diw-oid4vp/request/x")
        assertFailsWith<Exception> { lanHolder.holder.resolveUri(outside) }
    }
}

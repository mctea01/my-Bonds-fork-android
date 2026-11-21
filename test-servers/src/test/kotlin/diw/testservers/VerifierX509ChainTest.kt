package diw.testservers

import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.verifier.RequestObjectBuilder
import diw.wallet.core.verifier.VerifierRequestSpec
import diw.wallet.core.verifier.declaration.CertificateJwsSigner
import diw.wallet.core.verifier.declaration.JwsSigner
import io.ktor.http.encodeURLParameter
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * A verifier's X.509 identity sends its intermediates: the x5c of a request signed with a key whose store holds the
 * leaf alone is completed up to, not including, the root (TrustRegistry.chainToSend), and a holder that has the root
 * as an anchor but not the intermediate reaches it only through that chain.
 */
class VerifierX509ChainTest {
    private val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
    private val rootKey = gen.generateKeyPair()
    private val midKey = gen.generateKeyPair()
    private val leafKey = gen.generateKeyPair()
    private val root = cert("CN=Chain Test Root,C=TW", "CN=Chain Test Root,C=TW", rootKey, rootKey, ca = true)
    private val mid = cert("CN=Chain Test CA,C=TW", "CN=Chain Test Root,C=TW", midKey, rootKey, ca = true)
    private val leaf = cert("CN=verifier.example,O=Example Co,C=TW", "CN=Chain Test CA,C=TW", leafKey, midKey, ca = false,
        aia = "http://aia.example/chain-test-ca.cer")

    /** A certificate as CAs issue them: with both key identifiers, which the mdoc trust manager links anchors by. */
    private fun cert(subject: String, issuer: String, key: KeyPair, signer: KeyPair, ca: Boolean, aia: String? = null): X509Cert {
        val now = System.currentTimeMillis()
        val b = JcaX509v3CertificateBuilder(
            X500Name(issuer), BigInteger.valueOf(System.nanoTime()), Date(now - 86_400_000L), Date(now + 365L * 86_400_000L), X500Name(subject), key.public,
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(ca))
            .addExtension(Extension.keyUsage, true, KeyUsage(if (ca) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
            .addExtension(Extension.subjectKeyIdentifier, false, JcaX509ExtensionUtils().createSubjectKeyIdentifier(key.public))
            .addExtension(Extension.authorityKeyIdentifier, false, JcaX509ExtensionUtils().createAuthorityKeyIdentifier(signer.public))
        if (aia != null) {
            b.addExtension(Extension.authorityInfoAccess, false, AuthorityInformationAccess(
                AccessDescription(AccessDescription.id_ad_caIssuers, GeneralName(GeneralName.uniformResourceIdentifier, aia)),
            ))
        }
        return X509Cert(ByteString(b.build(JcaContentSignerBuilder("SHA256withECDSA").build(signer.private)).encoded))
    }

    /** A key store that returns [chain] for the leaf key, as a card or PKCS#12 file may. */
    private fun storeSigner(chain: List<X509Cert>) = object : DocumentSigner {
        override val certificateChain: List<ByteArray> = chain.map { it.encoded.toByteArray() }
        override val keyType = SignerKeyType.EC_P256
        override val source = SignerSource.PKCS12
        override suspend fun sign(data: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(leafKey.private); update(data); sign() }
    }

    private fun bytes(chain: List<X509Cert>) = chain.map { it.encoded.toByteArray() }

    private suspend fun request(signer: JwsSigner): String {
        val dcql = buildJsonObject {
            putJsonArray("credentials") {
                addJsonObject {
                    put("id", "mdl"); put("format", "mso_mdoc")
                    putJsonObject("meta") { put("doctype_value", DrivingLicense.MDL_DOCTYPE) }
                    putJsonArray("claims") { addJsonObject { putJsonArray("path") { add(DrivingLicense.MDL_NAMESPACE); add("age_over_18") } } }
                }
            }
        }
        val spec = VerifierRequestSpec(
            clientId = signer.clientId, responseMode = "direct_post", nonce = "nonce-chain-0123456789", dcqlQuery = dcql,
            responseUri = "http://127.0.0.1:9/response", state = "s1",
        )
        return "openid4vp://?client_id=${signer.clientId.encodeURLParameter()}&request=${RequestObjectBuilder.sign(spec, signer)}"
    }

    @Test
    fun chainToSendAddsIntermediatesWithoutTheRoot() = runBlocking<Unit> {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        registry.addIntermediate(mid, "Chain Test CA", "test")
        assertEquals(listOf(leaf, mid), registry.chainToSend(listOf(leaf)), "the intermediate comes from the user's intermediates")
        assertEquals(listOf(leaf, mid), registry.chainToSend(listOf(leaf, mid, root)), "the root is left out")
        assertEquals(listOf(leaf, mid), registry.chainToSend(listOf(leaf, root, mid)), "certificates given out of order are put in order")

        val fresh = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        assertEquals(listOf(leaf), fresh.chainToSend(listOf(leaf)), "nothing known: the leaf alone")
        assertEquals(listOf(root), fresh.chainToSend(listOf(root)), "a self-signed certificate is sent as it is")
        assertEquals(listOf(leaf, mid), fresh.chainToSend(listOf(leaf, mid)), "the chain given is kept")

        // The leaf's AIA caIssuers link fills the gap when no store has the intermediate.
        val aia = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        aia.issuerFetcher = { url -> if (url == "http://aia.example/chain-test-ca.cer") mid.encoded.toByteArray() else null }
        assertEquals(listOf(leaf, mid), aia.chainToSend(listOf(leaf)))

        // A certificate under the right name whose key did not sign the leaf is not sent.
        val impostor = cert("CN=Chain Test CA,C=TW", "CN=Chain Test Root,C=TW", gen.generateKeyPair(), rootKey, ca = true)
        assertEquals(listOf(leaf), fresh.chainToSend(listOf(leaf, impostor)))
    }

    @Test
    fun holderReachesTheRootThroughTheSentIntermediate() = runBlocking<Unit> {
        val holder = WalletFixture().init()
        holder.trust.addAnchor(TrustRole.VERIFIER, TrustEnvironment.USER, root, "Chain Test Root", official = false, source = "test")
        val verifierSide = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        verifierSide.addIntermediate(mid, "Chain Test CA", "test")
        val store = storeSigner(listOf(leaf))

        // The leaf alone: the holder knows the root but not the intermediate, so the verifier stays unanchored.
        val bare = CertificateJwsSigner(store)
        val alone = holder.holder.resolveUri(request(bare))
        assertNull(alone.verifier.trust.environment, alone.verifier.trust.reasons.toString())
        assertEquals(TrustTier.T3, alone.verifier.trust.tier)

        // With the intermediate in x5c the same key reaches the holder's anchor; the client_id does not change.
        val full = CertificateJwsSigner(store, bytes(verifierSide.chainToSend(listOf(leaf))))
        assertEquals(bare.clientId, full.clientId)
        val validated = holder.holder.resolveUri(request(full))
        assertEquals(TrustEnvironment.USER, validated.verifier.trust.environment, validated.verifier.trust.reasons.toString())
        assertEquals(TrustTier.T2, validated.verifier.trust.tier)
        assertEquals(listOf(leaf, mid), validated.verifier.certificateChain!!.certificates)

        // The chain must start with the key's own certificate.
        assertFailsWith<Exception> { CertificateJwsSigner(store, bytes(listOf(mid))) }
    }
}

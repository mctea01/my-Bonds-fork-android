package diw.wallet.core.w3c

import diw.wallet.core.did.Base58
import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.verifySignature
import diw.wallet.core.util.Jcs
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/** RDF Dataset Canonicalization (RDFC-1.0) of a JSON-LD document, as N-Quads. Platform supplied. */
interface LdCanonicalizer {
    suspend fun canonicalize(document: JsonObject): String
}

/** A verified Data Integrity proof. */
data class VerifiedProof(
    val type: String,
    val cryptosuite: String?,
    val verificationMethod: String,
    val proofPurpose: String?,
    val key: VerificationKey,
    val challenge: String?,
    val domain: String?,
    val created: Instant?,
)

/**
 * W3C Data Integrity proofs (ldp_vc, ldp_vp, di_vp): the JCS cryptosuites ecdsa-jcs-2019 and eddsa-jcs-2022 natively,
 * and the RDFC cryptosuites (ecdsa-rdfc-2019, eddsa-rdfc-2022, Ed25519Signature2020, JsonWebSignature2020,
 * EcdsaSecp256k1Signature2019) when an [LdCanonicalizer] is available.
 */
class DataIntegrity(
    private val didResolver: DidResolver,
    private val canonicalizer: LdCanonicalizer? = null,
) {
    /** Verifies the (single, or first matching) proof of [secured]. Throws [ProtocolException] when no proof verifies. */
    suspend fun verify(secured: JsonObject, expectedPurpose: String? = null, challenge: String? = null, domain: String? = null): VerifiedProof {
        val proofs = when (val p = secured["proof"]) {
            is JsonObject -> listOf(p)
            is JsonArray -> p.filterIsInstance<JsonObject>()
            else -> throw ProtocolException("invalid_proof", "Document has no proof")
        }
        val unsecured = JsonObject(secured - "proof")
        var failure: Exception? = null
        for (proof in proofs) {
            try {
                return verifyOne(unsecured, proof, expectedPurpose, challenge, domain)
            } catch (e: Exception) {
                failure = e
            }
        }
        throw failure as? ProtocolException ?: ProtocolException("invalid_proof", failure?.message ?: "No proof verified", failure)
    }

    private suspend fun verifyOne(unsecured: JsonObject, proof: JsonObject, expectedPurpose: String?, challenge: String?, domain: String?): VerifiedProof {
        val type = proof.str("type") ?: throw ProtocolException("invalid_proof", "Proof without type")
        val suite = proof.str("cryptosuite")
        val vm = proof.str("verificationMethod") ?: throw ProtocolException("invalid_proof", "Proof without verificationMethod")
        val purpose = proof.str("proofPurpose")
        if (expectedPurpose != null && purpose != expectedPurpose) throw ProtocolException("invalid_proof", "proofPurpose is $purpose, expected $expectedPurpose")
        if (challenge != null && proof.str("challenge") != challenge) throw ProtocolException("invalid_proof", "challenge does not match")
        if (domain != null && proof["domain"].let { d -> d !is JsonPrimitive || d.content != domain } && (proof["domain"] as? JsonArray)?.any { (it as? JsonPrimitive)?.content == domain } != true) {
            throw ProtocolException("invalid_proof", "domain does not match")
        }
        proof.str("expires")?.let { W3cVc.date(it) }?.let { if (it < Clock.System.now()) throw ProtocolException("invalid_proof", "Proof expired") }
        val method = didResolver.resolveKey(vm.substringBefore('#'), vm)
        val key = method.key
        val ok = when {
            type == "DataIntegrityProof" && (suite == "ecdsa-jcs-2019" || suite == "eddsa-jcs-2022") -> {
                val sig = multibase(proof.str("proofValue"))
                val data = hashData(jcsProofConfig(proof, unsecured), Jcs.canonicalBytes(unsecured), key)
                verifyRaw(key, data, sig)
            }
            type == "DataIntegrityProof" && (suite == "ecdsa-rdfc-2019" || suite == "eddsa-rdfc-2022") -> {
                val sig = multibase(proof.str("proofValue"))
                val data = hashData(rdfc(proofConfigWithContext(proof, unsecured)).encodeToByteArray(), rdfc(unsecured).encodeToByteArray(), key)
                verifyRaw(key, data, sig)
            }
            type == "Ed25519Signature2020" -> {
                val sig = multibase(proof.str("proofValue"))
                val data = hashData(rdfc(proofConfigWithContext(proof, unsecured)).encodeToByteArray(), rdfc(unsecured).encodeToByteArray(), key)
                verifyRaw(key, data, sig)
            }
            type == "JsonWebSignature2020" || type == "EcdsaSecp256k1Signature2019" || type == "Ed25519Signature2018" -> {
                val jws = proof.str("jws") ?: throw ProtocolException("invalid_proof", "$type without jws")
                val (h, _, s) = jws.split('.').also { if (it.size != 3) throw ProtocolException("invalid_proof", "Detached JWS expected") }
                val header = base64UrlJson(h)
                val config = JsonObject(proofConfigWithContext(proof, unsecured) - "jws")
                val verifyData = sha256(rdfc(config).encodeToByteArray()) + sha256(rdfc(unsecured).encodeToByteArray())
                val input = (h + ".").encodeToByteArray() + verifyData
                verifySignature(header.str("alg") ?: "ES256", key, input, s.fromBase64Url())
            }
            else -> throw ProtocolException("unsupported_proof", "Unsupported proof $type ${suite ?: ""}".trim())
        }
        if (!ok) throw ProtocolException("invalid_proof", "Data Integrity signature is invalid ($type ${suite ?: ""})")
        return VerifiedProof(type, suite, vm, purpose, key, proof.str("challenge"), proof.str("domain"), W3cVc.date(proof.str("created")))
    }

    /**
     * Adds a DataIntegrityProof with ecdsa-jcs-2019 (P-256/P-384 keys) or eddsa-jcs-2022 (Ed25519) to [unsecured].
     * [verificationMethod] is the DID URL of [key].
     */
    suspend fun sign(
        unsecured: JsonObject,
        key: AsymmetricKey,
        verificationMethod: String,
        proofPurpose: String,
        challenge: String? = null,
        domain: String? = null,
        created: Instant = Clock.System.now(),
    ): JsonObject {
        val suite = if (key.publicKey.curve == EcCurve.ED25519) "eddsa-jcs-2022" else "ecdsa-jcs-2019"
        val options = buildJsonObject {
            put("type", "DataIntegrityProof")
            put("cryptosuite", suite)
            put("created", Instant.fromEpochSeconds(created.epochSeconds).toString())
            put("verificationMethod", verificationMethod)
            put("proofPurpose", proofPurpose)
            challenge?.let { put("challenge", it) }
            domain?.let { put("domain", it) }
        }
        val config = unsecured["@context"]?.let { JsonObject(options + ("@context" to it)) } ?: options
        val hashData = hashData(Jcs.canonicalBytes(config), Jcs.canonicalBytes(unsecured), key.publicKey.curve)
        val sig = key.sign(hashData)
        val raw = sig.toCoseEncoded()
        val proof = JsonObject(options + ("proofValue" to JsonPrimitive("z" + Base58.encode(raw))))
        return JsonObject(unsecured + ("proof" to proof))
    }

    private fun jcsProofConfig(proof: JsonObject, unsecured: JsonObject): ByteArray = Jcs.canonicalBytes(proofConfigWithContext(proof, unsecured))

    private fun proofConfigWithContext(proof: JsonObject, unsecured: JsonObject): JsonObject {
        val options = JsonObject(proof - "proofValue")
        return unsecured["@context"]?.let { JsonObject(options + ("@context" to it)) } ?: options
    }

    private suspend fun rdfc(doc: JsonObject): String =
        (canonicalizer ?: throw ProtocolException("unsupported_proof", "RDF canonicalization is not available on this platform")).canonicalize(doc)

    private suspend fun hashData(config: ByteArray, document: ByteArray, key: VerificationKey): ByteArray {
        val curve = (key as? VerificationKey.Ec)?.key?.curve
        return hashData(config, document, curve)
    }

    private suspend fun hashData(config: ByteArray, document: ByteArray, curve: EcCurve?): ByteArray {
        val alg = if (curve == EcCurve.P384) Algorithm.SHA384 else Algorithm.SHA256
        return Crypto.digest(alg, config) + Crypto.digest(alg, document)
    }

    private suspend fun verifyRaw(key: VerificationKey, data: ByteArray, sig: ByteArray): Boolean {
        val alg = when (val k = key) {
            is VerificationKey.Ec -> when (k.key.curve) {
                EcCurve.P256 -> "ES256"
                EcCurve.P384 -> "ES384"
                EcCurve.P521 -> "ES512"
                EcCurve.ED25519 -> "EdDSA"
                else -> throw ProtocolException("unsupported_proof", "Unsupported curve ${k.key.curve}")
            }
            is VerificationKey.Secp256k1 -> "ES256K"
            is VerificationKey.Rsa -> "RS256"
        }
        return verifySignature(alg, key, data, sig)
    }

    private fun multibase(v: String?): ByteArray {
        val s = v ?: throw ProtocolException("invalid_proof", "Proof without proofValue")
        return when (s.firstOrNull()) {
            'z' -> Base58.decode(s.substring(1))
            'u' -> s.substring(1).fromBase64Url()
            else -> throw ProtocolException("invalid_proof", "Unsupported multibase prefix in proofValue")
        }
    }

    private suspend fun sha256(b: ByteArray) = Crypto.digest(Algorithm.SHA256, b)

    companion object {
        fun multibaseBase64Url(bytes: ByteArray) = "u" + bytes.toBase64Url()
    }
}

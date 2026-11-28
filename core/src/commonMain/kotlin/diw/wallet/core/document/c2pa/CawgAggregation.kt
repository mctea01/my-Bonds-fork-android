package diw.wallet.core.document.c2pa

import diw.wallet.core.did.DidKeys
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.i18n.ct
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.Jcs
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Cbor
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.EcPublicKeyOkp
import org.multipaz.util.toBase64Url
import kotlin.time.Instant

/**
 * The key of an identity claims aggregator: [did] (a did:jwk whose only key signs) and the COSE [algorithm] (-7
 * ES256 or -8 EdDSA). [sign] returns the raw signature (r||s for ES256, the 64 bytes of Ed25519).
 */
class IcaSigner(val did: String, val algorithm: Int, private val signRaw: suspend (ByteArray) -> ByteArray) {
    /** The verification method of the did:jwk (its only key is "#0"). */
    val keyId: String get() = "$did#0"

    suspend fun sign(data: ByteArray): ByteArray = signRaw(data)

    companion object {
        /** The signer of [publicKey] (P-256 or Ed25519) with its did:jwk ([CawgAggregation.issuerDid]). */
        suspend fun of(publicKey: EcPublicKey, sign: suspend (ByteArray) -> ByteArray): IcaSigner =
            IcaSigner(CawgAggregation.issuerDid(publicKey), CawgAggregation.algorithmOf(publicKey), sign)
    }
}

/**
 * One verifiedIdentities entry (CAWG identity assertion 1.3 section 9.1.2.4): what the aggregator verified about the
 * named actor ([type] such as cawg.document_verification), when ([verifiedAt]) and through which identity provider
 * ([providerId], a URI, and its user-visible [providerName]).
 */
data class CawgVerifiedIdentity(
    val type: String,
    val name: String? = null,
    val username: String? = null,
    val address: String? = null,
    val uri: String? = null,
    val method: String? = null,
    val verifiedAt: Instant,
    val providerId: String,
    val providerName: String,
)

/** An identity assertion of sig_type cawg.identity_claims_aggregation, issued by [signer] for [identities]. */
data class C2paIdentityAggregation(
    val signer: IcaSigner,
    val identities: List<CawgVerifiedIdentity>,
    val validUntil: Instant? = null,
)

/**
 * The wallet as identity claims aggregator (CAWG identity assertion 1.3 section 9.1): a W3C VC 2.0 of type
 * IdentityClaimsAggregationCredential, issued by the wallet's did:jwk, whose credentialSubject lists the identities
 * the wallet verified and binds them to the asset through c2paAsset, the JSON form of signer_payload (byte strings
 * in standard base64). It is secured with COSE (VC-JOSE-COSE 3.3.1): a tagged COSE_Sign1 with content type
 * application/vc and the credential as its attached payload.
 */
object CawgAggregation {
    const val SIG_TYPE = "cawg.identity_claims_aggregation"
    const val VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
    const val ICA_CONTEXT = "https://cawg.io/identity/1.1/ica/context/"
    const val ICA_TYPE = "IdentityClaimsAggregationCredential"
    const val CONTENT_TYPE = "application/vc"
    const val DOCUMENT_VERIFICATION = "cawg.document_verification"
    const val AFFILIATION = "cawg.affiliation"

    /** Every signature of the supported algorithms is 64 bytes, so the reserved size is known before signing. */
    private const val SIGNATURE_SIZE = 64

    /** -7 (ES256) for a P-256 key, -8 (EdDSA) for an Ed25519 key. */
    fun algorithmOf(key: EcPublicKey): Int = when {
        key is EcPublicKeyOkp && key.curve == EcCurve.ED25519 -> -8
        key is EcPublicKeyDoubleCoordinate && key.curve == EcCurve.P256 -> -7
        else -> throw SigningException(ct("core_cawg_ica_key_unsupported", key.curve.name))
    }

    /**
     * did:jwk of [key]: the JCS form of its public JWK with alg. The alg member also makes the JSON of an Ed25519 key
     * 93 bytes long, a multiple of 3, so its base64url form has no padding to drop; c2pa-rs decodes did:jwk with a
     * padded decoder and would refuse an unpadded value of another length.
     */
    suspend fun issuerDid(key: EcPublicKey): String {
        val alg = if (algorithmOf(key) == -8) "EdDSA" else "ES256"
        val jwk = JsonObject(DidKeys.canonicalJwk(key.toJwk()) + ("alg" to JsonPrimitive(alg)))
        return "did:jwk:" + Jcs.canonicalBytes(jwk).toBase64Url()
    }

    /** The rule of CAWG 1.3 section 9.1.2.4 that [v] breaks, or null when it is a valid entry. */
    fun problem(v: CawgVerifiedIdentity): String? {
        if (v.type.isBlank()) return "type"
        for ((k, value) in listOf("name" to v.name, "username" to v.username, "address" to v.address, "uri" to v.uri, "method" to v.method)) {
            if (value != null && value.isEmpty()) return k
        }
        when (v.type) {
            DOCUMENT_VERIFICATION -> if (v.name.isNullOrBlank()) return "name"
            "cawg.social_media" -> if (v.username.isNullOrBlank() || v.uri.isNullOrBlank()) return if (v.username.isNullOrBlank()) "username" else "uri"
            "cawg.crypto_wallet" -> if (v.address.isNullOrBlank()) return "address"
            "cawg.web_site" -> if (v.uri.isNullOrBlank()) return "uri"
        }
        if (v.providerName.isBlank()) return "provider.name"
        if (!uri(v.providerId)) return "provider.id"
        return null
    }

    /** An absolute URI: a scheme (RFC 3986 3.1) and something after it. */
    private fun uri(s: String): Boolean {
        val colon = s.indexOf(':')
        if (colon < 1 || colon == s.length - 1 || s.any { it.isWhitespace() }) return false
        return s[0].isLetter() && s.substring(0, colon).all { it.isLetterOrDigit() || it in "+-." }
    }

    /** Fails with the reason when [a] cannot be issued: no identities, an invalid entry, or validUntil before [issuedAt]. */
    fun check(a: C2paIdentityAggregation, issuedAt: Instant) {
        if (a.identities.isEmpty()) throw SigningException(ct("core_cawg_ica_no_identities"))
        a.identities.forEach { v -> problem(v)?.let { throw SigningException(ct("core_cawg_ica_identity_invalid", v.type, it)) } }
        a.validUntil?.let { if (it <= issuedAt) throw SigningException(ct("core_cawg_ica_valid_until")) }
    }

    /** RFC 3339 date-time in UTC, whole seconds. */
    private fun dateTime(t: Instant): String = Instant.fromEpochSeconds(t.epochSeconds).toString()

    private fun identityJson(v: CawgVerifiedIdentity): JsonObject = buildJsonObject {
        put("type", v.type)
        v.name?.let { put("name", it) }
        v.username?.let { put("username", it) }
        v.address?.let { put("address", it) }
        v.uri?.let { put("uri", it) }
        v.method?.let { put("method", it) }
        put("verifiedAt", dateTime(v.verifiedAt))
        putJsonObject("provider") {
            put("id", v.providerId)
            put("name", v.providerName)
        }
    }

    /** The credential of [a] for [signerPayload] (its CBOR as signed), valid from [issuedAt]. */
    fun credential(a: C2paIdentityAggregation, signerPayload: ByteArray, issuedAt: Instant): JsonObject = buildJsonObject {
        putJsonArray("@context") { add(VC_CONTEXT); add(ICA_CONTEXT) }
        putJsonArray("type") { add("VerifiableCredential"); add(ICA_TYPE) }
        put("issuer", a.signer.did)
        put("validFrom", dateTime(issuedAt))
        a.validUntil?.let { put("validUntil", dateTime(it)) }
        putJsonObject("credentialSubject") {
            putJsonArray("verifiedIdentities") { a.identities.forEach { add(identityJson(it)) } }
            put("c2paAsset", C2paManifests.toJson(Cbor.decode(signerPayload)))
        }
    }

    /**
     * The tagged COSE_Sign1 of the credential for [signerPayload]: protected {1: alg, 3: application/vc, 4: kid},
     * empty unprotected header, the credential JSON as payload. With [sign] false the signature is zeros of the final
     * length, which gives the size to reserve without using the key.
     */
    suspend fun cose(a: C2paIdentityAggregation, signerPayload: ByteArray, issuedAt: Instant, sign: Boolean): ByteArray {
        val vc = DiwJson.encodeToString(JsonObject.serializer(), credential(a, signerPayload, issuedAt)).encodeToByteArray()
        val prot = C2paCbor.rawMap(listOf(
            C2paCbor.int(1) to C2paCbor.int(a.signer.algorithm),
            C2paCbor.int(3) to C2paCbor.tstr(CONTENT_TYPE),
            C2paCbor.int(4) to C2paCbor.bstr(a.signer.keyId.encodeToByteArray()),
        ))
        val signature = if (sign) a.signer.sign(C2paManifests.toBeSigned(prot, vc)) else ByteArray(SIGNATURE_SIZE)
        if (signature.size != SIGNATURE_SIZE) throw SigningException(ct("core_c2pa_ecdsa_format"))
        return C2paCbor.tag(18, C2paCbor.array(listOf(C2paCbor.bstr(prot), C2paCbor.rawMap(emptyList()), C2paCbor.bstr(vc), C2paCbor.bstr(signature))))
    }
}

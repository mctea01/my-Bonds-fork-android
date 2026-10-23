package diw.wallet.core.zktls

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.derived.DerivedClaim
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.jwkThumbprint
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.w3c.SdJwtDisclosures
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.X509Cert
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * A web query result kept as a credential (p4-zkp.md "離線與存證"): an IETF SD-JWT VC bound by cnf to a holder key.
 *
 * - web-proof: the verifier of a zkTLS session signs what it verified, with the key that signed the request, after
 *   every check passed. It is as trusted as that verifier.
 * - web-record: the wallet's own document issuer key signs what the wallet's own TLS connection read. It states what
 *   this device saw, not a zero-knowledge proof; the key attestation chain goes with it where the key has one.
 *
 * Where and how the values were read ([Source], the method) is always visible; the page's fields and the status are
 * selectively disclosable. The query inputs (a serial, a picture code) are never part of it.
 */
object WebProofCredentials {
    const val VCT_PROOF = "urn:diw-wallet:vct:web-proof:1"
    const val VCT_RECORD = "urn:diw-wallet:vct:web-record:1"
    const val METHOD_PROXY = "zktls-proxy"
    const val METHOD_MPC = "zktls-mpc"
    const val METHOD_DEVICE = "device-attested"
    /** The revealed status segment, disclosed like a field. */
    const val CLAIM_STATUS = "queryStatus"
    const val MAX_RECEIPT = 65536

    /** Where the values were read. [certChainSha256] is SHA-256 of each certificate the site presented, leaf first. */
    data class Source(
        val host: String,
        val port: Int,
        val profileId: String,
        val profileTitle: String,
        val official: Boolean,
        val retrievedAt: Long,
        val certChainSha256: List<String>,
        val cipherSuite: String?,
    ) {
        fun toJson(): JsonObject = buildJsonObject {
            put("host", host)
            if (port != 443) put("port", port)
            put("profile", profileId)
            put("profileTitle", profileTitle)
            if (official) put("official", true)
            put("retrievedAt", Instant.fromEpochSeconds(retrievedAt).toString())
            putJsonArray("serverCertSha256") { certChainSha256.forEach { add(it) } }
            put("tlsVersion", "1.2")
            cipherSuite?.let { put("cipherSuite", it) }
        }
    }

    fun source(profile: ZkTlsProfile, time: Long, chain: List<ByteArray>, cipherSuite: String?) = Source(
        profile.host, profile.port, profile.id, profile.title, profile.official, time,
        chain.map { DerivedCredentials.hex(PlatformCrypto.sha256(it)) }, cipherSuite,
    )

    fun method(mode: String): String = if (mode == "mpc") METHOD_MPC else METHOD_PROXY

    /** The selectively disclosable claims of a passed check: each field read, then the status text. */
    fun claims(outcome: ZkTlsOutcome): List<DerivedClaim> =
        outcome.fields.map { (name, value) -> DerivedClaim(name, value, outcome.profile.field(name)?.label) } +
            listOfNotNull(outcome.statusText?.let { DerivedClaim(CLAIM_STATUS, it, "查詢狀態") })

    /** Readable names of the claims, for the credential list. */
    fun claimLabels(profile: ZkTlsProfile): Map<String, String> =
        profile.fields.associate { it.name to it.label } + (CLAIM_STATUS to "查詢狀態")

    /**
     * Signs a credential for [holderJwk] (a public EC JWK). [iss] is the issuer's DID (the header then names its
     * first verification method) unless [chain] is given, which goes in x5c. [session] carries the request's nonce
     * and purpose for a web-proof; [attestation] the key attestation chain for a web-record.
     */
    suspend fun issue(
        vct: String,
        iss: String,
        key: AsymmetricKey,
        holderJwk: JsonObject,
        source: Source,
        method: String,
        claims: List<DerivedClaim>,
        chain: List<X509Cert>? = null,
        session: ZkTlsSessionRequest? = null,
        attestation: List<ByteArray>? = null,
        now: Instant = Clock.System.now(),
    ): String {
        if (claims.isEmpty()) throw ProtocolException("invalid_request", "Nothing to keep")
        if (claims.any { it.name in RESERVED }) throw ProtocolException("invalid_profile", "A field name is reserved")
        val disclosures = DerivedCredentials.disclosures(claims)
        val payload = buildJsonObject {
            put("iss", iss)
            put("iat", now.epochSeconds)
            put("nbf", now.epochSeconds)
            put("vct", vct)
            putJsonObject("cnf") { put("jwk", publicJwk(holderJwk)) }
            put("source", source.toJson())
            put("method", method)
            session?.let { s ->
                putJsonObject("session") {
                    put("nonce", s.nonce)
                    if (s.purpose.isNotEmpty()) put("purpose", s.purpose)
                }
            }
            attestation?.takeIf { it.isNotEmpty() }?.let { certs ->
                putJsonObject("device") { putJsonArray("keyAttestation") { certs.forEach { add(it.toBase64()) } } }
            }
            putJsonArray("_sd") { disclosures.map { SdJwtDisclosures.digest(it) }.sorted().forEach { add(JsonPrimitive(it)) } }
            put("_sd_alg", "sha-256")
        }
        val header = buildJsonObject {
            put("alg", "ES256")
            put("typ", "dc+sd-jwt")
            if (chain != null) putJsonArray("x5c") { chain.forEach { add(it.encoded.toByteArray().toBase64()) } }
            else put("kid", DidKeys.verificationMethod(iss))
        }
        val input = header.toString().encodeToByteArray().toBase64Url() + "." + payload.toString().encodeToByteArray().toBase64Url()
        val jwt = input + "." + key.sign(input.encodeToByteArray()).toCoseEncoded().toBase64Url()
        return (listOf(jwt) + disclosures).joinToString("~") + "~"
    }

    /**
     * The holder's check of a verifier's [receipt]: signed by the key that signed the request of [session], a
     * web-proof for this session and site, bound to [holderJwk], and saying exactly what the holder's own reading of
     * its reveal says ([outcome]). Returns the receipt's resolved payload; throws when any of it does not hold.
     */
    suspend fun checkReceipt(
        receipt: String,
        session: ZkTlsSessionRequest.Verified,
        didResolver: DidResolver,
        holderJwk: JsonObject,
        outcome: ZkTlsOutcome,
    ): JsonObject {
        fun bad(why: String): Nothing = throw ProtocolException("invalid_receipt", why)
        if (receipt.length > MAX_RECEIPT) bad("The receipt is too large")
        val parts = SdJwtDisclosures.parse(receipt)
        if (parts.keyBinding != null) bad("The receipt carries a key binding")
        val jws = Jws.parse(parts.issuerJwt)
        if (jws.typ != "dc+sd-jwt" || jws.alg != "ES256") bad("Not an SD-JWT VC")
        val chain = session.chain
        if (chain != null) {
            val leaf = jws.x5c?.certificates?.firstOrNull() ?: bad("The receipt has no certificate")
            if (!leaf.encoded.toByteArray().contentEquals(chain.first().encoded.toByteArray())) bad("The receipt is not signed by the requester")
            jws.verify(VerificationKey.fromCertificate(chain.first()))
        } else {
            val did = session.did ?: bad("The request names no DID")
            val kid = jws.kid ?: bad("The receipt names no key")
            if (kid.substringBefore('#') != did) bad("The receipt is not signed by the requester")
            jws.verify(didResolver.resolveKey(did, kid).key)
        }
        val payload = SdJwtDisclosures.resolve(jws.payload, parts.disclosures)
        if (payload.str("vct") != VCT_PROOF) bad("Not a web proof")
        if (chain == null && payload.str("iss") != session.did) bad("The issuer is not the requester")
        val cnf = ((payload["cnf"] as? JsonObject)?.get("jwk") as? JsonObject) ?: bad("No holder key")
        if (jwkThumbprint(cnf) != jwkThumbprint(holderJwk)) bad("The receipt is bound to another key")
        val source = payload["source"] as? JsonObject ?: bad("No source")
        if (!source.str("host").equals(outcome.profile.host, ignoreCase = true) || source.str("profile") != outcome.profile.id) bad("The receipt names another page")
        if ((payload["session"] as? JsonObject)?.str("nonce") != session.request.nonce) bad("The receipt is for another request")
        if (payload.str("method") != method(session.request.mode)) bad("The receipt names another method")
        val expected = claims(outcome).associate { it.name to it.value }
        val stated = expected.keys.associateWith { payload.str(it) }
        if (stated != expected) bad("The receipt states other values than the proof")
        if (parts.disclosures.size != expected.size) bad("The receipt discloses other claims")
        return payload
    }

    /** The public members of an EC JWK, so a private member can never reach a credential. */
    fun publicJwk(jwk: JsonObject): JsonObject {
        if (jwk.str("kty") != "EC" || jwk.str("crv") != "P-256" || jwk.str("x") == null || jwk.str("y") == null) {
            throw ProtocolException("invalid_request", "The holder key must be a P-256 JWK")
        }
        return buildJsonObject { listOf("kty", "crv", "x", "y").forEach { put(it, jwk.str(it)) } }
    }

    /** The holder JWK a receipt request carries, or null when the bytes are not one. */
    fun bindingJwk(binding: ByteArray): JsonObject? = runCatching {
        publicJwk(diw.wallet.core.util.DiwJson.parseToJsonElement(binding.decodeToString()) as JsonObject)
    }.getOrNull()

    /** The resolved claims of a stored credential: its disclosures applied to the payload. */
    fun read(compact: String): JsonObject {
        val parts = SdJwtDisclosures.parse(compact)
        return SdJwtDisclosures.resolve(Jws.parse(parts.issuerJwt).payload, parts.disclosures)
    }

    /** Whether [vct] is one of the two web credentials. */
    fun isWeb(vct: String?): Boolean = vct == VCT_PROOF || vct == VCT_RECORD

    /**
     * The verifier's receipts for one session: a web-proof of a check that passed, signed by [key] (the key that
     * signed the request, under [iss] or with [chain]); none for a failed check.
     */
    fun receipts(request: ZkTlsSessionRequest, profile: ZkTlsProfile, iss: String, key: AsymmetricKey, chain: List<X509Cert>? = null) =
        ZkTlsReceipts { seen, holderJwk ->
            val outcome = ZkTlsCheck.check(request, profile, seen)
            if (!outcome.passed) null
            else issue(VCT_PROOF, iss, key, holderJwk, source(profile, seen.time, seen.certChainDer, null), method(request.mode), claims(outcome), chain, request)
        }

    /** Claim names a page field cannot take, since the credential's own members use them. */
    private val RESERVED = setOf("iss", "sub", "iat", "nbf", "exp", "jti", "vct", "cnf", "status", "source", "method", "session", "device", "_sd", "_sd_alg")
}

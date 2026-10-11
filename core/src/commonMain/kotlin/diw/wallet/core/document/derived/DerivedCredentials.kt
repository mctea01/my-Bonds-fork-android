package diw.wallet.core.document.derived

import diw.wallet.core.did.DidKeys
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.TimestampInfo
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.util.Jcs
import diw.wallet.core.w3c.SdJwtDisclosures
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/** The file a derived credential stands for; only its fingerprint, type and size are always visible. */
data class DerivedDocument(val sha256Hex: String, val mediaType: String, val size: Long)

/** One selectively disclosable claim; values are text so that the vc+moica form can carry them too. */
data class DerivedClaim(val name: String, val value: String)

/**
 * A credential the wallet derives from a stored document: an IETF SD-JWT VC issued by the wallet's own document
 * issuer DID (did:key) and bound by cnf to a credential key, so it is presented like any SD-JWT VC; and, when the
 * holder signs it with the citizen digital certificate card, the same claims as a Bonds vc+moica card.
 *
 * Both forms share one set of disclosures (same salts), so the citizen card signature over the vc+moica payload
 * also commits to the SD-JWT VC claims; the SD-JWT VC carries that signature as evidence. The evidence array
 * records what the wallet checked: the document signatures (as the wallet's statement), an RFC 3161 time stamp over
 * the document hash (verifiable by anyone) and the citizen certificate signature (verifiable by anyone).
 */
object DerivedCredentials {
    const val VCT = "urn:diw-wallet:vct:document-derived:1"
    const val TYPE = "DocumentDerivedCredential"

    const val EVIDENCE_SIGNATURE = "DocumentSignatureCheck"
    const val EVIDENCE_TIMESTAMP = "DocumentTimeStamp"
    const val EVIDENCE_CITIZEN = "CitizenCertificateSignature"

    /** Claim names the wallet suggests; the holder chooses which to include. */
    const val CLAIM_NAME = "name"
    const val CLAIM_TITLE = "documentTitle"
    const val CLAIM_FILE_NAME = "fileName"
    const val CLAIM_SIGNER = "documentSigner"
    const val CLAIM_SIGNED_AT = "documentSignedAt"
    const val CLAIM_SOURCE = "documentSource"

    /** Readable labels for the claim names above. */
    val claimLabels = mapOf(
        CLAIM_NAME to "持有人姓名",
        CLAIM_TITLE to "文件標題",
        CLAIM_FILE_NAME to "檔名",
        CLAIM_SIGNER to "文件簽署者",
        CLAIM_SIGNED_AT to "文件簽署時間",
        CLAIM_SOURCE to "文件來源",
    )

    /** Claims the wallet can fill from a stored file and its report. */
    fun suggestedClaims(report: DocumentReport, fileName: String?, source: String?): List<DerivedClaim> = buildList {
        report.title?.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(CLAIM_TITLE, it.trim())) }
        fileName?.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(CLAIM_FILE_NAME, it)) }
        val sig = mainSignature(report)
        (sig?.signer?.commonName ?: sig?.signerName)?.let { add(DerivedClaim(CLAIM_SIGNER, it)) }
        val time = sig?.timestamp?.takeIf { it.trusted }?.time ?: sig?.claimedTime
        time?.let { add(DerivedClaim(CLAIM_SIGNED_AT, Instant.fromEpochSeconds(it).toString())) }
        source?.takeIf { it.isNotBlank() }?.let { add(DerivedClaim(CLAIM_SOURCE, it)) }
    }

    /** The signature that speaks for the document: the first valid one, else the first. */
    fun mainSignature(report: DocumentReport): SignatureInfo? =
        report.signatures.firstOrNull { it.verdict == DocumentVerdict.VALID } ?: report.signatures.firstOrNull()

    /** Encoded disclosures with fresh 128 bit salts, in the order given. Names must be unique. */
    fun disclosures(claims: List<DerivedClaim>): List<String> {
        require(claims.map { it.name }.toSet().size == claims.size) { "Duplicate claim names" }
        return claims.map { c ->
            val array = JsonArray(listOf(JsonPrimitive(PlatformCrypto.randomBytes(16).toBase64Url()), JsonPrimitive(c.name), JsonPrimitive(c.value)))
            array.toString().encodeToByteArray().toBase64Url()
        }
    }

    /** What the wallet found about the document's signatures, as a statement of the issuing wallet. */
    fun signatureEvidence(report: DocumentReport): JsonObject = buildJsonObject {
        put("type", EVIDENCE_SIGNATURE)
        put("verdict", report.verdict.name)
        put("checkedAt", Instant.fromEpochSeconds(report.checkedAt).toString())
        putJsonArray("signatures") {
            report.signatures.forEach { s ->
                add(buildJsonObject {
                    put("format", s.format.name)
                    put("verdict", s.verdict.name)
                    s.trust?.let { put("trustTier", it.tier); put("official", it.official); it.environment?.let { e -> put("environment", e) } }
                    s.timestamp?.takeIf { it.trusted }?.let { put("timeStamped", Instant.fromEpochSeconds(it.time).toString()) }
                })
            }
        }
    }

    /** An RFC 3161 token whose message imprint is SHA-256 of the document. */
    fun timestampEvidence(token: ByteArray, info: TimestampInfo): JsonObject = buildJsonObject {
        put("type", EVIDENCE_TIMESTAMP)
        put("time", Instant.fromEpochSeconds(info.time).toString())
        info.tsa?.let { put("tsa", it) }
        put("token", token.toBase64())
    }

    private fun documentObject(document: DerivedDocument) = buildJsonObject {
        put("mediaType", document.mediaType)
        put("sha256", document.sha256Hex.lowercase())
        put("size", document.size)
    }

    private fun sdDigests(disclosures: List<String>): List<String> = disclosures.map { SdJwtDisclosures.digest(it) }.sorted()

    /**
     * The W3C credential of the vc+moica form: issued by and about [holderDid] (the Bonds self-issued holder), with
     * the document, evidence and the digests of [disclosures].
     */
    fun moicaPayload(
        holderDid: String,
        document: DerivedDocument,
        evidence: List<JsonObject>,
        disclosures: List<String>,
        now: Instant = Clock.System.now(),
        validUntil: Instant? = null,
    ): JsonObject = buildJsonObject {
        putJsonArray("@context") { add(JsonPrimitive(BondsOfflinePresentation.CREDENTIALS_V2)) }
        putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")); add(JsonPrimitive(TYPE)) }
        put("issuer", holderDid)
        put("validFrom", Instant.fromEpochSeconds(now.epochSeconds).toString())
        validUntil?.let { put("validUntil", Instant.fromEpochSeconds(it.epochSeconds).toString()) }
        putJsonObject("credentialSubject") { put("id", holderDid) }
        put("document", documentObject(document))
        if (evidence.isNotEmpty()) put("evidence", JsonArray(evidence))
        putJsonArray("_sd") { sdDigests(disclosures).forEach { add(JsonPrimitive(it)) } }
        put("_sd_alg", "sha-256")
    }

    /**
     * Signs [payload] with the citizen certificate [card] (RSASSA-PKCS1-v1_5 SHA-256 over the Bonds TBS string) and
     * with the holder key (issuerJWS), and returns the vc+moica card with all [disclosures].
     */
    suspend fun signMoica(payload: JsonObject, disclosures: List<String>, holder: HolderKey, card: DocumentSigner): MoicaSignedCredential {
        if (card.keyType != SignerKeyType.RSA) throw SigningException("vc+moica 需要以自然人憑證（RSA 2048）簽署")
        val holderDid = holder.did ?: throw SigningException("持有者金鑰沒有 DID")
        val bytes = Jcs.canonicalize(payload).encodeToByteArray()
        val tbs = MoicaSignedCredential.TBS_PREFIX + hex(PlatformCrypto.sha256(bytes))
        val signature = card.sign(tbs.encodeToByteArray())
        if (signature.size != MoicaSignedCredential.SIGNATURE_BYTES) throw SigningException("自然人憑證簽章長度不是 2048 位元")
        val header = buildJsonObject {
            put("alg", "ES256")
            put("cty", "vc")
            put("kid", DidKeys.verificationMethod(holderDid))
            put("typ", "vc+jwt")
        }
        val issuerJws = compactJws(header, bytes, holder.signingKey("ES256"))
        val serialized = Jcs.canonicalize(buildJsonObject {
            putJsonArray("disclosures") { disclosures.forEach { add(JsonPrimitive(it)) } }
            put("issuerJWS", issuerJws)
            put("payload", bytes.toBase64Url())
            putJsonObject("proof") {
                put("certificate", card.certificateChain.first().toBase64())
                put("signature", signature.toBase64())
                put("tbsConstruction", MoicaSignedCredential.TBS_CONSTRUCTION)
            }
        })
        return MoicaSignedCredential.parse(serialized)
    }

    /** The citizen certificate signature of a vc+moica card, as evidence inside the SD-JWT VC. */
    fun citizenEvidence(card: MoicaSignedCredential): JsonObject = buildJsonObject {
        put("type", EVIDENCE_CITIZEN)
        put("payload", card.payload)
        put("certificate", card.certificate)
        put("signature", card.signature)
        put("tbsConstruction", card.tbsConstruction)
    }

    /**
     * The IETF SD-JWT VC (compact, ending in '~'), signed by [issuer] (its DID must be set) and bound to
     * [holderKey]. [citizen] adds the vc+moica signature made over the same disclosures.
     */
    suspend fun sdJwtVc(
        issuer: HolderKey,
        holderKey: EcPublicKey,
        document: DerivedDocument,
        evidence: List<JsonObject>,
        disclosures: List<String>,
        citizen: MoicaSignedCredential? = null,
        now: Instant = Clock.System.now(),
        validUntil: Instant? = null,
    ): String {
        val iss = issuer.did ?: throw SigningException("文件發行金鑰沒有 DID")
        val allEvidence = evidence + listOfNotNull(citizen?.let { citizenEvidence(it) })
        val jwk = holderKey.toJwk()
        val payload = buildJsonObject {
            put("iss", iss)
            put("iat", now.epochSeconds)
            put("nbf", now.epochSeconds)
            validUntil?.let { put("exp", it.epochSeconds) }
            put("vct", VCT)
            putJsonObject("cnf") { put("jwk", jwk) }
            put("document", documentObject(document))
            if (allEvidence.isNotEmpty()) put("evidence", JsonArray(allEvidence))
            putJsonArray("_sd") { sdDigests(disclosures).forEach { add(JsonPrimitive(it)) } }
            put("_sd_alg", "sha-256")
        }
        val header = buildJsonObject {
            put("alg", "ES256")
            put("kid", DidKeys.verificationMethod(iss))
            put("typ", "dc+sd-jwt")
        }
        val jwt = compactJws(header, payload.toString().encodeToByteArray(), issuer.signingKey("ES256"))
        return (listOf(jwt) + disclosures).joinToString("~") + "~"
    }

    private suspend fun compactJws(header: JsonObject, payload: ByteArray, key: AsymmetricKey): String {
        val input = header.toString().encodeToByteArray().toBase64Url() + "." + payload.toBase64Url()
        val sig = key.sign(input.encodeToByteArray())
        return input + "." + sig.toCoseEncoded().toBase64Url()
    }

    internal fun hex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
}

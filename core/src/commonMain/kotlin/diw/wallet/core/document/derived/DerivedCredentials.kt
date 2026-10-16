package diw.wallet.core.document.derived

import diw.wallet.core.did.DidKeys
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.TimestampInfo
import diw.wallet.core.document.official.OfficialDocuments
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.HolderHint
import diw.wallet.core.jose.PlatformCrypto
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

/**
 * One selectively disclosable claim, as text. [label] is the readable name of a claim read from the document's
 * content (the wallet's own claims are named in claimLabels).
 */
data class DerivedClaim(val name: String, val value: String, val label: String? = null)

/**
 * A credential the wallet derives from a stored document: an IETF SD-JWT VC issued by the wallet's own document
 * issuer DID (did:key) and bound by cnf to a credential key, so it is presented like any SD-JWT VC. It is a
 * credential structure only: signing the document itself (PAdES, CAdES, XAdES with the citizen certificate card or
 * another key) is a separate step whose result the evidence then reports. The Bonds vc+moica structure is kept for
 * the national ID card alone.
 *
 * The evidence array records what the wallet checked: the document signatures (as the wallet's statement) and an
 * RFC 3161 time stamp over the document hash (verifiable by anyone).
 */
object DerivedCredentials {
    const val VCT = "urn:diw-wallet:vct:document-derived:1"
    const val TYPE = "DocumentDerivedCredential"

    const val EVIDENCE_SIGNATURE = "DocumentSignatureCheck"
    const val EVIDENCE_TIMESTAMP = "DocumentTimeStamp"

    /** Claim names the wallet suggests; the holder chooses which to include. */
    const val CLAIM_TITLE = "documentTitle"
    const val CLAIM_FILE_NAME = "fileName"
    const val CLAIM_SIGNER = "documentSigner"
    const val CLAIM_SIGNED_AT = "documentSignedAt"
    const val CLAIM_SOURCE = "documentSource"
    /** Claims the holder typed rather than the wallet read from the document carry this prefix. */
    const val SELF_ASSERTED_PREFIX = "holderStated:"

    /** Readable labels for the claim names above. */
    val claimLabels = mapOf(
        CLAIM_TITLE to "文件標題",
        CLAIM_FILE_NAME to "檔名",
        CLAIM_SIGNER to "文件簽署者",
        CLAIM_SIGNED_AT to "文件簽署時間",
        CLAIM_SOURCE to "文件來源",
    )

    /**
     * Claims the wallet fills from a stored file: its report (title, signer, signing time), where it came from, and
     * what its content says ([text], the text layer of a PDF; [xml], an official document; OpenCerts data in the
     * report). Nothing here is typed by the holder.
     */
    fun suggestedClaims(report: DocumentReport, fileName: String?, source: String?, text: String? = null, xml: String? = null): List<DerivedClaim> =
        suggested(report, fileName, source, text, xml).claims

    /**
     * [suggestedClaims] with a note for the holder. A household record is read per person and only the holder's
     * own block (picked by [holders]) gives personal claims.
     */
    fun suggested(
        report: DocumentReport,
        fileName: String?,
        source: String?,
        text: String? = null,
        xml: String? = null,
        holders: List<HolderHint> = emptyList(),
    ): DocumentFields.ContentFields {
        val base = baseClaims(report, fileName, source, text)
        var notice: String? = null
        val parsed = buildList {
            report.openCert?.let { addAll(DocumentFields.fromOpenCert(it)) }
            xml?.let {
                addAll(DocumentFields.fromOfficialLetter(it))
                OfficialDocuments.parse(it.encodeToByteArray())?.let { doc -> addAll(DocumentFields.fromOfficial(doc)) }
            }
            text?.let { t ->
                val household = DocumentFields.fromHousehold(t, holders)
                if (household != null) {
                    notice = household.notice
                    addAll(household.claims)
                } else {
                    // Entry and exit records and the certificates read as a structure; their bilingual labels would repeat as pairs.
                    val entryExit = DocumentFields.fromEntryExit(t).ifEmpty { DocumentFields.fromMainlandEntryExit(t) }
                    addAll(entryExit.ifEmpty { ParsedCertificate.parse(t)?.claims() ?: DocumentFields.fromText(t) })
                }
            }
        }
        val names = base.map { it.name }.toMutableSet()
        return DocumentFields.ContentFields(base + parsed.filter { names.add(it.name) }.take(DocumentFields.MAX_FIELDS), notice)
    }

    /** Readable name of [claim]. */
    fun labelOf(claim: DerivedClaim): String = claim.label ?: claimLabels[claim.name] ?: claim.name

    private fun baseClaims(report: DocumentReport, fileName: String?, source: String?, text: String?): List<DerivedClaim> = buildList {
        (report.title?.takeIf { it.isNotBlank() } ?: report.openCert?.name?.takeIf { it.isNotBlank() } ?: text?.let { DocumentFields.titleFromText(it) })
            ?.let { add(DerivedClaim(CLAIM_TITLE, it.trim())) }
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

    /** The IETF SD-JWT VC (compact, ending in '~'), signed by [issuer] (its DID must be set) and bound to [holderKey]. */
    suspend fun sdJwtVc(
        issuer: HolderKey,
        holderKey: EcPublicKey,
        document: DerivedDocument,
        evidence: List<JsonObject>,
        disclosures: List<String>,
        now: Instant = Clock.System.now(),
        validUntil: Instant? = null,
    ): String {
        val iss = issuer.did ?: throw SigningException("文件發行金鑰沒有 DID")
        val jwk = holderKey.toJwk()
        val payload = buildJsonObject {
            put("iss", iss)
            put("iat", now.epochSeconds)
            put("nbf", now.epochSeconds)
            validUntil?.let { put("exp", it.epochSeconds) }
            put("vct", VCT)
            putJsonObject("cnf") { put("jwk", jwk) }
            put("document", documentObject(document))
            if (evidence.isNotEmpty()) put("evidence", JsonArray(evidence))
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

package diw.wallet.core.document

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import kotlinx.serialization.Serializable

/** What a stored file is, as recognised from its bytes (the name only breaks ties). */
@Serializable
enum class DocumentFormat(val mediaType: String) {
    PDF("application/pdf"),
    /** CMS SignedData (.p7s detached, .p7m enveloping, .p7b certificates). */
    CMS_SIGNED("application/pkcs7-signature"),
    /** CMS EnvelopedData, such as the household registration transcript token (.asdt). */
    CMS_ENVELOPED("application/pkcs7-mime"),
    /** RFC 3161 time-stamp token or response (.tsr, .tst). */
    TIMESTAMP("application/timestamp-reply"),
    XML("application/xml"),
    /** OFD (GB/T 33190) container. */
    OFD("application/ofd"),
    /** ASiC-E container (ETSI EN 319 162). */
    ASIC_E("application/vnd.etsi.asic-e+zip"),
    ZIP("application/zip"),
    /** OpenAttestation (OpenCerts) document. */
    OPENCERTS("application/vnd.opencerts+json"),
    JSON("application/json"),
    /** Office document: OOXML or ODF (a ZIP package) or the older OLE compound file (.doc, .xls, .ppt). */
    OFFICE("application/octet-stream"),
    IMAGE("image/*"),
    TEXT("text/plain"),
    OTHER("application/octet-stream"),
}

/** The signature technologies the inspector recognises. */
@Serializable
enum class SignatureFormat(val title: String) {
    PADES("PAdES（ETSI.CAdES.detached）"),
    PDF_PKCS7("PDF PKCS#7（adbe.pkcs7.detached）"),
    PDF_PKCS7_SHA1("PDF PKCS#7（adbe.pkcs7.sha1）"),
    PDF_DOC_TIMESTAMP("PDF 文件時戳（ETSI.RFC3161）"),
    PDF_X509("PDF X.509（adbe.x509.rsa_sha1）"),
    CADES("CAdES / PKCS#7"),
    XADES("XAdES"),
    XMLDSIG("XML 數位簽章（XMLDSig）"),
    OFFICIAL_APPROVAL("電子公文線上簽核（簽核點）"),
    OFD_SEAL("OFD 電子印章（GB/T 38540）"),
    OFD_SIGN("OFD 數位簽章（GB/T 35275）"),
    ASIC_CADES("ASiC-E（CAdES）"),
    RFC3161("RFC 3161 時戳"),
    OPENCERTS("OpenAttestation（Merkle 證明）"),
}

/** One check: passed, passed with a caveat, failed, or not possible here. */
@Serializable
enum class Check { PASS, WARN, FAIL, NOT_CHECKED }

/** Overall verdict of a signature or a document, shown with the shared verdict card. */
@Serializable
enum class DocumentVerdict { VALID, PARTIAL, INVALID, UNSIGNED }

/** A certificate as shown in the chain; [der] is the base64 DER for the certificate screen. */
@Serializable
data class CertInfo(
    val subject: String,
    val issuer: String,
    val commonName: String?,
    val serialHex: String,
    val notBefore: Long,
    val notAfter: Long,
    val der: String,
    val publicKey: String,
)

/** Serializable form of a [TrustDecision]. */
@Serializable
data class TrustSummary(
    val tier: String,
    val environment: String?,
    val official: Boolean,
    val anchorName: String?,
    val labels: List<String>,
) {
    fun decision(): TrustDecision = TrustDecision(
        tier = runCatching { TrustTier.valueOf(tier) }.getOrDefault(TrustTier.T4),
        environment = TrustEnvironment.fromId(environment),
        official = official,
        anchorName = anchorName,
        labels = labels.mapNotNull { runCatching { TrustLabel.valueOf(it) }.getOrNull() }.toSet(),
    )

    companion object {
        fun of(d: TrustDecision) = TrustSummary(d.tier.name, d.environment?.id, d.official, d.anchorName, d.labels.map { it.name })
    }
}

/** A verified (or not) RFC 3161 time-stamp token. */
@Serializable
data class TimestampInfo(
    /** genTime in epoch seconds. */
    val time: Long,
    val tsa: String?,
    /** The token's message imprint matches the data it is supposed to cover. */
    val imprint: Check,
    /** The token's own signature. */
    val signature: Check,
    val trust: TrustSummary?,
    val chain: List<CertInfo> = emptyList(),
    val hashAlgorithm: String? = null,
    val problems: List<String> = emptyList(),
) {
    /** A time the wallet can rely on: intact, signed and chained to an enabled TSA anchor. */
    val trusted: Boolean get() = imprint == Check.PASS && signature == Check.PASS && trust != null && "UNKNOWN_ANCHOR" !in trust.labels
}

/** How a PDF changed after a signature (ISO 32000-1 12.8.2.2, incremental updates). */
@Serializable
enum class LaterChanges { NONE, SIGNATURES_ONLY, OTHER }

/** The verification of one signature. */
@Serializable
data class SignatureInfo(
    val format: SignatureFormat,
    /** Field name, signature file or element that holds it. */
    val label: String,
    val algorithm: String?,
    val signer: CertInfo?,
    /** Signer first, as built from the signature, the document and the AIA links. */
    val chain: List<CertInfo>,
    /** The signed bytes hash to the signed digest and the signature verifies with the signer key. */
    val integrity: Check,
    /** The signature covers the whole file (PDF: up to its end; detached: the content given). */
    val coversWholeDocument: Boolean?,
    val laterChanges: LaterChanges? = null,
    /** Signing time the signer wrote (PDF /M or the signingTime attribute): a claim, not a proof. */
    val claimedTime: Long? = null,
    val timestamp: TimestampInfo? = null,
    val trust: TrustSummary?,
    /** The signer certificate was valid when signed: at the trusted time stamp, else now. */
    val certificateValidity: Check,
    /** Revocation data (OCSP or CRL) was found in the signature or the document. */
    val revocationData: Boolean = false,
    val reason: String? = null,
    val location: String? = null,
    val signerName: String? = null,
    /** DocMDP permission of a PDF certification signature (1: no changes, 2: form filling and signing, 3: annotations too). */
    val docMdp: Int? = null,
    val problems: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
) {
    val verdict: DocumentVerdict
        get() = when {
            integrity == Check.FAIL || certificateValidity == Check.FAIL || laterChanges == LaterChanges.OTHER -> DocumentVerdict.INVALID
            integrity != Check.PASS -> DocumentVerdict.PARTIAL
            trust == null || "UNKNOWN_ANCHOR" in trust.labels || trust.tier == "T4" -> DocumentVerdict.PARTIAL
            certificateValidity != Check.PASS -> DocumentVerdict.PARTIAL
            coversWholeDocument == false && laterChanges != LaterChanges.SIGNATURES_ONLY -> DocumentVerdict.PARTIAL
            else -> DocumentVerdict.VALID
        }
}

/** The encrypted envelope of a CMS EnvelopedData file: who can open it. */
@Serializable
data class EnvelopeInfo(
    val recipients: List<String>,
    val contentEncryption: String?,
    val keyEncryption: List<String>,
    val encryptedBytes: Int,
)

/** An OpenAttestation document: its fields, issuers and the result of the integrity check. */
@Serializable
data class OpenCertInfo(
    val version: String,
    val name: String?,
    val issuers: List<String>,
    val identityProofs: List<String>,
    val fields: Map<String, String>,
    val integrity: Check,
    val issuerVerified: Check,
    /** The last online check of issuance and issuer identity, kept with the file. */
    val online: OpenCertOnline? = null,
)

/**
 * The online check of an OpenAttestation document: whether the issuer published it (document store, token registry
 * or DID signature) and has not revoked it, and whether the issuer's identity (DNS record or OpenCerts registry)
 * holds. [checkedAt] is in epoch seconds.
 */
@Serializable
data class OpenCertOnline(
    val checkedAt: Long,
    val issuance: Check,
    val issuanceDetail: List<String>,
    val identity: Check,
    val identityDetail: List<String>,
    val registryName: String? = null,
)

/** Everything the inspector found in a file. */
@Serializable
data class DocumentReport(
    val format: DocumentFormat,
    val sha256: String,
    val size: Long,
    val title: String? = null,
    val pages: Int? = null,
    val encrypted: Boolean = false,
    val signatures: List<SignatureInfo> = emptyList(),
    val envelope: EnvelopeInfo? = null,
    val openCert: OpenCertInfo? = null,
    /** Files inside a container (ZIP, OFD, ASiC). */
    val entries: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
    val problems: List<String> = emptyList(),
    val checkedAt: Long,
) {
    val verdict: DocumentVerdict
        get() = when {
            signatures.isEmpty() && openCert == null -> DocumentVerdict.UNSIGNED
            signatures.any { it.verdict == DocumentVerdict.INVALID } -> DocumentVerdict.INVALID
            openCert?.integrity == Check.FAIL || openCert?.online?.issuance == Check.FAIL -> DocumentVerdict.INVALID
            openCert != null && signatures.isEmpty() && openCert.integrity == Check.PASS &&
                openCert.online?.issuance == Check.PASS && openCert.online.identity == Check.PASS -> DocumentVerdict.VALID
            signatures.isNotEmpty() && signatures.all { it.verdict == DocumentVerdict.VALID } && openCert == null -> DocumentVerdict.VALID
            else -> DocumentVerdict.PARTIAL
        }

    /** The best trust tier among the valid signatures. */
    val bestTier: TrustTier?
        get() = signatures.filter { it.verdict == DocumentVerdict.VALID }.mapNotNull { s -> s.trust?.let { runCatching { TrustTier.valueOf(it.tier) }.getOrNull() } }.minOrNull()
}

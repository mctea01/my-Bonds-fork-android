package diw.wallet.core.document

import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import org.multipaz.crypto.X509Cert
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * What the document inspector needs from the wallet: trust decisions for signer and time-stamp chains, and (when
 * the wallet is online and allows it) the issuer certificates that a certificate's AIA extension points to.
 */
interface DocumentTrustSource {
    /** Trust of [chain] (leaf first) in [role] at [at]: [TrustRole.DOCUMENT] for signers, [TrustRole.TSA] for time stamps. */
    suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision

    /** Certificates published at an AIA caIssuers URL (DER or PKCS#7 certs-only); empty when offline or not allowed. */
    suspend fun fetchIssuerCertificates(url: String): List<ByteArray>
}

/**
 * Verifies the signatures of a stored file: PDF (PAdES, PKCS#7, document time stamps), CMS (.p7s with its
 * content, .p7m), XML signatures (XMLDSig, XAdES, including official documents), OFD seals and signatures
 * (GB/T 38540, GB/T 35275), ASiC-E containers and RFC 3161 tokens; and describes what it cannot verify (CMS
 * envelopes such as .asdt, OpenAttestation documents are checked by [diw.wallet.core.document.opencerts]).
 * Revocation is checked with the OCSP responses and CRLs embedded in the signature or the document only.
 */
expect object DocumentInspector {
    suspend fun inspect(
        bytes: ByteArray,
        fileName: String?,
        trust: DocumentTrustSource,
        /** Content of a detached signature (.p7s) when the user picked it. */
        detachedContent: ByteArray? = null,
        now: Instant = Clock.System.now(),
    ): DocumentReport

    /** Verifies an RFC 3161 token (or a response holding one) over [data] (the stored file). */
    suspend fun verifyTimestamp(token: ByteArray, data: ByteArray, trust: DocumentTrustSource): TimestampInfo

    /** Verifies an RFC 3161 token over data known only by its SHA-256 [sha256] (a derived credential's document). */
    suspend fun verifyTimestampDigest(token: ByteArray, sha256: ByteArray, trust: DocumentTrustSource): TimestampInfo

    /** DER of an RFC 3161 TimeStampReq for SHA-256 of [data], with a random nonce and certReq true. */
    fun timestampRequest(data: ByteArray): ByteArray

    /** The token of a TimeStampResp; throws with the TSA's status text when it was not granted. */
    fun timestampToken(response: ByteArray): ByteArray

    /** Content of an enveloping CMS signature (.p7m), or null when the signature is detached. */
    fun encapsulatedContent(cms: ByteArray): ByteArray?
}

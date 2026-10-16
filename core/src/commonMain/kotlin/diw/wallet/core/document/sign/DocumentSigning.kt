package diw.wallet.core.document.sign

import diw.wallet.core.document.official.ApprovalPoint
import diw.wallet.core.document.pdf.PdfSignOptions

/**
 * Making signed documents with any [DocumentSigner]: PAdES (an incremental update keeps earlier signatures valid),
 * CAdES (.p7s detached or .p7m enveloping), ASiC-E containers for several files, and XAdES enveloped signatures
 * for XML such as official documents. With a [Timestamper] the signatures get a signature time stamp (-T level).
 * Every signature is verified with the signer certificate before it is returned.
 */
expect object DocumentSigning {
    suspend fun signPdf(pdf: ByteArray, signer: DocumentSigner, options: PdfSignOptions, timestamper: Timestamper?): ByteArray

    /** With [validation], the chains and revocation data (OCSP first) go into the signature (baseline LT). */
    suspend fun signCades(content: ByteArray, signer: DocumentSigner, detached: Boolean, timestamper: Timestamper?, validation: HttpFetch? = null): ByteArray

    suspend fun buildAsic(files: List<Pair<String, ByteArray>>, signer: DocumentSigner, timestamper: Timestamper?, validation: HttpFetch? = null): ByteArray

    /** With [validation], XAdES CertificateValues and RevocationValues are added (baseline LT). */
    suspend fun signXml(xml: ByteArray, signer: DocumentSigner, timestamper: Timestamper?, validation: HttpFetch? = null): ByteArray

    /** Chain (completed through AIA) and revocation data, OCSP first, of a certificate chain (signer first). */
    suspend fun collectValidation(chain: List<ByteArray>, fetch: HttpFetch, known: List<ByteArray> = emptyList()): ValidationData

    /** The same for the time-stamp authority of an RFC 3161 token, kept with the time stamp. */
    suspend fun timestampValidation(token: ByteArray, fetch: HttpFetch, known: List<ByteArray> = emptyList()): ValidationData

    /**
     * Signs the files of an official document case the way the official document handbook does (線上簽核, .si): a new
     * signing point in [approval], or in a new approval file when it is null, covering [files] (name and bytes, the
     * document first). The files themselves are not changed. Returns the approval file.
     */
    suspend fun signApproval(approval: ByteArray?, files: List<Pair<String, ByteArray>>, signer: DocumentSigner, point: ApprovalPoint): ByteArray

    /** Files of a ZIP archive (such as a MyData download), directories omitted. */
    fun unzip(bytes: ByteArray): Map<String, ByteArray>

    /** A ZIP archive of [files] in order, names written as UTF-8 (for exports). */
    fun zip(files: List<Pair<String, ByteArray>>): ByteArray

    /** A PKCS#12 (.p12, .pfx) key and certificate opened with [password], as a signer. */
    fun pkcs12Signer(p12: ByteArray, password: String): DocumentSigner

    /** DER of a self-issued certificate for a wallet key ([publicKeyDer] SubjectPublicKeyInfo) signed by that key. */
    suspend fun selfIssuedCertificate(publicKeyDer: ByteArray, subjectName: String, sign: suspend (ByteArray) -> ByteArray, keyType: SignerKeyType, validDays: Int): ByteArray

    /** Subject common name and serial number (hex) of a certificate, for display. */
    fun certificateSummary(der: ByteArray): Pair<String, String>?
}

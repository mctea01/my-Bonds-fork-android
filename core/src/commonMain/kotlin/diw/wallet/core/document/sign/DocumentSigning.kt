package diw.wallet.core.document.sign

import diw.wallet.core.document.pdf.PdfSignOptions

/**
 * Making signed documents with any [DocumentSigner]: PAdES (an incremental update keeps earlier signatures valid),
 * CAdES (.p7s detached or .p7m enveloping), ASiC-E containers for several files, and XAdES enveloped signatures
 * for XML such as official documents. With a [Timestamper] the signatures get a signature time stamp (-T level).
 * Every signature is verified with the signer certificate before it is returned.
 */
expect object DocumentSigning {
    suspend fun signPdf(pdf: ByteArray, signer: DocumentSigner, options: PdfSignOptions, timestamper: Timestamper?): ByteArray

    suspend fun signCades(content: ByteArray, signer: DocumentSigner, detached: Boolean, timestamper: Timestamper?): ByteArray

    suspend fun buildAsic(files: List<Pair<String, ByteArray>>, signer: DocumentSigner, timestamper: Timestamper?): ByteArray

    suspend fun signXml(xml: ByteArray, signer: DocumentSigner, timestamper: Timestamper?): ByteArray

    /** Files of a ZIP archive (such as a MyData download), directories omitted. */
    fun unzip(bytes: ByteArray): Map<String, ByteArray>

    /** A PKCS#12 (.p12, .pfx) key and certificate opened with [password], as a signer. */
    fun pkcs12Signer(p12: ByteArray, password: String): DocumentSigner

    /** DER of a self-issued certificate for a wallet key ([publicKeyDer] SubjectPublicKeyInfo) signed by that key. */
    suspend fun selfIssuedCertificate(publicKeyDer: ByteArray, subjectName: String, sign: suspend (ByteArray) -> ByteArray, keyType: SignerKeyType, validDays: Int): ByteArray

    /** Subject common name and serial number (hex) of a certificate, for display. */
    fun certificateSummary(der: ByteArray): Pair<String, String>?
}

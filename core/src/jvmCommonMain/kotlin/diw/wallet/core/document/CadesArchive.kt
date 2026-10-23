package diw.wallet.core.document

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERSet
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.AttributeTable
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.cms.SignerInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.SignerInformationStore
import java.io.ByteArrayOutputStream

/**
 * CAdES archive-time-stamp-v3 (ETSI EN 319 122-1 5.5.2 and 5.5.3), the time stamp of baseline B-LTA. The time stamp
 * covers the content, the signature and an ats-hash-index-v3 listing the hash of every certificate, revocation value
 * and unsigned attribute value present when it was made; the index rides in the time-stamp token's own unsigned
 * attributes, so validation data added later does not break it.
 */
internal object CadesArchive {
    val ATS_V3 = ASN1ObjectIdentifier("0.4.0.1733.2.4")
    val HASH_INDEX_V3 = ASN1ObjectIdentifier("0.4.0.19122.1.5")
    private const val SHA256_OID = "2.16.840.1.101.3.4.2.1"

    private fun der(e: ASN1Encodable): ByteArray = e.toASN1Primitive().getEncoded(ASN1Encoding.DER)

    private fun hashes(items: Iterable<ByteArray>, alg: String): List<ByteArray> = items.map { DocCrypto.digest(alg, it) }

    private fun certificateItems(sd: SignedData): List<ByteArray> = sd.certificates?.map { der(it) }.orEmpty()

    private fun revocationItems(sd: SignedData): List<ByteArray> = sd.crLs?.map { der(it) }.orEmpty()

    /** For each value of each unsigned attribute: attrType DER followed by the value's DER. */
    private fun attributeItems(si: SignerInfo): List<ByteArray> = si.unauthenticatedAttributes?.flatMap { e ->
        val a = Attribute.getInstance(e)
        a.attrValues.map { der(a.attrType) + der(it) }
    }.orEmpty()

    /**
     * ATSHashIndexV3 over what [sd] and [si] hold now, with SHA-256. The algorithm is written out: EN 319 122-1 lists a
     * default, but EU DSS rebuilds the index with it when absent, so an omitted one would not match its imprint.
     */
    fun hashIndex(sd: SignedData, si: SignerInfo): DERSequence {
        fun seq(items: List<ByteArray>) = DERSequence(hashes(items, "SHA-256").map { DEROctetString(it) }.toTypedArray<ASN1Encodable>())
        return DERSequence(arrayOf<ASN1Encodable>(AlgorithmIdentifier(ASN1ObjectIdentifier(SHA256_OID)),
            seq(certificateItems(sd)), seq(revocationItems(sd)), seq(attributeItems(si))))
    }

    /** The data an archive time stamp's imprint is the hash of (EN 319 122-1 5.5.2); [contentDigest] uses that hash too. */
    fun imprintInput(sd: SignedData, si: SignerInfo, contentDigest: ByteArray, index: ASN1Encodable): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(der(sd.encapContentInfo.contentType))
        out.write(contentDigest)
        out.write(der(si.version))
        out.write(der(si.sid))
        out.write(der(si.digestAlgorithm))
        si.authenticatedAttributes?.let { out.write(DERTaggedObject(false, 0, it).getEncoded(ASN1Encoding.DER)) }
        out.write(der(si.digestEncryptionAlgorithm))
        out.write(der(si.encryptedDigest))
        out.write(der(index))
        return out.toByteArray()
    }

    /**
     * Adds an archive-time-stamp-v3 to the first signer of [signedData] (a ContentInfo DER) over [content], the
     * signed content; [timestamp] returns an RFC 3161 token for data it hashes with SHA-256.
     */
    suspend fun addArchiveTimestamp(signedData: ByteArray, content: ByteArray, timestamp: suspend (ByteArray) -> ByteArray): ByteArray {
        val ci = ContentInfo.getInstance(Bc.parse(signedData))
        val sd = SignedData.getInstance(ci.content)
        val si = SignerInfo.getInstance(sd.signerInfos.getObjectAt(0))
        val index = hashIndex(sd, si)
        val token = timestamp(imprintInput(sd, si, DocCrypto.digest("SHA-256", content), index))
        // The hash index goes in the token's own unsigned attributes, outside what the time-stamp authority signed.
        val tst = CMSSignedData(ContentInfo.getInstance(Bc.parse(token)))
        val tsi = tst.signerInfos.signers.first()
        val table = (tsi.unsignedAttributes ?: AttributeTable(ASN1EncodableVector())).add(HASH_INDEX_V3, index)
        val withIndex = CMSSignedData.replaceSigners(tst, SignerInformationStore(SignerInformation.replaceUnsignedAttributes(tsi, table)))
        val unsigned = ASN1EncodableVector()
        si.unauthenticatedAttributes?.forEach { unsigned.add(it) }
        unsigned.add(Attribute(ATS_V3, DERSet(withIndex.toASN1Structure())))
        val newSi = SignerInfo(si.sid, si.digestAlgorithm, si.authenticatedAttributes, si.digestEncryptionAlgorithm, si.encryptedDigest, DERSet(unsigned))
        val signers = ASN1EncodableVector().apply {
            add(newSi)
            for (i in 1 until sd.signerInfos.size()) add(sd.signerInfos.getObjectAt(i))
        }
        val newSd = SignedData(sd.digestAlgorithms, sd.encapContentInfo, sd.certificates, sd.crLs, DERSet(signers))
        return ContentInfo(ci.contentType, newSd).getEncoded(ASN1Encoding.DER)
    }

    /** One archive time stamp found on a signer. */
    class Found(val token: ByteArray, val input: ByteArray?, val problem: String?)

    /**
     * The archive-time-stamp-v3 tokens on [si] of [sd] with the data each should cover, rebuilt from the hash index
     * the token carries; [content] is the signed content (null when it is not available).
     */
    fun find(sd: SignedData, si: SignerInfo, content: ByteArray?): List<Found> {
        val attrs = si.unauthenticatedAttributes?.map { Attribute.getInstance(it) }.orEmpty().filter { it.attrType == ATS_V3 }
        return attrs.flatMap { a -> a.attrValues.map { v -> found(sd, si, content, der(v)) } }
    }

    private fun found(sd: SignedData, si: SignerInfo, content: ByteArray?, token: ByteArray): Found {
        val parsed = runCatching {
            val tst = CMSSignedData(ContentInfo.getInstance(Bc.parse(token)))
            val tsi = tst.signerInfos.signers.first()
            val index = tsi.unsignedAttributes?.get(HASH_INDEX_V3)?.attrValues?.getObjectAt(0)
            val imprintAlg = org.bouncycastle.tsp.TimeStampToken(tst).timeStampInfo.messageImprintAlgOID.id
            index to imprintAlg
        }.getOrNull() ?: return Found(token, null, "無法解析保存時戳")
        val (index, imprintAlg) = parsed
        if (index == null) return Found(token, null, "保存時戳缺少 ats-hash-index-v3，無法確認涵蓋的資料")
        if (content == null) return Found(token, null, "需要原始內容檔才能檢查保存時戳")
        val seq = ASN1Sequence.getInstance(index)
        // hashIndAlgorithm is present only when it is not SHA-256.
        val offset = if (seq.size() == 4) 1 else 0
        val indexAlg = if (offset == 1) AlgorithmIdentifier.getInstance(seq.getObjectAt(0)).algorithm.id else SHA256_OID
        val listed = (0 until 3).map { i -> ASN1Sequence.getInstance(seq.getObjectAt(offset + i)).map { ASN1OctetString.getInstance(it).octets } }
        val alg = AlgorithmNames.jcaDigest(indexAlg)
        val present = listOf(certificateItems(sd), revocationItems(sd), attributeItems(si)).map { hashes(it, alg) }
        val missing = listed.indices.any { i -> listed[i].any { h -> present[i].none { it.contentEquals(h) } } }
        val problem = if (missing) "保存時戳之後有憑證、撤銷資訊或未簽署屬性被移除或修改" else null
        return Found(token, imprintInput(sd, si, DocCrypto.digest(AlgorithmNames.jcaDigest(imprintAlg), content), index), problem)
    }
}

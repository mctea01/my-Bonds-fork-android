package diw.wallet.core.document.sign

import diw.wallet.core.document.Bc
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.GmSignedData
import diw.wallet.core.i18n.ct
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1GeneralizedTime
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.ASN1UTCTime
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DERGeneralizedTime
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DERUTF8String
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Date

/**
 * Electronic seals (GB/T 38540-2020, GM/T 0031): reading an SESeal (versions 1 to 5), making one for the signer's
 * own SM2 key, and the SES_Signature that stamps a document with it. Version 4 and 5 seals give a version 4
 * signature (the signer certificate and algorithm outside TBS_Sign, an optional time stamp); version 1 to 3 seals
 * give the GM/T 0031-2014 form (both inside TBS_Sign).
 */
internal object OfdSeals {
    const val SM3_WITH_SM2 = "1.2.156.10197.1.501"
    private const val VENDOR = "DIW"
    private val V1_TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")

    /** A seal read from its DER: what it says, its authorised signer list (certificates or digests) and its own ASN.1. */
    class Parsed(val asn1: ASN1Sequence, val info: OfdSealInfo, val certs: List<ByteArray>) {
        val der: ByteArray get() = asn1.encoded
    }

    fun info(der: ByteArray): OfdSealInfo? = parse(der)?.info

    fun parse(der: ByteArray): Parsed? = runCatching {
        val seal = ASN1Sequence.getInstance(Bc.parse(der))
        val sealInfo = ASN1Sequence.getInstance(seal.getObjectAt(0))
        val header = ASN1Sequence.getInstance(sealInfo.getObjectAt(0))
        if ((header.getObjectAt(0) as ASN1String).string != "ES") return null
        val version = ASN1Integer.getInstance(header.getObjectAt(1)).value.toInt()
        val esId = (sealInfo.getObjectAt(1) as ASN1String).string
        val property = ASN1Sequence.getInstance(sealInfo.getObjectAt(2))
        val picture = ASN1Sequence.getInstance(sealInfo.getObjectAt(3))
        val type = ASN1Integer.getInstance(property.getObjectAt(0)).value.toInt()
        val name = (property.getObjectAt(1) as ASN1String).string
        val times = property.mapNotNull { time(it) }
        val list = property.firstOrNull { it is ASN1Sequence || it is ASN1TaggedObject }?.let { certList(it) }.orEmpty()
        val makerDer = if (seal.size() >= 4) ASN1OctetString.getInstance(seal.getObjectAt(1)).octets
        else ASN1OctetString.getInstance(ASN1Sequence.getInstance(seal.getObjectAt(1)).getObjectAt(0)).octets
        val maker = Bc.holder(makerDer)?.let { h -> h.subject.getRDNs(org.bouncycastle.asn1.x500.style.BCStyle.CN).firstOrNull()?.first?.value?.toString() ?: h.subject.toString() }
        val info = OfdSealInfo(
            version = version, id = esId, name = name, personal = type == 2,
            validFrom = times.getOrNull(times.size - 2), validTo = times.lastOrNull(),
            pictureType = (picture.getObjectAt(0) as ASN1String).string.lowercase(),
            picture = ASN1OctetString.getInstance(picture.getObjectAt(1)).octets,
            widthMm = runCatching { ASN1Integer.getInstance(picture.getObjectAt(2)).value.toDouble() }.getOrDefault(0.0),
            heightMm = runCatching { ASN1Integer.getInstance(picture.getObjectAt(3)).value.toDouble() }.getOrDefault(0.0),
            maker = maker, signers = list.size,
        )
        Parsed(seal, info, list)
    }.getOrNull()

    private fun time(e: ASN1Encodable): Long? = when (e) {
        is ASN1GeneralizedTime -> runCatching { e.date.time / 1000 }.getOrNull()
        is ASN1UTCTime -> runCatching { e.adjustedDate.time / 1000 }.getOrNull()
        else -> null
    }

    /** Certificates (type 1) or certificate digests (type 2) of the signers a seal allows. */
    private fun certList(e: ASN1Encodable): List<ByteArray> = runCatching {
        val seq = if (e is ASN1TaggedObject) ASN1Sequence.getInstance(e.baseObject.toASN1Primitive()) else ASN1Sequence.getInstance(e)
        seq.flatMap { item ->
            when (item) {
                is ASN1OctetString -> listOf(item.octets)
                is ASN1Sequence -> item.mapNotNull { (it as? ASN1OctetString)?.octets }
                else -> emptyList()
            }
        }
    }.getOrDefault(emptyList())

    /** True when [seal] lets the holder of [cert] (DER) sign with it: listed by certificate or digest, or no list at all. */
    fun allows(seal: Parsed, cert: ByteArray): Boolean = seal.certs.isEmpty() || seal.certs.any {
        it.contentEquals(cert) || it.contentEquals(DocCrypto.digest("SM3", cert)) || it.contentEquals(DocCrypto.digest("SHA-256", cert))
    }

    /** Width and height of a PNG from its header, or null for another file. */
    fun pngSize(png: ByteArray): Pair<Int, Int>? {
        if (png.size < 24 || png[0] != 0x89.toByte() || png[1] != 'P'.code.toByte() || png[12] != 'I'.code.toByte()) return null
        fun u32(o: Int) = ((png[o].toInt() and 0xFF) shl 24) or ((png[o + 1].toInt() and 0xFF) shl 16) or ((png[o + 2].toInt() and 0xFF) shl 8) or (png[o + 3].toInt() and 0xFF)
        return (u32(16) to u32(20)).takeIf { it.first > 0 && it.second > 0 }
    }

    private fun gt(seconds: Long) = DERGeneralizedTime(Date(seconds * 1000))

    /**
     * A version 4 SESeal for the signer's own key: the signer is both the seal maker and the one signer it allows.
     * Valid from now until the signer certificate expires.
     */
    suspend fun make(signer: DocumentSigner, name: String, personal: Boolean, picture: ByteArray, widthMm: Int, heightMm: Int, nowSeconds: Long): ByteArray {
        val cert = signer.certificateChain.firstOrNull() ?: throw SigningException(ct("core_key_no_certificate"))
        val holder = Bc.holder(cert) ?: throw SigningException(ct("core_key_no_certificate"))
        val until = holder.notAfter.time / 1000
        if (until <= nowSeconds) throw SigningException(ct("core_ofd_seal_cert_expired"))
        val header = DERSequence(arrayOf<ASN1Encodable>(DERIA5String("ES"), ASN1Integer(4), DERIA5String(VENDOR)))
        val property = DERSequence(
            arrayOf<ASN1Encodable>(
                ASN1Integer(if (personal) 2L else 1L), DERUTF8String(name), ASN1Integer(1),
                DERSequence(DEROctetString(cert)), gt(nowSeconds), gt(nowSeconds - 60), gt(until),
            ),
        )
        val pic = DERSequence(arrayOf<ASN1Encodable>(DERIA5String("PNG"), DEROctetString(picture), ASN1Integer(widthMm.toLong()), ASN1Integer(heightMm.toLong())))
        val esId = VENDOR + DocCrypto.randomBytes(8).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
        val sealInfo = DERSequence(arrayOf<ASN1Encodable>(header, DERIA5String(esId), property, pic))
        val signature = signer.sign(sealInfo.encoded)
        if (!GmSignedData.verifySignature(holder, SM3_WITH_SM2, null, sealInfo.encoded, signature)) throw SigningException(ct("core_jds_mismatch"))
        return DERSequence(arrayOf<ASN1Encodable>(sealInfo, DEROctetString(cert), ASN1ObjectIdentifier(SM3_WITH_SM2), DERBitString(signature))).encoded
    }

    /**
     * The SES_Signature stamping [signed] (the Signature.xml bytes) with [seal]: TBS_Sign with the SM3 digest of
     * [signed] and [property] (the Signature.xml path), signed by [signer]; a version 4 signature carries an RFC 3161
     * token over the signature value when [timestamper] gives one. Checked before it is returned.
     */
    suspend fun signature(seal: Parsed, signer: DocumentSigner, signed: ByteArray, property: String, nowSeconds: Long, timestamper: Timestamper?, token: (ByteArray) -> ASN1Primitive): ByteArray {
        val cert = signer.certificateChain.firstOrNull() ?: throw SigningException(ct("core_key_no_certificate"))
        val holder = Bc.holder(cert) ?: throw SigningException(ct("core_key_no_certificate"))
        val hash = DERBitString(DocCrypto.digest("SM3", signed))
        val v4 = seal.info.version >= 4
        val tbs = if (v4) {
            DERSequence(arrayOf<ASN1Encodable>(ASN1Integer(4), seal.asn1, gt(nowSeconds), hash, DERIA5String(property)))
        } else {
            val time = ZonedDateTime.ofInstant(java.time.Instant.ofEpochSecond(nowSeconds), ZoneOffset.UTC).format(V1_TIME)
            DERSequence(
                arrayOf<ASN1Encodable>(
                    ASN1Integer(seal.info.version.toLong()), seal.asn1, DERBitString(time.encodeToByteArray()), hash, DERIA5String(property),
                    DEROctetString(cert), ASN1ObjectIdentifier(SM3_WITH_SM2),
                ),
            )
        }
        val value = signer.sign(tbs.encoded)
        if (!GmSignedData.verifySignature(holder, SM3_WITH_SM2, null, tbs.encoded, value)) throw SigningException(ct("core_jds_mismatch"))
        if (!v4) return DERSequence(arrayOf<ASN1Encodable>(tbs, DERBitString(value))).encoded
        val out = ASN1EncodableVector().apply {
            add(tbs)
            add(DEROctetString(cert))
            add(ASN1ObjectIdentifier(SM3_WITH_SM2))
            add(DERBitString(value))
            timestamper?.timestamp(value)?.let { add(DERTaggedObject(true, 0, DERBitString(token(it).encoded))) }
        }
        return DERSequence(out).encoded
    }
}

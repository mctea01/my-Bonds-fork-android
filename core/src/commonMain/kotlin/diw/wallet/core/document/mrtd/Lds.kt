package diw.wallet.core.document.mrtd

/**
 * The SecurityInfos of EF.CardAccess and DG14 (ICAO 9303 part 11, 9.2): which access, chip and active
 * authentication protocols the chip supports and with which keys.
 */
sealed class SecurityInfo {
    abstract val oid: String

    data class Pace(override val oid: String, val version: Int, val parameterId: Int?) : SecurityInfo() {
        val cipher: SmCipher? get() = MrtdOids.cipherOf(oid)
        /** Generic mapping, which is what this wallet implements (integrated and CAM mapping are not). */
        val genericMapping: Boolean get() = oid.startsWith(MrtdOids.PACE_DH_GM + ".") || oid.startsWith(MrtdOids.PACE_ECDH_GM + ".")
    }

    data class ChipAuthentication(override val oid: String, val version: Int, val keyId: Int?) : SecurityInfo() {
        val cipher: SmCipher? get() = MrtdOids.cipherOf(oid)
    }

    data class ChipAuthenticationPublicKey(override val oid: String, val publicKey: ByteArray, val keyId: Int?) : SecurityInfo() {
        override fun equals(other: Any?) = other is ChipAuthenticationPublicKey && other.oid == oid && other.publicKey.contentEquals(publicKey) && other.keyId == keyId
        override fun hashCode() = oid.hashCode() * 31 + publicKey.contentHashCode()
    }

    data class ActiveAuthentication(override val oid: String, val version: Int, val signatureAlgorithm: String?) : SecurityInfo()

    data class TerminalAuthentication(override val oid: String, val version: Int) : SecurityInfo()

    data class Other(override val oid: String) : SecurityInfo()

    companion object {
        /** The infos of a SET OF SecurityInfo (EF.CardAccess) or DG14 (tag 6E around the SET). */
        fun parse(bytes: ByteArray): List<SecurityInfo> {
            val outer = BerTlv.read(bytes, 0) ?: return emptyList()
            val set = when (outer.tag) {
                0x6E -> BerTlv.find(outer.value, 0x31) ?: return emptyList()
                0x31 -> outer.value
                else -> return emptyList()
            }
            return BerTlv.children(set).filter { it.tag == 0x30 }.mapNotNull { one(it.value) }
        }

        private fun one(seq: ByteArray): SecurityInfo? {
            val parts = BerTlv.children(seq)
            val oidTlv = parts.firstOrNull { it.tag == 0x06 } ?: return null
            val oid = BerTlv.oidString(oidTlv.value)
            val ints = parts.filter { it.tag == 0x02 }.map { BerTlv.uint(it.value) }
            return when {
                oid.startsWith(MrtdOids.PACE + ".") -> Pace(oid, ints.getOrElse(0) { 0 }, ints.getOrNull(1))
                oid.startsWith(MrtdOids.PK + ".") -> {
                    val spki = parts.firstOrNull { it.tag == 0x30 } ?: return null
                    ChipAuthenticationPublicKey(oid, seq.copyOfRange(spki.start, spki.end), ints.getOrNull(0))
                }
                oid.startsWith(MrtdOids.CA + ".") -> ChipAuthentication(oid, ints.getOrElse(0) { 0 }, ints.getOrNull(1))
                oid == MrtdOids.AA -> ActiveAuthentication(oid, ints.getOrElse(0) { 0 }, parts.drop(1).firstOrNull { it.tag == 0x06 }?.let { BerTlv.oidString(it.value) })
                oid.startsWith(MrtdOids.TA) -> TerminalAuthentication(oid, ints.getOrElse(0) { 0 })
                else -> Other(oid)
            }
        }
    }
}

/** Protocol object identifiers of BSI TR-03110 and ICAO 9303. */
object MrtdOids {
    const val BSI = "0.4.0.127.0.7.2.2"
    const val PK = "$BSI.1"
    const val PK_DH = "$PK.1"
    const val PK_ECDH = "$PK.2"
    const val TA = "$BSI.2"
    const val CA = "$BSI.3"
    const val CA_DH = "$CA.1"
    const val CA_ECDH = "$CA.2"
    const val PACE = "$BSI.4"
    const val PACE_DH_GM = "$PACE.1"
    const val PACE_ECDH_GM = "$PACE.2"
    const val PACE_DH_IM = "$PACE.3"
    const val PACE_ECDH_IM = "$PACE.4"
    const val PACE_ECDH_CAM = "$PACE.6"
    const val AA = "2.23.136.1.1.5"
    const val LDS_SECURITY_OBJECT = "2.23.136.1.1.1"

    /** The cipher named by the last arc of a PACE or CA protocol: 1 3DES, 2 to 4 AES-128 to AES-256. */
    fun cipherOf(oid: String): SmCipher? = when (oid.substringAfterLast('.')) {
        "1" -> SmCipher.DES3
        "2" -> SmCipher.AES128
        "3" -> SmCipher.AES192
        "4" -> SmCipher.AES256
        else -> null
    }

    /** "PACE-ECDH-GM-AES-128" and the like. */
    fun protocolName(oid: String): String {
        val cipher = when (cipherOf(oid)) {
            SmCipher.DES3 -> "3DES"; SmCipher.AES128 -> "AES-128"; SmCipher.AES192 -> "AES-192"; SmCipher.AES256 -> "AES-256"; null -> "?"
        }
        val base = oid.substringBeforeLast('.')
        val name = when (base) {
            PACE_DH_GM -> "PACE-DH-GM"; PACE_ECDH_GM -> "PACE-ECDH-GM"; PACE_DH_IM -> "PACE-DH-IM"; PACE_ECDH_IM -> "PACE-ECDH-IM"
            PACE_ECDH_CAM -> "PACE-ECDH-CAM"; CA_DH -> "CA-DH"; CA_ECDH -> "CA-ECDH"
            else -> return oid
        }
        return "$name-$cipher"
    }
}

/** The elementary files of the LDS 1 application. */
enum class LdsFile(val fid: Int, val tag: Int, val dataGroup: Int?) {
    COM(0x011E, 0x60, null), SOD(0x011D, 0x77, null),
    DG1(0x0101, 0x61, 1), DG2(0x0102, 0x75, 2), DG3(0x0103, 0x63, 3), DG4(0x0104, 0x76, 4), DG5(0x0105, 0x65, 5),
    DG6(0x0106, 0x66, 6), DG7(0x0107, 0x67, 7), DG8(0x0108, 0x68, 8), DG9(0x0109, 0x69, 9), DG10(0x010A, 0x6A, 10),
    DG11(0x010B, 0x6B, 11), DG12(0x010C, 0x6C, 12), DG13(0x010D, 0x6D, 13), DG14(0x010E, 0x6E, 14), DG15(0x010F, 0x6F, 15),
    DG16(0x0110, 0x70, 16);

    /** DG3 and DG4 (fingerprints, iris) need Extended Access Control with a terminal certificate, which a wallet has not. */
    val restricted: Boolean get() = this == DG3 || this == DG4

    companion object {
        fun ofTag(tag: Int) = entries.firstOrNull { it.tag == tag }
        fun ofDataGroup(n: Int) = entries.firstOrNull { it.dataGroup == n }
    }
}

/** A picture stored in a data group, as an encoded image the app can decode (JPEG or JPEG 2000). */
class MrtdImage(val mediaType: String, val data: ByteArray, val width: Int?, val height: Int?)

/** The holder's additional personal details (DG11). Names keep the zone's filler convention turned into spaces. */
data class PersonalDetails(
    val fullName: String?,
    val otherNames: List<String>,
    val personalNumber: String?,
    /** YYYYMMDD. */
    val fullBirthDate: String?,
    val placeOfBirth: String?,
    val address: String?,
    val telephone: String?,
    val profession: String?,
    val title: String?,
    val personalSummary: String?,
    val otherTravelDocuments: List<String>,
    val custodyInformation: String?,
)

/** Additional document details (DG12). */
data class DocumentDetails(
    val issuingAuthority: String?,
    /** YYYYMMDD. */
    val issueDate: String?,
    val otherPersons: List<String>,
    val endorsements: String?,
    val taxOrExitRequirements: String?,
    /** yyyyMMddhhmmss. */
    val personalizationTime: String?,
    val personalizationDevice: String?,
)

/** Parsers of the LDS data groups (ICAO 9303 part 10). */
object Lds {
    /** EF.COM: LDS and Unicode versions and the tags of the data groups present. */
    class Com(val ldsVersion: String?, val unicodeVersion: String?, val tags: List<Int>) {
        val files: List<LdsFile> get() = tags.mapNotNull { LdsFile.ofTag(it) }
    }

    private fun body(bytes: ByteArray, tag: Int): ByteArray? = BerTlv.read(bytes, 0)?.takeIf { it.tag == tag }?.value

    fun com(bytes: ByteArray): Com? {
        val v = body(bytes, 0x60) ?: return null
        fun version(t: Int) = BerTlv.find(v, t)?.decodeToString()?.let { s -> s.chunked(2).joinToString(".") { it.trimStart('0').ifEmpty { "0" } } }
        val tags = BerTlv.find(v, 0x5C)?.map { it.toInt() and 0xFF }.orEmpty()
        return Com(version(0x5F01), version(0x5F36), tags)
    }

    fun dg1(bytes: ByteArray): Mrz? = body(bytes, 0x61)?.let { BerTlv.find(it, 0x5F1F) }?.decodeToString()?.let { Mrz.parse(it) }

    /** The facial images of DG2 (ISO/IEC 19794-5 records inside the biometric information templates). */
    fun dg2(bytes: ByteArray): List<MrtdImage> {
        val v = body(bytes, 0x75) ?: return emptyList()
        val group = BerTlv.find(v, 0x7F61) ?: return emptyList()
        return BerTlv.children(group).filter { it.tag == 0x7F60 }.mapNotNull { bit ->
            val bdb = BerTlv.find(bit.value, 0x5F2E) ?: BerTlv.find(bit.value, 0x7F2E) ?: return@mapNotNull null
            faceImage(bdb)
        }
    }

    /** The picture of a biometric data block: an ISO/IEC 19794-5 facial record, or a bare image as a fallback. */
    fun faceImage(bdb: ByteArray): MrtdImage? {
        if (bdb.size > 14 && bdb[0] == 'F'.code.toByte() && bdb[1] == 'A'.code.toByte() && bdb[2] == 'C'.code.toByte() && bdb[3] == 0.toByte()) {
            runCatching {
                var p = 14
                val recordLength = u32(bdb, p)
                val featurePoints = u16(bdb, p + 4)
                val recordEnd = minOf(bdb.size, p + recordLength)
                p += 20 + featurePoints * 8
                val dataType = bdb[p + 1].toInt() and 0xFF
                val width = u16(bdb, p + 2)
                val height = u16(bdb, p + 4)
                p += 12
                if (p < recordEnd) {
                    val data = bdb.copyOfRange(p, recordEnd)
                    val type = imageType(data) ?: if (dataType == 1) "image/jp2" else "image/jpeg"
                    return MrtdImage(type, data, width, height)
                }
            }
        }
        return imageIn(bdb)
    }

    /** The first JPEG or JPEG 2000 image inside [b]. */
    fun imageIn(b: ByteArray): MrtdImage? {
        for (i in 0 until b.size - 12) {
            val type = imageTypeAt(b, i) ?: continue
            return MrtdImage(type, b.copyOfRange(i, b.size), null, null)
        }
        return null
    }

    private val JP2 = byteArrayOf(0, 0, 0, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87.toByte(), 0x0A)

    /** image/jpeg, image/jp2 (JP2 file) or image/j2k (bare codestream), by the signature at the start of [b]. */
    fun imageType(b: ByteArray): String? = imageTypeAt(b, 0)

    private fun imageTypeAt(b: ByteArray, i: Int): String? {
        fun at(k: Int, v: Int) = i + k < b.size && b[i + k] == v.toByte()
        return when {
            at(0, 0xFF) && at(1, 0xD8) && at(2, 0xFF) -> "image/jpeg"
            JP2.indices.all { at(it, JP2[it].toInt()) } -> "image/jp2"
            at(0, 0xFF) && at(1, 0x4F) && at(2, 0xFF) && at(3, 0x51) -> "image/j2k"
            else -> null
        }
    }

    private fun u16(b: ByteArray, p: Int) = ((b[p].toInt() and 0xFF) shl 8) or (b[p + 1].toInt() and 0xFF)
    private fun u32(b: ByteArray, p: Int) = (u16(b, p) shl 16) or u16(b, p + 2)

    /**
     * Text of a DG11 or DG12 field: UTF-8, fillers as spaces, a double filler (name parts) as a comma. Control
     * characters some issuers pad fields with (such as NUL) count as spaces, so they do not show as gaps.
     */
    private fun text(b: ByteArray?): String? = b?.decodeToString()?.map { if (it.isISOControl()) ' ' else it }?.joinToString("")?.let { s ->
        if (s.contains("<<")) {
            val idx = s.indexOf("<<")
            val primary = s.substring(0, idx).replace('<', ' ').trim()
            val secondary = s.substring(idx + 2).replace('<', ' ').trim().replace(Regex(" +"), " ")
            listOf(primary, secondary).filter { it.isNotEmpty() }.joinToString(", ")
        } else s.replace('<', ' ').trim().replace(Regex(" +"), " ")
    }?.takeIf { it.isNotEmpty() }

    private fun list(v: ByteArray, tag: Int): List<String> =
        BerTlv.children(v).filter { it.tag == tag }.mapNotNull { text(it.value) } +
            BerTlv.children(v).filter { it.tag == 0xA0 }.flatMap { a -> BerTlv.children(a.value).filter { it.tag == tag }.mapNotNull { text(it.value) } }

    fun dg11(bytes: ByteArray): PersonalDetails? {
        val v = body(bytes, 0x6B) ?: return null
        return PersonalDetails(
            fullName = text(BerTlv.find(v, 0x5F0E)),
            otherNames = list(v, 0x5F0F),
            personalNumber = text(BerTlv.find(v, 0x5F10)),
            fullBirthDate = BerTlv.find(v, 0x5F2B)?.let { date(it) },
            placeOfBirth = text(BerTlv.find(v, 0x5F11)),
            address = text(BerTlv.find(v, 0x5F42)),
            telephone = text(BerTlv.find(v, 0x5F12)),
            profession = text(BerTlv.find(v, 0x5F13)),
            title = text(BerTlv.find(v, 0x5F14)),
            personalSummary = text(BerTlv.find(v, 0x5F15)),
            otherTravelDocuments = list(v, 0x5F17),
            custodyInformation = text(BerTlv.find(v, 0x5F18)),
        )
    }

    fun dg12(bytes: ByteArray): DocumentDetails? {
        val v = body(bytes, 0x6C) ?: return null
        return DocumentDetails(
            issuingAuthority = text(BerTlv.find(v, 0x5F19)),
            issueDate = BerTlv.find(v, 0x5F26)?.let { date(it) },
            otherPersons = list(v, 0x5F1A),
            endorsements = text(BerTlv.find(v, 0x5F1B)),
            taxOrExitRequirements = text(BerTlv.find(v, 0x5F1C)),
            personalizationTime = BerTlv.find(v, 0x5F55)?.let { b -> if (b.all { it in 0x30..0x39 }) b.decodeToString() else hexDigits(b) },
            personalizationDevice = text(BerTlv.find(v, 0x5F56)),
        )
    }

    /** A date written as 8 ASCII digits, or as 4 BCD bytes as some issuers do. */
    private fun date(b: ByteArray): String? = when {
        b.size == 8 && b.all { it in 0x30..0x39 } -> b.decodeToString()
        b.size == 4 -> hexDigits(b).takeIf { s -> s.all { it.isDigit() } }
        else -> b.decodeToString().filter { it.isDigit() }.takeIf { it.length == 8 }
    }

    private fun hexDigits(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    /** The displayed portrait (DG5) or signature (DG7) images. */
    fun displayedImages(bytes: ByteArray): List<MrtdImage> {
        val outer = BerTlv.read(bytes, 0) ?: return emptyList()
        return BerTlv.children(outer.value).filter { it.tag == 0x5F40 || it.tag == 0x5F43 }.mapNotNull { t ->
            imageType(t.value)?.let { MrtdImage(it, t.value, null, null) } ?: imageIn(t.value)
        }
    }

    /** The Active Authentication public key of DG15 (a SubjectPublicKeyInfo). */
    fun dg15(bytes: ByteArray): ByteArray? {
        val outer = BerTlv.read(bytes, 0)?.takeIf { it.tag == 0x6F } ?: return null
        val spki = BerTlv.read(outer.value, 0) ?: return null
        return outer.value.copyOfRange(spki.start, spki.end)
    }
}

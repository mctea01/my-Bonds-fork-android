package diw.wallet.core.document

import diw.wallet.core.document.mrtd.ChipCheck
import diw.wallet.core.document.mrtd.Lds
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.MrtdCrypto
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.document.mrtd.MrtdOids
import diw.wallet.core.document.mrtd.SecurityInfo
import diw.wallet.core.i18n.ct
import diw.wallet.core.trust.TrustRole
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSSignedData
import kotlin.io.encoding.Base64
import kotlin.time.Instant

/**
 * Passive authentication of a travel document read into the wallet (ICAO 9303 part 11, 5.1): the security object's
 * CMS signature by the document signer, the document signer's chain to a country signing CA anchor
 * ([TrustRole.TRAVEL_DOCUMENT]), and the hash of every data group read against the security object. Active
 * Authentication is verified again from the stored challenge and response; Chip Authentication can only be reported
 * as it went while the chip was read.
 */
internal object MrtdInspection {
    /**
     * The security object: the hash algorithm, the hash of each data group by number, and [contentType] as the
     * signed content names it.
     */
    class SecurityObject(val hashAlgorithm: String, val hashes: Map<Int, ByteArray>, val ldsVersion: String?, val contentType: String)

    /** Why the signed content could not be read as a security object. */
    class NotSecurityObject(message: String) : Exception(message)

    /**
     * The LDSSecurityObject of [sd]. Besides id-icao-ldsSecurityObject, the content may be named id-data (some
     * documents issued in mainland China), by the old 1.3.27.1.1.1, or by 2.23.136.1.1.6.2 (Taiwan's passports, in the
     * arc of ICAO certificate extensions); the content must still parse as an LDSSecurityObject, which is what the data
     * groups are checked against, and a type that is not the standard one is shown as a note. Any other type is refused.
     */
    fun securityObject(sd: CMSSignedData): SecurityObject {
        val type = sd.signedContentTypeOID
        val content = sd.signedContent?.content as? ByteArray ?: throw NotSecurityObject("no encapsulated content")
        if (type !in LDS_CONTENT_TYPES) throw NotSecurityObject("content type $type")
        val (alg, hashes, seq) = try {
            val seq = ASN1Sequence.getInstance(org.bouncycastle.asn1.ASN1InputStream(content).use { it.readObject() } ?: throw NotSecurityObject("empty content"))
            val alg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1)).algorithm.id
            val hashes = ASN1Sequence.getInstance(seq.getObjectAt(2)).map { e ->
                val dg = ASN1Sequence.getInstance(e)
                ASN1Integer.getInstance(dg.getObjectAt(0)).intValueExact() to ASN1OctetString.getInstance(dg.getObjectAt(1)).octets
            }.toMap()
            Triple(alg, hashes, seq)
        } catch (e: NotSecurityObject) {
            throw e
        } catch (e: Exception) {
            throw NotSecurityObject("content of type $type is not an LDSSecurityObject")
        }
        if (hashes.isEmpty()) throw NotSecurityObject("no data group hashes")
        if (hashes.keys.any { it !in 1..16 }) throw NotSecurityObject("data group numbers out of range")
        val lds = if (seq.size() > 3) runCatching {
            val v = ASN1Sequence.getInstance(seq.getObjectAt(3))
            org.bouncycastle.asn1.ASN1PrintableString.getInstance(v.getObjectAt(0)).string
        }.getOrNull() else null
        return SecurityObject(AlgorithmNames.jcaDigest(alg), hashes, lds, type)
    }

    /** id-icao-ldsSecurityObject, id-data, the old 1.3.27.1.1.1 and the type of Taiwan passports. */
    private val LDS_CONTENT_TYPES = setOf(MrtdOids.LDS_SECURITY_OBJECT, "1.2.840.113549.1.7.1", "1.3.27.1.1.1", "2.23.136.1.1.6.2")

    /** The CMS SignedData inside EF.SOD (tag 77). */
    fun sodCms(sod: ByteArray): ByteArray {
        val t = diw.wallet.core.document.mrtd.BerTlv.read(sod, 0) ?: throw IllegalArgumentException("SOD")
        return if (t.tag == 0x77) t.value else sod
    }

    suspend fun inspect(bytes: ByteArray, base: DocumentReport, checks: CmsChecks, pki: PkiSupport, now: Instant): DocumentReport {
        val dump = MrtdDump.decode(bytes) ?: return base.copy(format = DocumentFormat.EMRTD, problems = listOf(ct("core_mrtd_unreadable")))
        val notes = ArrayList<String>()
        val problems = ArrayList<String>()
        val mrz = dump.file(LdsFile.DG1)?.let { Lds.dg1(it) }
        val sod = dump.file(LdsFile.SOD) ?: return base.copy(format = DocumentFormat.EMRTD, problems = listOf(ct("core_mrtd_no_sod")))
        val cms = sodCms(sod)
        val label = ct("core_mrtd_sod_label")
        val sig = checks.verify(cms, null, SignatureFormat.ICAO_PA, label, now, role = TrustRole.TRAVEL_DOCUMENT).first()
        val sd = runCatching { CMSSignedData(cms) }.getOrNull()
        val parsed = sd?.let { runCatching { securityObject(it) } }
        val so = parsed?.getOrNull()
        val matched = ArrayList<Int>()
        val mismatched = ArrayList<Int>()
        val notRead = ArrayList<Int>()
        val notCovered = ArrayList<Int>()
        if (so == null) {
            val reason = parsed?.exceptionOrNull()?.let { it.message ?: it.javaClass.simpleName } ?: "CMS"
            problems.add(ct("core_mrtd_no_lds_object") + " (" + reason + ")")
        } else {
            if (so.contentType != MrtdOids.LDS_SECURITY_OBJECT) notes.add(ct("core_mrtd_content_type", so.contentType))
            for ((n, expected) in so.hashes.toSortedMap()) {
                val f = LdsFile.ofDataGroup(n)
                val data = f?.let { dump.file(it) }
                when {
                    data == null -> notRead.add(n)
                    DocCrypto.digest(so.hashAlgorithm, data).contentEquals(expected) -> matched.add(n)
                    else -> mismatched.add(n)
                }
            }
            for (f in LdsFile.entries) {
                val n = f.dataGroup ?: continue
                if (n !in so.hashes && dump.files.containsKey(f.name)) notCovered.add(n)
            }
            if (mismatched.isNotEmpty()) problems.add(ct("core_mrtd_hash_mismatch", mismatched.joinToString(", ") { "DG$it" }))
            if (notCovered.isNotEmpty()) problems.add(ct("core_mrtd_not_covered", notCovered.joinToString(", ") { "DG$it" }))
            if (1 !in matched) problems.add(ct("core_mrtd_dg1_unverified"))
            if (so.hashAlgorithm == "SHA-1") notes.add(ct("core_mrtd_sha1"))
        }
        val signerHolder = sd?.certificates?.getMatches(null)?.filterIsInstance<X509CertificateHolder>()?.firstOrNull()
        val signerCountry = signerHolder?.let { Bc.country(it) }
        if (signerCountry != null && mrz != null && !sameState(signerCountry, mrz.issuingState)) {
            problems.add(ct("core_mrtd_country_mismatch", signerCountry, mrz.issuingState))
        }
        // Integrity of the whole: the CMS signature and every data group read.
        val integrity = when {
            sig.integrity == Check.FAIL || mismatched.isNotEmpty() || notCovered.isNotEmpty() || so == null -> Check.FAIL
            sig.integrity != Check.PASS -> sig.integrity
            else -> Check.PASS
        }
        if (mrz != null && !mrz.checkDigitsValid) notes.add(ct("core_mrtd_check_digits", mrz.failedChecks.joinToString(", ")))
        if (mrz?.nameMayBeTruncated == true) notes.add(ct("core_mrtd_name_truncated"))

        val aa = dump.activeAuthentication?.let { rec ->
            val spki = dump.file(LdsFile.DG15)?.let { Lds.dg15(it) }
            val sigOid = dump.file(LdsFile.DG14)?.let { SecurityInfo.parse(it) }?.filterIsInstance<SecurityInfo.ActiveAuthentication>()?.firstOrNull()?.signatureAlgorithm
            if (spki != null && 15 in matched && MrtdCrypto.verifyActiveAuthentication(spki, Base64.decode(rec.challenge), Base64.decode(rec.response), sigOid) != null) ChipCheck.PASS else ChipCheck.FAIL
        } ?: dump.activeAuthenticationResult
        when (dump.chipAuthentication) {
            ChipCheck.PASS -> notes.add(ct("core_mrtd_ca_pass", dump.chipAuthenticationProtocol ?: "CA"))
            ChipCheck.FAIL -> problems.add(ct("core_mrtd_ca_fail"))
            else -> {}
        }
        if (dump.chipAuthentication == ChipCheck.PASS && 14 !in matched) problems.add(ct("core_mrtd_dg14_unverified"))
        when (aa) {
            ChipCheck.PASS -> notes.add(ct("core_mrtd_aa_pass"))
            ChipCheck.FAIL -> problems.add(ct("core_mrtd_aa_fail"))
            else -> {}
        }
        if (dump.chipAuthentication != ChipCheck.PASS && aa != ChipCheck.PASS) notes.add(ct("core_mrtd_no_clone_check"))
        notes.add(ct("core_mrtd_access", dump.access))
        if (dump.unreadable.isNotEmpty()) notes.add(ct("core_mrtd_unreadable_files", dump.unreadable.joinToString(", ")))
        val signature = sig.copy(
            integrity = integrity,
            coversWholeDocument = notCovered.isEmpty() && mismatched.isEmpty(),
            problems = sig.problems + problems,
            notes = sig.notes,
        )
        val title = mrz?.let { m -> listOf(m.primaryIdentifier, m.secondaryIdentifier).filter { it.isNotEmpty() }.joinToString(" ").ifEmpty { null } }
        return base.copy(
            format = DocumentFormat.EMRTD,
            title = title,
            signatures = listOf(signature),
            travelDocument = TravelDocumentCheck(
                hashAlgorithm = so?.hashAlgorithm,
                matched = matched,
                mismatched = mismatched,
                notRead = notRead,
                notCovered = notCovered,
                ldsVersion = so?.ldsVersion ?: dump.file(LdsFile.COM)?.let { Lds.com(it)?.ldsVersion },
                access = dump.access,
                chipAuthentication = dump.chipAuthentication,
                activeAuthentication = aa,
                signerCountry = signerCountry,
                issuingState = mrz?.issuingState,
                readAt = dump.readAt,
            ),
            notes = notes,
        )
    }

    /** ISO 3166 alpha-2 of the certificate against the alpha-3 code of the zone ("D" is Germany in the zone). */
    private fun sameState(alpha2: String, zone: String): Boolean {
        val a3 = ALPHA3[alpha2.uppercase()] ?: return true
        return a3 == zone || (zone == "D" && a3 == "DEU")
    }

    /** Alpha-2 to alpha-3 for the states whose documents the wallet is likely to read; others are not compared. */
    private val ALPHA3 = mapOf(
        "TW" to "TWN", "CN" to "CHN", "HK" to "CHN", "MO" to "CHN", "JP" to "JPN", "KR" to "KOR", "US" to "USA",
        "GB" to "GBR", "DE" to "DEU", "FR" to "FRA", "NL" to "NLD", "IT" to "ITA", "ES" to "ESP", "CA" to "CAN",
        "AU" to "AUS", "NZ" to "NZL", "SG" to "SGP", "MY" to "MYS", "TH" to "THA", "PH" to "PHL", "VN" to "VNM",
        "ID" to "IDN", "IN" to "IND", "CH" to "CHE", "AT" to "AUT", "BE" to "BEL", "SE" to "SWE", "NO" to "NOR",
        "DK" to "DNK", "FI" to "FIN", "PL" to "POL", "CZ" to "CZE", "PT" to "PRT", "IE" to "IRL", "UA" to "UKR",
    )
}

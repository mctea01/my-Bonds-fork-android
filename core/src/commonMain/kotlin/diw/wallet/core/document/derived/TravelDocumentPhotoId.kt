package diw.wallet.core.document.derived

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.mrtd.Lds
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.MrtdCrypto
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.holder.HolderKey
import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlinx.io.bytestring.ByteString
import org.multipaz.asn1.ASN1Integer
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.RawCbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.Uint
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.toDataItem
import org.multipaz.cbor.toDataItemFullDate
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseLabel
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.X509KeyUsage
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * An ISO/IEC 23220-2 Photo ID mdoc made from an electronic passport (docs/design/zkpassport.md 5.4 item 3): the
 * person fields come from DG1 (and the portrait from DG2), and `org.iso.23220.datagroups.1` carries DG1, DG2 and the
 * security object as the chip returned them, so a verifier can repeat passive authentication to the issuing state's
 * CSCA. The issuer is the wallet's document issuer key under a self-signed certificate (T3); this is the standard
 * presentation of a passport, apart from the zkPassport dialect.
 */
object TravelDocumentPhotoId {
    const val DOCTYPE = "org.iso.23220.photoid.1"
    const val NAMESPACE = "org.iso.23220.1"
    const val PHOTO_ID_NAMESPACE = "org.iso.23220.photoid.1"
    const val DATAGROUPS_NAMESPACE = "org.iso.23220.datagroups.1"

    /** Age thresholds stated at issuance; a false can only become true later, so a stale value never overstates age. */
    val AGE_THRESHOLDS = listOf(13, 15, 16, 18, 21, 25, 60, 65)

    /** Validity of one issuance, cut at the passport's expiry. */
    val VALIDITY = 365.days

    /** ICAO 9303 part 4 key purpose of a document signer of mdocs (ISO/IEC 18013-5 B.1.4): id-mdl-kp-mdlDS. */
    private val MDL_DS_EKU = byteArrayOf(0x30, 0x09, 0x06, 0x07, 0x28, 0x81.toByte(), 0x8C.toByte(), 0x5D, 0x05, 0x01, 0x02)
    private const val OID_EXTENDED_KEY_USAGE = "2.5.29.37"

    /** The data elements of [dump] by namespace, for the holder to review before issuance; null without a readable DG1. */
    fun elements(dump: MrtdDump, now: Instant = Clock.System.now()): Map<String, Map<String, DataItem>>? {
        val dg1 = dump.file(LdsFile.DG1) ?: return null
        val mrz = Lds.dg1(dg1) ?: return null
        val sod = dump.file(LdsFile.SOD)
        val dg2 = dump.file(LdsFile.DG2)
        val portrait = dg2?.let { Lds.dg2(it).firstOrNull() }
        return buildMap {
            put(NAMESPACE, person(mrz, portrait?.data, now))
            put(DATAGROUPS_NAMESPACE, buildMap {
                put("dg1", Bstr(dg1))
                dg2?.let { put("dg2", Bstr(it)) }
                sod?.let { put("sod", Bstr(it)) }
            })
        }
    }

    private fun person(mrz: Mrz, portrait: ByteArray?, now: Instant): Map<String, DataItem> = buildMap {
        val year = now.toLocalDateTime(TimeZone.UTC).year
        mrz.primaryIdentifier.takeIf { it.isNotBlank() }?.let { put("family_name", Tstr(it)) }
        mrz.secondaryIdentifier.takeIf { it.isNotBlank() }?.let { put("given_name", Tstr(it)) }
        val birth = date(TravelDocumentFields.date(mrz.birthDate, false, year))
        birth?.let { b ->
            put("birth_date", b.toDataItemFullDate())
            put("age_birth_year", Uint(b.year.toULong()))
            val today = now.toLocalDateTime(TimeZone.UTC).date
            val age = today.year - b.year - (if (today.month.ordinal < b.month.ordinal || (today.month == b.month && today.day < b.day)) 1 else 0)
            AGE_THRESHOLDS.forEach { put("age_over_${it.toString().padStart(2, '0')}", if (age >= it) Simple.TRUE else Simple.FALSE) }
        }
        portrait?.let { put("portrait", Bstr(it)) }
        expiry(mrz, year)?.let { put("expiry_date", it.toDataItemFullDate()) }
        MrtdCrypto.alpha2(mrz.issuingState)?.let { put("issuing_country", Tstr(it)) }
        MrtdCrypto.alpha2(mrz.nationality)?.let { put("nationality", Tstr(it)) }
        put("sex", Uint(sex(mrz.sex).toULong()))
        mrz.documentNumber.takeIf { it.isNotBlank() }?.let { put("document_number", Tstr(it)) }
    }

    /** ISO/IEC 5218: 1 male, 2 female, 0 not known (the zone's X and filler). */
    fun sex(zone: String): Int = when (zone.trim().uppercase()) {
        "M" -> 1
        "F" -> 2
        else -> 0
    }

    private fun date(iso: String): LocalDate? = runCatching { LocalDate.parse(iso) }.getOrNull()

    fun expiry(mrz: Mrz, currentYear: Int): LocalDate? = date(TravelDocumentFields.date(mrz.expiryDate, true, currentYear))

    /** When an issuance made [now] ends: [VALIDITY] later, or at the end of the passport's last valid day if sooner. */
    fun validUntil(dump: MrtdDump, now: Instant): Instant {
        val year = now.toLocalDateTime(TimeZone.UTC).year
        val expiry = dump.file(LdsFile.DG1)?.let { Lds.dg1(it) }?.let { expiry(it, year) }
            ?.let { Instant.parse("${it}T23:59:59Z") }
        return listOfNotNull(now + VALIDITY, expiry).min()
    }

    /** A self-signed document signer certificate for [issuer], valid over the credential's validity. */
    suspend fun certificate(issuer: HolderKey, validFrom: Instant, validUntil: Instant): X509Cert {
        val name = X500Name.fromName("C=TW,O=DIW MY WALLET,CN=DIW MY WALLET Photo ID (self-issued)")
        return X509Cert.Builder(
            publicKey = issuer.publicKey,
            signingKey = issuer.signingKey(),
            serialNumber = ASN1Integer.fromRandom(128),
            subject = name,
            issuer = name,
            validFrom = validFrom,
            validUntil = validUntil,
        )
            .includeSubjectKeyIdentifier(true)
            .includeAuthorityKeyIdentifierAsSubjectKeyIdentifier(true)
            .setKeyUsage(setOf(X509KeyUsage.DIGITAL_SIGNATURE))
            .addExtension(OID_EXTENDED_KEY_USAGE, true, MDL_DS_EKU)
            .build()
    }

    fun namespaces(elements: Map<String, Map<String, DataItem>>): IssuerNamespaces = buildIssuerNamespaces {
        elements.forEach { (ns, values) -> addNamespace(ns) { values.forEach { (name, value) -> addDataElement(name, value) } } }
    }

    /**
     * The IssuerSigned structure (ISO/IEC 18013-5 8.3.2.1.2.2) of [elements] bound to [deviceKey], as the bytes an
     * mdoc credential is certified with.
     */
    suspend fun issuerSigned(
        issuer: HolderKey,
        elements: Map<String, Map<String, DataItem>>,
        deviceKey: EcPublicKey,
        now: Instant,
        validUntil: Instant,
    ): ByteString {
        val signedAt = Instant.fromEpochSeconds(now.epochSeconds)
        val ns = namespaces(elements)
        val mso = MobileSecurityObject(
            version = "1.0",
            docType = DOCTYPE,
            signedAt = signedAt,
            validFrom = signedAt,
            validUntil = Instant.fromEpochSeconds(validUntil.epochSeconds),
            expectedUpdate = null,
            digestAlgorithm = Algorithm.SHA256,
            valueDigests = ns.getValueDigests(Algorithm.SHA256),
            deviceKey = deviceKey,
        )
        val cert = certificate(issuer, signedAt, validUntil)
        val tagged = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(mso.toDataItem()))))
        val prot = mapOf<CoseLabel, DataItem>(CoseNumberLabel(Cose.COSE_LABEL_ALG) to Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem())
        val unprot = mapOf<CoseLabel, DataItem>(CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN) to X509CertChain(listOf(cert)).toDataItem())
        val issuerAuth = Cbor.encode(Cose.coseSign1Sign(issuer.signingKey("ES256"), tagged, true, prot, unprot).toDataItem())
        return ByteString(Cbor.encode(buildCborMap {
            put("nameSpaces", ns.toDataItem())
            put("issuerAuth", RawCbor(issuerAuth))
        }))
    }

    const val EVIDENCE = "TravelDocumentPhotoIdPassiveAuthentication"

    /**
     * Verifier side: with DG1 and the security object disclosed, passive authentication is repeated (DG2 too when
     * disclosed) and every disclosed person field must equal what the chip files say. The holder binding is still the
     * issuing wallet's statement: passive authentication shows the data is the issuing state's, not that the chip
     * was read by this holder.
     */
    suspend fun verify(disclosed: Map<String, Map<String, DataItem>>, trust: DocumentTrustSource?, now: Instant = Clock.System.now()): List<EvidenceResult> {
        val title = "電子護照被動驗證（Photo ID）"
        val groups = disclosed[DATAGROUPS_NAMESPACE].orEmpty()
        fun bytes(name: String): ByteArray? = runCatching { groups[name]?.asBstr }.getOrNull()
        val dg1 = bytes("dg1")
        val sod = bytes("sod")
        val dg2 = bytes("dg2")
        if (dg1 == null || sod == null) {
            return listOf(EvidenceResult(EVIDENCE, title, Check.NOT_CHECKED, "未附 DG1 與 SOD，資料只有出示者錢包的簽章，查驗方無法向發證國核對"))
        }
        if (trust == null) return listOf(EvidenceResult(EVIDENCE, title, Check.NOT_CHECKED, "此處無法重做被動驗證"))
        val result = TravelDocumentFields.passiveAuthentication(title, dg1, sod, dg2, trust, now).copy(type = EVIDENCE)
        if (result.check == Check.FAIL) return listOf(result)
        val mrz = Lds.dg1(dg1) ?: return listOf(EvidenceResult(EVIDENCE, title, Check.FAIL, "DG1 無法解讀"))
        val expected = person(mrz, dg2?.let { Lds.dg2(it).firstOrNull()?.data }, now)
        val shown = disclosed[NAMESPACE].orEmpty()
        val differing = shown.filter { (name, value) ->
            when {
                name.startsWith("age_over_") -> value == Simple.TRUE && expected[name] != Simple.TRUE
                name == "age_birth_year" || name in expected -> expected[name] != value
                else -> false
            }
        }.keys.map { labels[it] ?: it }
        val unchecked = shown.keys.filter { it !in expected && !it.startsWith("age_over_") && it != "age_birth_year" }.map { labels[it] ?: it }
        val fields = when {
            differing.isNotEmpty() -> EvidenceResult(EVIDENCE, "Photo ID 欄位", Check.FAIL, "出示的欄位與晶片檔案不符：" + differing.joinToString("、"))
            unchecked.isNotEmpty() -> EvidenceResult(EVIDENCE, "Photo ID 欄位", Check.WARN, "出示的欄位與晶片檔案相符，但下列欄位晶片檔案沒有，無法核對：" + unchecked.joinToString("、"))
            else -> EvidenceResult(EVIDENCE, "Photo ID 欄位", Check.PASS, "出示的欄位與晶片檔案相符")
        }
        val binding = EvidenceResult(EVIDENCE, "Photo ID 持有者綁定", Check.NOT_CHECKED,
            "被動驗證證明資料出自發證國，但裝置金鑰由出示者的錢包綁定（自簽），不證明晶片由這位持有者讀取")
        return listOf(result, fields, binding)
    }

    /** Names of the data elements, for the cards that list the credential's claims. */
    val labels: Map<String, String> = mapOf(
        "family_name" to "姓", "given_name" to "名", "birth_date" to "出生日期", "age_birth_year" to "出生年",
        "portrait" to "相片", "expiry_date" to "效期截止日", "issuing_country" to "發證國", "nationality" to "國籍",
        "sex" to "性別", "document_number" to "證件號碼", "dg1" to "DG1 原文", "dg2" to "DG2 原文（相片）", "sod" to "安全物件 SOD 原文",
    ) + AGE_THRESHOLDS.associate { "age_over_${it.toString().padStart(2, '0')}" to "已滿 $it 歲" }
}

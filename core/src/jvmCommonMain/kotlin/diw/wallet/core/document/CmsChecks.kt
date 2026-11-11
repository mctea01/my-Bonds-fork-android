package diw.wallet.core.document

import diw.wallet.core.i18n.ct
import diw.wallet.core.trust.TrustRole
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.cms.Attribute
import org.bouncycastle.asn1.cms.CMSAttributes
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.Time
import org.bouncycastle.asn1.ess.SigningCertificate
import org.bouncycastle.asn1.ess.SigningCertificateV2
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.tsp.TimeStampResponse
import org.bouncycastle.tsp.TimeStampToken
import kotlin.time.Instant

/**
 * CMS signature and RFC 3161 time-stamp verification with BouncyCastle: signature and digest, the signing
 * certificate attributes (ESS v1 and v2), the signature time stamp (CAdES-T), embedded revocation data
 * (SignedData crls and OCSP, Adobe revocationInfoArchival, the PDF DSS), the chain to an enabled anchor, and the
 * certificate's validity at the trusted time.
 */
internal class CmsChecks(private val pki: PkiSupport) {

    /** Result of checking one SignerInfo before trust: what the format-specific caller adds to. */
    class SignerResult(
        val info: SignatureInfo,
        val signerHolder: X509CertificateHolder?,
    )

    /**
     * Verifies every signer of [cms]. [content] is the detached content (null when encapsulated or not available).
     * [extraCerts], [extraOcsps] and [extraCrls] come from the document (PDF DSS).
     */
    suspend fun verify(
        cms: ByteArray,
        content: ByteArray?,
        format: SignatureFormat,
        label: String,
        now: Instant,
        extraCerts: List<ByteArray> = emptyList(),
        extraOcsps: List<ByteArray> = emptyList(),
        extraCrls: List<ByteArray> = emptyList(),
        claimedTimeOverride: Long? = null,
        fallbackClaimed: Long? = null,
        /** SHA-256 of detached content that is not available itself (a zkPDF masked file, whose digest is proven). */
        contentSha256: ByteArray? = null,
        /** The role whose anchors the signer must chain to. */
        role: TrustRole = TrustRole.DOCUMENT,
    ): List<SignatureInfo> {
        val sd = try {
            if (contentSha256 != null) {
                CMSSignedData(mapOf(SHA256.algorithm.id to contentSha256), ContentInfo.getInstance(Bc.parse(cms)).encoded)
            } else signedData(cms, content)
        } catch (e: Exception) {
            return listOf(failed(format, label, ct("core_cms_unparsable") + (e.message ?: e.javaClass.simpleName)))
        }
        val certs = sd.certificates.getMatches(null).filterIsInstance<X509CertificateHolder>() +
            extraCerts.flatMap { Bc.certificates(it) }.mapNotNull { Bc.holder(it) }
        val (cmsOcsps, cmsCrls) = pki.cmsRevocation(sd)
        val signers = sd.signerInfos.signers.toList()
        if (signers.isEmpty()) return listOf(failed(format, label, ct("core_cms_no_signers")))
        val detachedMissing = content == null && contentSha256 == null && sd.signedContent == null
        return signers.mapIndexed { i, si ->
            check(si, certs, format, if (signers.size > 1) ct("core_cms_signer_n", label, i + 1) else label, now, detachedMissing,
                cmsOcsps + extraOcsps, cmsCrls + extraCrls, claimedTimeOverride, fallbackClaimed, sd, content, role)
        }
    }

    private suspend fun check(
        si: SignerInformation,
        certs: List<X509CertificateHolder>,
        format: SignatureFormat,
        label: String,
        now: Instant,
        detachedMissing: Boolean,
        ocsps: List<ByteArray>,
        crls: List<ByteArray>,
        claimedTimeOverride: Long?,
        fallbackClaimed: Long?,
        sd: CMSSignedData,
        content: ByteArray?,
        role: TrustRole,
    ): SignatureInfo {
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val signer = certs.firstOrNull { si.sid.match(it) }
        val algorithm = AlgorithmNames.signature(si.encryptionAlgOID, si.digestAlgOID)
        if (AlgorithmNames.weak(si.digestAlgOID)) notes.add(ct("core_cms_weak_digest", AlgorithmNames.digest(si.digestAlgOID)))
        val integrity = when {
            signer == null -> { problems.add(ct("core_cms_no_signer_cert")); Check.NOT_CHECKED }
            detachedMissing -> { notes.add(ct("core_sig_detached_needs_content")); Check.NOT_CHECKED }
            else -> try {
                // Verified with the bare key: BouncyCastle would also reject a certificate not valid at the claimed
                // signingTime, which signers set wrongly (an e-sign service writes 2010); validity is checked below.
                val key = JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(signer).publicKey
                if (si.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(Bc.provider).build(key))) Check.PASS
                else { problems.add(ct("core_sig_value_mismatch")); Check.FAIL }
            } catch (e: org.bouncycastle.cms.CMSSignerDigestMismatchException) {
                problems.add(ct("core_cms_digest_mismatch")); Check.FAIL
            } catch (e: Exception) {
                problems.add(ct("core_cms_verify_failed") + (e.message ?: e.javaClass.simpleName)); Check.FAIL
            }
        }
        val attrs = si.signedAttributes
        val claimed = claimedTimeOverride ?: attrs?.get(CMSAttributes.signingTime)?.let { a ->
            runCatching { Time.getInstance(a.attrValues.getObjectAt(0)).date.time / 1000 }.getOrNull()
        } ?: fallbackClaimed
        // ESS signing certificate attributes bind the signer certificate into the signature (CAdES, PAdES).
        var essBound = false
        if (signer != null && attrs != null) {
            attrs.get(PKCSObjectIdentifiers.id_aa_signingCertificateV2)?.let { a ->
                runCatching {
                    val v2 = SigningCertificateV2.getInstance(a.attrValues.getObjectAt(0))
                    val id = v2.certs.first()
                    val alg = id.hashAlgorithm?.algorithm?.id ?: "2.16.840.1.101.3.4.2.1"
                    val expected = DocCrypto.digest(AlgorithmNames.jcaDigest(alg), signer.encoded)
                    if (expected.contentEquals(id.certHash)) essBound = true else problems.add(ct("core_cms_signing_cert_mismatch"))
                }
            }
            attrs.get(PKCSObjectIdentifiers.id_aa_signingCertificate)?.let { a ->
                runCatching {
                    val v1 = SigningCertificate.getInstance(a.attrValues.getObjectAt(0))
                    if (DocCrypto.digest("SHA-1", signer.encoded).contentEquals(v1.certs.first().certHash)) essBound = true
                    else problems.add(ct("core_cms_signing_cert_mismatch"))
                }
            }
        }
        if (!essBound && format == SignatureFormat.PADES) problems.add(ct("core_cms_pades_no_signing_cert"))
        // Signature time stamp (CAdES-T): an RFC 3161 token over the signature value.
        val tst = si.unsignedAttributes?.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)?.let { a ->
            runCatching { a.attrValues.getObjectAt(0).toASN1Primitive().encoded }.getOrNull()
        }
        val timestamp = tst?.let { timestamp(it, si.signature) }
        // Adobe revocationInfoArchival in the signed attributes.
        val adobe = attrs?.get(PkiSupport.ADOBE_REVOCATION)?.let { pki.adobeRevocation(it.attrValues.getObjectAt(0)) }
        val allOcsps = ocsps + adobe?.first.orEmpty()
        val allCrls = crls + adobe?.second.orEmpty()
        // CAdES baseline level, and the archive time stamps of B-LTA rebuilt from their hash index.
        if (format == SignatureFormat.CADES || format == SignatureFormat.ASIC_CADES) {
            val signed = content ?: (sd.signedContent?.content as? ByteArray)
            val asn = org.bouncycastle.asn1.cms.SignedData.getInstance(sd.toASN1Structure().content)
            val archives = runCatching { CadesArchive.find(asn, si.toASN1Structure(), signed) }.getOrDefault(emptyList())
            notes.add(ct("core_cms_cades_level") + XmlDsig.baselineLevel(timestamp != null, allOcsps.isNotEmpty() || allCrls.isNotEmpty(), archives.isNotEmpty()))
            for (a in archives) {
                a.problem?.let { if (a.input == null) notes.add(it) else problems.add(it) }
                val ts = a.input?.let { timestamp(a.token, it) } ?: continue
                notes.add(XmlDsig.archiveNote(ts))
                if (ts.imprint == Check.FAIL || ts.signature == Check.FAIL) problems.add(ct("core_cms_archive_invalid") + ts.problems.joinToString(ct("core_sep_semicolon")))
            }
        }
        return evaluate(
            format = format,
            label = label,
            algorithm = algorithm,
            signer = signer,
            pool = certs,
            integrity = integrity,
            claimed = claimed,
            timestamp = timestamp,
            ocsps = allOcsps,
            crls = allCrls,
            now = now,
            problems = problems,
            notes = notes,
            role = role,
        )
    }

    /** Trust, validity and revocation of a signer whose signature has been checked. */
    suspend fun evaluate(
        format: SignatureFormat,
        label: String,
        algorithm: String?,
        signer: X509CertificateHolder?,
        pool: List<X509CertificateHolder>,
        integrity: Check,
        claimed: Long?,
        timestamp: TimestampInfo?,
        ocsps: List<ByteArray>,
        crls: List<ByteArray>,
        now: Instant,
        problems: MutableList<String>,
        notes: MutableList<String>,
        coversWhole: Boolean? = null,
        role: TrustRole = TrustRole.DOCUMENT,
    ): SignatureInfo {
        if (signer == null) {
            return SignatureInfo(format, label, algorithm, null, emptyList(), integrity, coversWhole, claimedTime = claimed,
                timestamp = timestamp, trust = null, certificateValidity = Check.NOT_CHECKED, problems = problems, notes = notes)
        }
        val chain = pki.buildChain(signer, pool)
        val trustedTime = timestamp?.takeIf { it.trusted }?.time?.let { Instant.fromEpochSeconds(it) }
        val validNow = PkiSupport.validAt(signer, now)
        val validity = when {
            trustedTime != null -> if (PkiSupport.validAt(signer, trustedTime)) Check.PASS else {
                problems.add(ct("core_cms_tst_outside_validity")); Check.FAIL
            }
            validNow -> Check.PASS
            claimed != null && PkiSupport.validAt(signer, Instant.fromEpochSeconds(claimed)) -> {
                notes.add(ct("core_cms_cert_expired_claimed")); Check.WARN
            }
            else -> { problems.add(ct("core_cms_cert_not_valid")); Check.FAIL }
        }
        val at = trustedTime ?: if (validNow) now else claimed?.let { Instant.fromEpochSeconds(it) } ?: now
        val decision = pki.decide(role, chain, at)
        if (PkiSupport.unknownAnchor(decision)) {
            val root = chain.last()
            notes.add(if (pki.selfSigned(root)) ct("core_cms_root_untrusted", pki.cn(root.subject) ?: root.subject)
            else ct("core_cms_chain_incomplete", pki.cn(root.issuer) ?: root.issuer))
        }
        // Embedded revocation data first; travel documents carry none, so their signer's CRL is fetched when online.
        // A revocation before the trusted time (or now) invalidates the signature.
        val embedded = pki.revocation(signer, chain.getOrNull(1), ocsps, crls)
        val online = if (embedded == null && role == TrustRole.TRAVEL_DOCUMENT) pki.onlineCrl(signer, chain.getOrNull(1), role, now) else null
        val revocation = embedded ?: online?.revocation
        online?.notes?.let { notes.addAll(it) }
        var finalValidity = validity
        if (revocation != null) {
            if (revocation.revoked) {
                val when_ = revocation.at
                val reference = (trustedTime ?: now).epochSeconds
                if (when_ == null || when_ <= reference) {
                    problems.add(ct("core_cms_cert_revoked", revocation.source, revocation.reason?.let { ct("core_comma_value", it) } ?: ""))
                    finalValidity = Check.FAIL
                } else {
                    notes.add(ct("core_cms_revoked_after_tst", revocation.source))
                }
            } else {
                notes.add(if (revocation === online?.revocation) ct("core_crl_online_good", PkiSupport.day(revocation.producedAt))
                else ct("core_cms_revocation_good", revocation.source))
            }
        } else if (online == null) {
            notes.add(ct("core_cms_no_revocation"))
        }
        if (pki.keyDescription(signer).startsWith("RSA ") && pki.rsaBits(signer) in 1..2047) notes.add(ct("core_cms_short_key"))
        return SignatureInfo(
            format = format,
            label = label,
            algorithm = algorithm,
            signer = pki.certInfo(signer),
            chain = chain.map { pki.certInfo(it) },
            integrity = integrity,
            coversWholeDocument = coversWhole,
            claimedTime = claimed,
            timestamp = timestamp,
            trust = TrustSummary.of(decision),
            certificateValidity = finalValidity,
            revocationData = revocation != null,
            signerName = pki.cn(signer.subject),
            problems = problems,
            notes = notes,
        )
    }

    /** Verifies an RFC 3161 token whose message imprint should be the hash of [covered]. */
    /** [coveredSha256], when given, stands for the covered data (which is then not hashed). */
    suspend fun timestamp(token: ByteArray, covered: ByteArray, coveredSha256: ByteArray? = null): TimestampInfo {
        val problems = ArrayList<String>()
        val tst = try {
            TimeStampToken(ContentInfo.getInstance(Bc.parse(token)))
        } catch (e: Exception) {
            return TimestampInfo(0, null, Check.FAIL, Check.FAIL, null, problems = listOf(ct("core_cms_tst_unparsable") + (e.message ?: "")))
        }
        val info = tst.timeStampInfo
        val algOid = info.messageImprintAlgOID.id
        val imprint = if (coveredSha256 != null) coveredSha256.takeIf { algOid == SHA256.algorithm.id }
        else runCatching { DocCrypto.digest(AlgorithmNames.jcaDigest(algOid), covered) }.getOrNull()
        val imprintOk = if (imprint != null && imprint.contentEquals(info.messageImprintDigest)) Check.PASS else {
            problems.add(ct("core_tst_data_mismatch")); Check.FAIL
        }
        val certs = tst.certificates.getMatches(null).filterIsInstance<X509CertificateHolder>()
        val tsa = certs.firstOrNull { tst.sid.match(it) }
        val signatureOk = when {
            tsa == null -> { problems.add(ct("core_cms_tst_no_cert")); Check.NOT_CHECKED }
            else -> try {
                tst.validate(JcaSimpleSignerInfoVerifierBuilder().setProvider(Bc.provider).build(tsa)); Check.PASS
            } catch (e: Exception) {
                problems.add(ct("core_cms_tst_invalid") + (e.message ?: "")); Check.FAIL
            }
        }
        val genTime = Instant.fromEpochMilliseconds(info.genTime.time)
        val chain = tsa?.let { pki.buildChain(it, certs) }.orEmpty()
        val decision = if (tsa != null && signatureOk == Check.PASS) pki.decide(TrustRole.TSA, chain, genTime) else null
        val name = tsa?.let { pki.cn(it.subject) } ?: info.tsa?.name?.toString()
        if (decision != null && PkiSupport.unknownAnchor(decision)) problems.add(ct("core_cms_tsa_untrusted", name ?: ct("core_unknown")))
        return TimestampInfo(
            time = genTime.epochSeconds,
            tsa = name,
            imprint = imprintOk,
            signature = signatureOk,
            trust = decision?.let { TrustSummary.of(it) },
            chain = chain.map { pki.certInfo(it) },
            hashAlgorithm = AlgorithmNames.digest(algOid),
            problems = problems,
        )
    }

    fun failed(format: SignatureFormat, label: String, problem: String) = SignatureInfo(
        format, label, null, null, emptyList(), Check.FAIL, null, trust = null, certificateValidity = Check.NOT_CHECKED, problems = listOf(problem),
    )

    companion object {
        /**
         * The SignedData of [cms], read leniently: only its first object counts, so the padding of a PDF /Contents
         * and stray end-of-contents markers after a BER encoding (some e-sign services write one) are ignored.
         */
        fun signedData(cms: ByteArray, content: ByteArray?): CMSSignedData {
            val ci = ContentInfo.getInstance(Bc.parse(cms))
            return if (content != null) CMSSignedData(CMSProcessableByteArray(content), ci) else CMSSignedData(ci)
        }

        /** The token inside a TimeStampResp, or the token itself. */
        fun tokenOf(bytes: ByteArray): ByteArray {
            runCatching {
                val resp = TimeStampResponse(bytes)
                resp.timeStampToken?.let { return it.encoded }
            }
            return bytes
        }

        fun octets(a: Attribute): ByteArray? = runCatching { ASN1OctetString.getInstance(a.attrValues.getObjectAt(0)).octets }.getOrNull()

        val SHA256: AlgorithmIdentifier = AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256)
    }
}

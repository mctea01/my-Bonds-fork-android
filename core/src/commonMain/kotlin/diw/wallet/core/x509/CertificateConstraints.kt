package diw.wallet.core.x509

import diw.wallet.core.i18n.ct
import diw.wallet.core.trust.Pkix
import diw.wallet.core.trust.TrustRole
import org.multipaz.crypto.X509Cert
import kotlin.time.Instant

/** How much a finding of [CertificateConstraints] weighs on the trust result. */
enum class ConstraintSeverity {
    /** A rule of the certificate profile is broken: the path is not valid for the use (T4). */
    FAIL,

    /** The certificate is valid but its algorithm or key is too weak to rely on at the time checked (at most T3). */
    WEAK,

    /** Shown with the certificate; does not change the result. */
    NOTE,
}

/** The rule a finding is about, as the specifications name it. */
enum class ConstraintRule {
    KEY_USAGE, EXTENDED_KEY_USAGE, BASIC_CONSTRAINTS, PATH_LENGTH, CA_KEY_USAGE, NAME_CONSTRAINTS, CERTIFICATE_POLICIES,
    POLICY_MAPPINGS, UNKNOWN_CRITICAL_EXTENSION, SIGNATURE_ALGORITHM, KEY_STRENGTH, ENCODING,
}

/** One finding about the certificate at [index] of the path (0 is the leaf). [message] is the user's language. */
data class ConstraintFinding(
    val severity: ConstraintSeverity,
    val rule: ConstraintRule,
    val index: Int,
    val subject: String,
    val message: String,
)

/** The findings for a path. */
data class ConstraintReport(val findings: List<ConstraintFinding>) {
    val failed: Boolean get() = findings.any { it.severity == ConstraintSeverity.FAIL }
    val weak: Boolean get() = findings.any { it.severity == ConstraintSeverity.WEAK }
    val failures: List<ConstraintFinding> get() = findings.filter { it.severity == ConstraintSeverity.FAIL }
    fun at(index: Int): List<ConstraintFinding> = findings.filter { it.index == index }

    /** "subject: message" lines of the findings at or above [min], for trust reasons and signature problems. */
    fun lines(min: ConstraintSeverity = ConstraintSeverity.NOTE): List<String> =
        findings.filter { it.severity.ordinal <= min.ordinal }.map { "${it.subject}: ${it.message}" }

    companion object {
        val EMPTY = ConstraintReport(emptyList())
    }
}

/**
 * What the leaf certificate's key is used for, which decides the keyUsage and extKeyUsage it must allow. The roles
 * of [TrustRole] map to these through [of]; an OCSP responder and the signing certificate of a citizen digital
 * certificate card are checked directly.
 */
enum class CertificatePurpose {
    /** Credential issuers other than mdoc (SD-JWT VC, W3C VC, signed metadata). */
    ISSUER,

    /** An mdoc document signer (ISO/IEC 18013-5 Annex B, Table B.3). */
    MDOC_ISSUER,
    VERIFIER,
    WALLET_PROVIDER,
    TRUST_LIST_PROVIDER,
    STATUS_LIST,

    /** A time-stamp authority (RFC 3161 2.3). */
    TSA,

    /** A document or electronic seal signer (PDF, CMS, XML, OFD, the official document approvals). */
    DOCUMENT,

    /** A C2PA claim signer (C2PA 2.x, 14.5.1 certificate profile). */
    CONTENT,

    /** An ICAO 9303 document signer. */
    TRAVEL_DOCUMENT,

    /** A delegated OCSP responder (RFC 6960 4.2.2.2). */
    OCSP_RESPONDER;

    companion object {
        /** The purpose a chain is evaluated for in [role]; an issuer with an mdoc [docType] is an mdoc document signer. */
        fun of(role: TrustRole, docType: String? = null): CertificatePurpose = when (role) {
            TrustRole.ISSUER -> if (docType != null) MDOC_ISSUER else ISSUER
            TrustRole.VERIFIER -> VERIFIER
            TrustRole.WALLET_PROVIDER -> WALLET_PROVIDER
            TrustRole.TRUST_LIST_PROVIDER -> TRUST_LIST_PROVIDER
            TrustRole.STATUS_LIST -> STATUS_LIST
            TrustRole.TSA -> TSA
            TrustRole.DOCUMENT -> DOCUMENT
            TrustRole.CONTENT -> CONTENT
            TrustRole.TRAVEL_DOCUMENT -> TRAVEL_DOCUMENT
        }
    }
}

/**
 * The certificate profile and path rules the platform validators leave out or apply only to some chains, checked the
 * same way for every chain the wallet evaluates (Multipaz, PKIX, trust lists, the built-in CSCAs):
 *
 * - the leaf's keyUsage and extKeyUsage for the [CertificatePurpose] (RFC 5280 4.2.1.3 and 4.2.1.12, RFC 3161 2.3,
 *   RFC 6960 4.2.2.2, ISO/IEC 18013-5 Annex B, C2PA 14.5.1);
 * - basicConstraints, pathLenConstraint and keyCertSign of every issuing certificate (RFC 5280 6.1.4 (k) to (n));
 * - nameConstraints (RFC 5280 6.1.3 (b), (c) and 6.1.4 (g)), including those of the trust anchor (RFC 5937);
 * - certificatePolicies, policyMappings, policyConstraints and inhibitAnyPolicy with the valid policy tree of
 *   RFC 5280 6.1, starting from any-policy with no explicit policy required;
 * - critical extensions the wallet does not process (RFC 5280 4.2: the certificate must be rejected);
 * - the signature algorithm and key size of every certificate the path relies on: MD2, MD5, RSA and DSA below 1024
 *   bits and curves below 224 bits fail; SHA-1 after 2017 and RSA or DSA below 2048 bits after 2013 (NIST SP 800-131A,
 *   ETSI TS 119 312) are weak at the time checked.
 *
 * The path is leaf first; with [anchored] its last certificate is the trust anchor, whose own signature and
 * extensions other than the constraints it places on the path are not judged.
 */
object CertificateConstraints {
    private val SHA1_SUNSET = Instant.parse("2017-01-01T00:00:00Z")
    private val SHORT_KEY_SUNSET = Instant.parse("2014-01-01T00:00:00Z")

    /** Extensions the wallet processes or that carry no constraint to process; any other critical extension fails. */
    private val PROCESSED = setOf(
        X509Names.SUBJECT_KEY_IDENTIFIER, X509Names.AUTHORITY_KEY_IDENTIFIER, X509Names.KEY_USAGE, X509Names.EXTENDED_KEY_USAGE,
        X509Names.BASIC_CONSTRAINTS, X509Names.SUBJECT_ALT_NAME, X509Names.ISSUER_ALT_NAME, X509Names.NAME_CONSTRAINTS,
        X509Names.CERTIFICATE_POLICIES, X509Names.POLICY_MAPPINGS, X509Names.POLICY_CONSTRAINTS, X509Names.INHIBIT_ANY_POLICY,
        X509Names.CRL_DISTRIBUTION_POINTS, X509Names.FRESHEST_CRL, X509Names.AUTHORITY_INFO_ACCESS, X509Names.SUBJECT_INFO_ACCESS,
        X509Names.PRIVATE_KEY_USAGE_PERIOD, X509Names.QC_STATEMENTS, X509Names.OCSP_NO_CHECK, X509Names.ICAO_DOCUMENT_TYPE_LIST,
        X509Names.ICAO_NAME_CHANGE, X509Names.SCT_LIST, X509Names.TLS_FEATURE,
    )

    /** Purposes that dedicate a key to one service: a certificate naming only these may sign nothing else. */
    private val DEDICATED = setOf(X509Names.KP_TIME_STAMPING, X509Names.KP_OCSP_SIGNING)

    /** Purposes the specifications define, so that a certificate naming only these is known to be for other uses. */
    private val KNOWN_PURPOSES = setOf(
        X509Names.KP_SERVER_AUTH, X509Names.KP_CLIENT_AUTH, X509Names.KP_CODE_SIGNING, X509Names.KP_EMAIL_PROTECTION,
        X509Names.KP_TIME_STAMPING, X509Names.KP_OCSP_SIGNING, X509Names.KP_DOCUMENT_SIGNING, X509Names.KP_MDOC_DS,
        X509Names.KP_MDOC_READER, X509Names.KP_MDOC_IACA, X509Names.KP_MDOC_READER_CA, X509Names.KP_C2PA_CLAIM_SIGNING,
        X509Names.KP_ADOBE_AUTHENTIC_DOCUMENTS, X509Names.KP_MS_DOCUMENT_SIGNING, X509Names.KP_MS_SMARTCARD_LOGON,
        "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6", "1.3.6.1.5.5.7.3.7", "1.3.6.1.5.5.7.3.17", "1.3.6.1.5.5.7.3.21", "1.3.6.1.5.5.7.3.22",
    )

    /** Purposes accepted for document and seal signatures (RFC 9336, RFC 8550, Adobe and Microsoft document signing). */
    private val DOCUMENT_PURPOSES = setOf(
        X509Names.KP_DOCUMENT_SIGNING, X509Names.KP_EMAIL_PROTECTION, X509Names.KP_CLIENT_AUTH,
        X509Names.KP_ADOBE_AUTHENTIC_DOCUMENTS, X509Names.KP_MS_DOCUMENT_SIGNING, X509Names.KP_MS_SMARTCARD_LOGON,
    )

    /** C2PA 14.5.1: the claim signer's extKeyUsage must name one of these. */
    private val CONTENT_PURPOSES = setOf(X509Names.KP_EMAIL_PROTECTION, X509Names.KP_DOCUMENT_SIGNING, X509Names.KP_C2PA_CLAIM_SIGNING)

    /** Purposes the protocols of these roles expect; another known purpose is shown, since they define no EKU rule. */
    private val EXPECTED: Map<CertificatePurpose, Set<String>> = mapOf(
        CertificatePurpose.ISSUER to setOf(X509Names.KP_MDOC_DS, X509Names.KP_DOCUMENT_SIGNING, X509Names.KP_SERVER_AUTH, X509Names.KP_CLIENT_AUTH),
        CertificatePurpose.VERIFIER to setOf(X509Names.KP_MDOC_READER, X509Names.KP_SERVER_AUTH, X509Names.KP_CLIENT_AUTH),
    )

    /** Checks [path] (leaf first) for [purpose] at [at]; without a purpose only the path rules apply. */
    fun check(path: List<X509Cert>, purpose: CertificatePurpose?, at: Instant, anchored: Boolean): ConstraintReport {
        if (path.isEmpty()) return ConstraintReport.EMPTY
        val details = path.map { X509Details.orNull(it) }
        val out = mutableListOf<ConstraintFinding>()
        details.forEachIndexed { i, d ->
            if (d == null) out += ConstraintFinding(ConstraintSeverity.FAIL, ConstraintRule.ENCODING, i, path[i].let { runCatching { it.subject.name }.getOrDefault("?") }, ct("core_x509_c_unreadable"))
        }
        if (out.isNotEmpty()) return ConstraintReport(out)
        val certs = details.filterNotNull()
        val top = certs.size - 1
        // The top certificate is an anchor, or a root that signed itself (whose self-signature proves nothing). A
        // self-issued certificate signed by another key, such as a key rollover certificate, is checked like any other.
        val topIsTrusted = anchored || (certs[top].selfIssued && Pkix.signedBy(path[top], path[top]))
        fun add(sev: ConstraintSeverity, rule: ConstraintRule, i: Int, message: String) {
            out += ConstraintFinding(sev, rule, i, displayName(certs[i]), message)
        }

        certs.forEachIndexed { i, d ->
            val isAnchor = i == top && topIsTrusted
            d.problems.forEach { add(ConstraintSeverity.NOTE, ConstraintRule.ENCODING, i, it) }
            // RFC 5280 4.2: an unrecognised critical extension rejects the certificate.
            for (e in d.extensions) {
                if (!e.critical) continue
                if (e.oid !in PROCESSED) {
                    add(if (isAnchor) ConstraintSeverity.NOTE else ConstraintSeverity.FAIL, ConstraintRule.UNKNOWN_CRITICAL_EXTENSION, i,
                        ct("core_x509_c_unknown_critical", e.label))
                } else if (e.error != null) {
                    add(if (isAnchor) ConstraintSeverity.NOTE else ConstraintSeverity.FAIL, ConstraintRule.ENCODING, i,
                        ct("core_x509_c_critical_malformed", e.label))
                }
            }
            // The key of every certificate signs the one below it (or the data, for the leaf).
            keyStrength(d, at)?.let { (sev, msg) -> add(sev, ConstraintRule.KEY_STRENGTH, i, msg) }
            // The signature on a certificate is relied on unless it is the anchor's (or a root's) own.
            if (!isAnchor) signatureStrength(d, at)?.let { (sev, msg) -> add(sev, ConstraintRule.SIGNATURE_ALGORITHM, i, msg) }
        }

        // Issuing certificates: basicConstraints, pathLenConstraint and keyCertSign (RFC 5280 6.1.4 (k), (l), (m), (n)).
        for (i in 1..top) {
            val d = certs[i]
            val isAnchor = i == top && topIsTrusted
            val bc = d.basicConstraints
            if (bc == null || !bc.first) {
                when {
                    !isAnchor -> add(ConstraintSeverity.FAIL, ConstraintRule.BASIC_CONSTRAINTS, i,
                        if (d.extension(X509Names.BASIC_CONSTRAINTS)?.error != null) ct("core_x509_c_bc_malformed") else ct("core_x509_c_not_ca"))
                    d.version == 3 -> add(ConstraintSeverity.NOTE, ConstraintRule.BASIC_CONSTRAINTS, i, ct("core_x509_c_anchor_not_ca"))
                }
            }
            val ku = d.keyUsage
            if (d.extension(X509Names.KEY_USAGE) != null && (ku == null || KEY_CERT_SIGN !in ku)) {
                add(ConstraintSeverity.FAIL, ConstraintRule.CA_KEY_USAGE, i, ct("core_x509_c_no_cert_sign", usageText(ku)))
            }
            val pathLen = bc?.second
            if (pathLen != null) {
                // Non-self-issued intermediate certificates between this one and the leaf.
                val below = (1 until i).count { !certs[it].selfIssued }
                if (below > pathLen) add(ConstraintSeverity.FAIL, ConstraintRule.PATH_LENGTH, i, ct("core_x509_c_path_len", pathLen, below))
            }
        }

        nameConstraints(certs, top, ::add)
        policies(certs, if (topIsTrusted) top else top + 1, ::add)
        // A trust anchor judged by itself is trusted for the role directly: there is no end-entity key use to check.
        if (purpose != null && !(anchored && top == 0)) leafUsage(certs[0], purpose, ::add)
        return ConstraintReport(out)
    }

    /** [cert] may sign OCSP responses for its issuer (RFC 6960 4.2.2.2): extKeyUsage id-kp-OCSPSigning, keyUsage allowing signatures. */
    fun ocspResponderAllowed(cert: X509Cert): Boolean {
        val d = X509Details.orNull(cert) ?: return false
        val out = mutableListOf<ConstraintSeverity>()
        leafUsage(d, CertificatePurpose.OCSP_RESPONDER) { sev, _, _, _ -> out += sev }
        return ConstraintSeverity.FAIL !in out
    }

    /** The leaf rules alone for [cert] used for [purpose] (no issuers): what [check] reports at index 0. */
    fun leaf(cert: X509Cert, purpose: CertificatePurpose, at: Instant): ConstraintReport =
        ConstraintReport(check(listOf(cert), purpose, at, anchored = false).findings.filter { it.index == 0 && it.rule in LEAF_RULES })

    private val LEAF_RULES = setOf(ConstraintRule.KEY_USAGE, ConstraintRule.EXTENDED_KEY_USAGE, ConstraintRule.UNKNOWN_CRITICAL_EXTENSION, ConstraintRule.KEY_STRENGTH)

    private const val DIGITAL_SIGNATURE = 0
    private const val NON_REPUDIATION = 1
    private const val KEY_CERT_SIGN = 5

    private fun displayName(d: X509Details): String =
        d.subject.first("2.5.4.3") ?: d.subject.first("2.5.4.10") ?: d.subject.text.ifEmpty { d.serialHex }

    private fun usageText(ku: Set<Int>?): String = ku?.sorted()?.joinToString(", ") { X509Names.KEY_USAGE_BITS[it] }?.ifEmpty { "-" } ?: "-"

    private fun purposesText(eku: List<String>): String = eku.joinToString(", ") { X509Names.oid(it) ?: it }

    private fun leafUsage(d: X509Details, purpose: CertificatePurpose, add: (ConstraintSeverity, ConstraintRule, Int, String) -> Unit) {
        val fail = ConstraintSeverity.FAIL
        // keyUsage (RFC 5280 4.2.1.3): verifying signatures on anything but certificates and CRLs needs
        // digitalSignature or nonRepudiation; an mdoc document signer needs digitalSignature (ISO/IEC 18013-5 B.1.4).
        val kuExt = d.extension(X509Names.KEY_USAGE)
        if (kuExt != null) {
            val ku = d.keyUsage
            when {
                ku == null -> add(fail, ConstraintRule.KEY_USAGE, 0, ct("core_x509_c_ku_malformed"))
                purpose == CertificatePurpose.MDOC_ISSUER -> if (DIGITAL_SIGNATURE !in ku) add(fail, ConstraintRule.KEY_USAGE, 0, ct("core_x509_c_ku_mdoc", usageText(ku)))
                DIGITAL_SIGNATURE !in ku && NON_REPUDIATION !in ku -> add(fail, ConstraintRule.KEY_USAGE, 0, ct("core_x509_c_ku_sign", usageText(ku)))
            }
        }
        // extKeyUsage (RFC 5280 4.2.1.12): when present the key may be used only for the purposes listed.
        val ekuExt = d.extension(X509Names.EXTENDED_KEY_USAGE)
        val eku = d.extendedKeyUsage
        if (ekuExt != null && eku == null) {
            add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_eku_malformed"))
            return
        }
        val any = eku != null && X509Names.ANY_EKU in eku
        when (purpose) {
            CertificatePurpose.TSA -> {
                // RFC 3161 2.3: exactly one extKeyUsage, id-kp-timeStamping, marked critical.
                when {
                    eku == null -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_tsa_no_eku"))
                    eku != listOf(X509Names.KP_TIME_STAMPING) -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_tsa_eku", purposesText(eku)))
                    ekuExt?.critical != true -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_tsa_not_critical"))
                }
            }
            CertificatePurpose.OCSP_RESPONDER -> {
                if (eku == null || X509Names.KP_OCSP_SIGNING !in eku) add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_ocsp_eku", eku?.let { purposesText(it) } ?: "-"))
            }
            CertificatePurpose.CONTENT -> {
                // C2PA 14.5.1: extKeyUsage present, without anyExtendedKeyUsage, naming a claim signing purpose.
                when {
                    eku == null -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_c2pa_no_eku"))
                    any -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_c2pa_any"))
                    eku.none { it in CONTENT_PURPOSES } -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_c2pa_eku", purposesText(eku)))
                }
            }
            CertificatePurpose.MDOC_ISSUER -> {
                // ISO/IEC 18013-5 Table B.3: extKeyUsage 1.0.18013.5.1.2, critical.
                when {
                    eku == null -> add(ConstraintSeverity.NOTE, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_mdoc_no_eku"))
                    X509Names.KP_MDOC_DS !in eku && !any -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_mdoc_eku", purposesText(eku)))
                }
            }
            CertificatePurpose.DOCUMENT -> {
                if (eku != null && !any && eku.none { it in DOCUMENT_PURPOSES }) {
                    if (eku.all { it in KNOWN_PURPOSES }) add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_doc_eku", purposesText(eku)))
                    else add(ConstraintSeverity.NOTE, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_eku_unknown", purposesText(eku)))
                }
            }
            else -> {
                if (eku != null && !any) {
                    when {
                        // Keys dedicated to time stamping or OCSP responses sign nothing else.
                        eku.all { it in DEDICATED } -> add(fail, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_eku_dedicated", purposesText(eku)))
                        EXPECTED[purpose]?.let { exp -> eku.none { it in exp } } == true ->
                            add(ConstraintSeverity.NOTE, ConstraintRule.EXTENDED_KEY_USAGE, 0, ct("core_x509_c_eku_other", purposesText(eku)))
                    }
                }
            }
        }
    }

    private fun keyStrength(d: X509Details, at: Instant): Pair<ConstraintSeverity, String>? {
        val k = d.publicKey
        val bits = k.bits
        return when (k.type) {
            KeyType.RSA, KeyType.RSA_PSS, KeyType.DSA -> when {
                bits == null -> null
                bits < 1024 -> ConstraintSeverity.FAIL to ct("core_x509_c_key_broken", k.algorithm.name ?: k.algorithm.oid, bits)
                bits < 2048 -> (if (at >= SHORT_KEY_SUNSET) ConstraintSeverity.WEAK else ConstraintSeverity.NOTE) to ct("core_x509_c_key_short", k.algorithm.name ?: k.algorithm.oid, bits)
                else -> null
            }
            KeyType.EC -> when {
                bits == null -> ConstraintSeverity.NOTE to ct("core_x509_c_curve_unknown", k.curveName ?: "-")
                bits < 224 -> ConstraintSeverity.FAIL to ct("core_x509_c_key_broken", k.curveName ?: "EC", bits)
                else -> null
            }
            else -> null
        }
    }

    private fun signatureStrength(d: X509Details, at: Instant): Pair<ConstraintSeverity, String>? {
        val alg = d.signatureAlgorithm
        val name = alg.name ?: alg.oid
        return when (alg.oid) {
            "1.2.840.113549.1.1.2", "1.2.840.113549.1.1.4" -> ConstraintSeverity.FAIL to ct("core_x509_c_sig_broken", name)
            "1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.10040.4.3" ->
                (if (at >= SHA1_SUNSET) ConstraintSeverity.WEAK else ConstraintSeverity.NOTE) to ct("core_x509_c_sig_sha1", name)
            "1.2.840.113549.1.1.10" -> if (alg.parameters?.startsWith("hashAlgorithm SHA-1") == true)
                (if (at >= SHA1_SUNSET) ConstraintSeverity.WEAK else ConstraintSeverity.NOTE) to ct("core_x509_c_sig_sha1", "$name SHA-1") else null
            else -> null
        }
    }

    // Name constraints (RFC 5280 6.1.3 (b), (c), 6.1.4 (g); RFC 5937 for the anchor's own).

    private fun nameConstraints(certs: List<X509Details>, top: Int, add: (ConstraintSeverity, ConstraintRule, Int, String) -> Unit) {
        // Constraints from each CA, applied to every certificate below it.
        for (ca in 1..top) {
            val nc = certs[ca].nameConstraints
            if (certs[ca].extension(X509Names.NAME_CONSTRAINTS) != null && nc == null) {
                add(ConstraintSeverity.FAIL, ConstraintRule.NAME_CONSTRAINTS, ca, ct("core_x509_c_nc_malformed"))
                continue
            }
            val (permitted, excluded) = nc ?: continue
            if (certs[ca].nameConstraintDistances) {
                add(ConstraintSeverity.FAIL, ConstraintRule.NAME_CONSTRAINTS, ca, ct("core_x509_c_nc_distance", displayName(certs[ca])))
                continue
            }
            for (i in 0 until ca) {
                // A self-issued intermediate certificate is not checked against the constraints (6.1.3 (b)).
                if (i > 0 && certs[i].selfIssued) continue
                val names = namesOf(certs[i])
                for (n in names) {
                    val ofType = permitted.filter { it.type == n.type }
                    val unsupported = n.type !in SUPPORTED
                    if (unsupported && (ofType.isNotEmpty() || excluded.any { it.type == n.type })) {
                        add(ConstraintSeverity.FAIL, ConstraintRule.NAME_CONSTRAINTS, i, ct("core_x509_c_nc_unsupported", n.type.specName, displayName(certs[ca])))
                        continue
                    }
                    if (ofType.isNotEmpty() && ofType.none { matches(it, n) }) {
                        add(ConstraintSeverity.FAIL, ConstraintRule.NAME_CONSTRAINTS, i, ct("core_x509_c_nc_not_permitted", n.text, displayName(certs[ca])))
                    }
                    excluded.firstOrNull { it.type == n.type && matches(it, n) }?.let {
                        add(ConstraintSeverity.FAIL, ConstraintRule.NAME_CONSTRAINTS, i, ct("core_x509_c_nc_excluded", n.text, it.text, displayName(certs[ca])))
                    }
                }
            }
        }
    }

    private val SUPPORTED = setOf(GeneralName.Type.DNS, GeneralName.Type.RFC822, GeneralName.Type.URI, GeneralName.Type.IP, GeneralName.Type.DIRECTORY)

    /**
     * The names a certificate is checked on: its subject (when not empty) and subjectAltName; the subject's
     * emailAddress attributes only when there is no subjectAltName (RFC 5280 4.2.1.10).
     */
    private fun namesOf(d: X509Details): List<GeneralName> = buildList {
        if (!d.subject.empty) add(GeneralName(GeneralName.Type.DIRECTORY, d.subject.text, ByteArray(0), d.subject))
        if (d.extension(X509Names.SUBJECT_ALT_NAME) == null) {
            d.subject.attributes.filter { it.oid == X509Names.EMAIL_ADDRESS }.forEach { add(GeneralName(GeneralName.Type.RFC822, it.value, ByteArray(0))) }
        }
        addAll(d.subjectAltNames)
    }

    private fun matches(constraint: GeneralName, name: GeneralName): Boolean = when (constraint.type) {
        GeneralName.Type.DNS -> dnsWithin(name.value, constraint.value)
        GeneralName.Type.RFC822 -> emailWithin(name.value, constraint.value)
        GeneralName.Type.URI -> uriHost(name.value)?.let { hostWithin(it, constraint.value) } ?: false
        GeneralName.Type.IP -> ipWithin(name.raw, constraint.raw)
        GeneralName.Type.DIRECTORY -> dnWithin(name.directory, constraint.directory)
        else -> false
    }

    /** dNSName: the name is the constraint or a subdomain of it; a constraint starting with a dot only matches subdomains. */
    private fun dnsWithin(name: String, constraint: String): Boolean {
        val n = name.lowercase().trimEnd('.')
        val c = constraint.lowercase().trimEnd('.')
        if (c.isEmpty()) return true
        return if (c.startsWith(".")) n.endsWith(c) else n == c || n.endsWith(".$c")
    }

    /** rfc822Name: a mailbox, all mailboxes on a host, or (with a leading dot) on any host of a domain. */
    private fun emailWithin(name: String, constraint: String): Boolean {
        val n = name.lowercase()
        val c = constraint.lowercase()
        val host = n.substringAfterLast('@')
        return when {
            '@' in c -> n == c
            c.startsWith(".") -> host.endsWith(c)
            else -> host == c
        }
    }

    private fun hostWithin(host: String, constraint: String): Boolean {
        val h = host.lowercase()
        val c = constraint.lowercase()
        return if (c.startsWith(".")) h.endsWith(c) else h == c
    }

    private fun uriHost(uri: String): String? {
        val rest = uri.substringAfter("://", "").takeIf { it.isNotEmpty() } ?: return null
        val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@')
        val host = if (authority.startsWith("[")) authority.substringBefore(']').removePrefix("[") else authority.substringBefore(':')
        return host.ifEmpty { null }
    }

    private fun ipWithin(address: ByteArray, constraint: ByteArray): Boolean {
        if (constraint.size != address.size * 2) return false
        for (i in address.indices) {
            val mask = constraint[address.size + i].toInt()
            if ((address[i].toInt() and mask) != (constraint[i].toInt() and mask)) return false
        }
        return true
    }

    /** directoryName: the constraint's RDNs begin the name (RFC 5280 7.1 comparison). */
    private fun dnWithin(name: DistinguishedName?, constraint: DistinguishedName?): Boolean {
        if (name == null || constraint == null) return false
        if (constraint.rdns.size > name.rdns.size) return false
        return constraint.rdns.indices.all { X509Details.sameRdn(name.rdns[it], constraint.rdns[it], name.rdnEncodings[it], constraint.rdnEncodings[it]) }
    }

    // Certificate policies (RFC 5280 6.1.2 to 6.1.5) with user-initial-policy-set {anyPolicy} and no initial inhibitors.

    private class Node(val policy: String, var expected: Set<String>, val parent: Node?) {
        val children = mutableListOf<Node>()
    }

    /**
     * Runs the policy algorithm over the certificates below index [end] (the anchor is not processed), from the one
     * the anchor issued down to the leaf; reports when a certificate's policy constraints require an explicit policy
     * that the path does not carry, or a mapping names anyPolicy.
     */
    private fun policies(certs: List<X509Details>, end: Int, add: (ConstraintSeverity, ConstraintRule, Int, String) -> Unit) {
        val n = end
        if (n <= 0) return
        var explicit = n + 1
        var inhibitAny = n + 1
        var mapping = n + 1
        var root: Node? = Node(X509Names.ANY_POLICY, setOf(X509Names.ANY_POLICY), null)
        fun level(depth: Int): List<Node> {
            var nodes = listOfNotNull(root)
            repeat(depth) { nodes = nodes.flatMap { it.children } }
            return nodes
        }
        fun prune(depth: Int) {
            for (dd in depth - 1 downTo 0) {
                for (node in level(dd)) if (node.children.isEmpty()) {
                    if (node.parent == null) root = null else node.parent.children.remove(node)
                }
            }
        }
        // Processing order: i = 1 is the certificate the anchor issued, i = n is the leaf.
        for (i in 1..n) {
            val d = certs[n - i]
            val index = n - i
            val selfIssued = d.selfIssued
            if (d.extension(X509Names.CERTIFICATE_POLICIES) != null && d.policies == null) {
                add(ConstraintSeverity.FAIL, ConstraintRule.CERTIFICATE_POLICIES, index, ct("core_x509_c_cp_malformed"))
                return
            }
            val policies = d.policies
            if (policies != null && root != null) {
                val parents = level(i - 1)
                for (p in policies) {
                    if (p == X509Names.ANY_POLICY) continue
                    val matched = parents.filter { p in it.expected }
                    if (matched.isNotEmpty()) matched.forEach { it.children.add(Node(p, setOf(p), it)) }
                    else parents.firstOrNull { it.policy == X509Names.ANY_POLICY }?.let { it.children.add(Node(p, setOf(p), it)) }
                }
                if (X509Names.ANY_POLICY in policies && (inhibitAny > 0 || (i < n && selfIssued))) {
                    for (parent in parents) {
                        for (e in parent.expected) {
                            if (parent.children.any { it.policy == e }) continue
                            parent.children.add(Node(e, setOf(e), parent))
                        }
                    }
                }
                prune(i)
            } else if (policies == null) {
                root = null
            }
            if (explicit <= 0 && root == null) {
                add(ConstraintSeverity.FAIL, ConstraintRule.CERTIFICATE_POLICIES, index, ct("core_x509_c_policy_required"))
                return
            }
            if (i == n) {
                // Wrap-up (6.1.5 (a), (b), (g)).
                if (explicit > 0) explicit--
                if (d.policyConstraints?.first == 0L) explicit = 0
                if (explicit <= 0 && root == null) add(ConstraintSeverity.FAIL, ConstraintRule.CERTIFICATE_POLICIES, index, ct("core_x509_c_policy_required"))
                return
            }
            // Preparation for the next certificate (6.1.4 (a), (b), (h), (i), (j)).
            if (d.extension(X509Names.POLICY_MAPPINGS) != null && d.policyMappings == null) {
                add(ConstraintSeverity.FAIL, ConstraintRule.POLICY_MAPPINGS, index, ct("core_x509_c_pm_malformed"))
                return
            }
            val maps = d.policyMappings.orEmpty()
            if (maps.any { it.first == X509Names.ANY_POLICY || it.second == X509Names.ANY_POLICY }) {
                add(ConstraintSeverity.FAIL, ConstraintRule.POLICY_MAPPINGS, index, ct("core_x509_c_pm_any"))
                return
            }
            if (maps.isNotEmpty() && root != null) {
                val byIssuer = maps.groupBy({ it.first }, { it.second })
                val nodes = level(i)
                for ((id, subjects) in byIssuer) {
                    val withId = nodes.filter { it.policy == id }
                    if (mapping > 0) {
                        if (withId.isNotEmpty()) withId.forEach { it.expected = subjects.toSet() }
                        else nodes.firstOrNull { it.policy == X509Names.ANY_POLICY }?.parent?.let { p -> p.children.add(Node(id, subjects.toSet(), p)) }
                    } else {
                        withId.forEach { it.parent?.children?.remove(it) }
                        prune(i)
                    }
                }
            }
            if (!selfIssued) {
                if (explicit > 0) explicit--
                if (mapping > 0) mapping--
                if (inhibitAny > 0) inhibitAny--
            }
            d.policyConstraints?.let { (require, inhibit) ->
                if (require != null && require < explicit) explicit = require.toInt()
                if (inhibit != null && inhibit < mapping) mapping = inhibit.toInt()
            }
            d.inhibitAnyPolicy?.let { if (it < inhibitAny) inhibitAny = it.toInt() }
        }
    }
}

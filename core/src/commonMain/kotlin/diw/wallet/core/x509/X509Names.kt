package diw.wallet.core.x509

/**
 * The names the specifications give to the object identifiers a certificate carries (RFC 5280, RFC 3279, RFC 4055,
 * RFC 5480, RFC 8410, RFC 3739, ETSI EN 319 412, ISO/IEC 18013-5, ICAO 9303, C2PA, GM/T 0006), shown next to the OID.
 */
object X509Names {
    // Extensions (RFC 5280 4.2 and others).
    const val SUBJECT_DIRECTORY_ATTRIBUTES = "2.5.29.9"
    const val SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
    const val KEY_USAGE = "2.5.29.15"
    const val PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16"
    const val SUBJECT_ALT_NAME = "2.5.29.17"
    const val ISSUER_ALT_NAME = "2.5.29.18"
    const val BASIC_CONSTRAINTS = "2.5.29.19"
    const val NAME_CONSTRAINTS = "2.5.29.30"
    const val CRL_DISTRIBUTION_POINTS = "2.5.29.31"
    const val CERTIFICATE_POLICIES = "2.5.29.32"
    const val POLICY_MAPPINGS = "2.5.29.33"
    const val AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
    const val POLICY_CONSTRAINTS = "2.5.29.36"
    const val EXTENDED_KEY_USAGE = "2.5.29.37"
    const val FRESHEST_CRL = "2.5.29.46"
    const val INHIBIT_ANY_POLICY = "2.5.29.54"
    const val AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
    const val QC_STATEMENTS = "1.3.6.1.5.5.7.1.3"
    const val SUBJECT_INFO_ACCESS = "1.3.6.1.5.5.7.1.11"
    const val LOGOTYPE = "1.3.6.1.5.5.7.1.12"
    const val TLS_FEATURE = "1.3.6.1.5.5.7.1.24"
    const val OCSP_NO_CHECK = "1.3.6.1.5.5.7.48.1.5"
    const val SCT_LIST = "1.3.6.1.4.1.11129.2.4.2"
    const val CT_PRECERT_POISON = "1.3.6.1.4.1.11129.2.4.3"
    const val MS_CA_VERSION = "1.3.6.1.4.1.311.21.1"
    const val MS_PREVIOUS_CA_HASH = "1.3.6.1.4.1.311.21.2"
    const val MS_TEMPLATE_V2 = "1.3.6.1.4.1.311.21.7"
    const val MS_APPLICATION_POLICIES = "1.3.6.1.4.1.311.21.10"
    const val MS_TEMPLATE_NAME = "1.3.6.1.4.1.311.20.2"
    const val NETSCAPE_CERT_TYPE = "2.16.840.1.113730.1.1"
    const val NETSCAPE_COMMENT = "2.16.840.1.113730.1.13"
    const val ICAO_NAME_CHANGE = "2.23.136.1.1.6.1"
    const val ICAO_DOCUMENT_TYPE_LIST = "2.23.136.1.1.6.2"
    const val ENTRUST_VERSION = "1.2.840.113533.7.65.0"

    const val ANY_POLICY = "2.5.29.32.0"
    const val ANY_EKU = "2.5.29.37.0"

    // Extended key usages.
    const val KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    const val KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    const val KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
    const val KP_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
    const val KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
    const val KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
    const val KP_DOCUMENT_SIGNING = "1.3.6.1.5.5.7.3.36"
    const val KP_MDOC_DS = "1.0.18013.5.1.2"
    const val KP_MDOC_READER = "1.0.18013.5.1.6"
    const val KP_MDOC_IACA = "1.0.18013.5.1.7"
    const val KP_MDOC_READER_CA = "1.0.18013.5.1.8"
    const val KP_C2PA_CLAIM_SIGNING = "1.3.6.1.4.1.62558.2.1"
    const val KP_ADOBE_AUTHENTIC_DOCUMENTS = "1.2.840.113583.1.1.5"
    const val KP_MS_DOCUMENT_SIGNING = "1.3.6.1.4.1.311.10.3.12"
    const val KP_MS_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"

    const val EMAIL_ADDRESS = "1.2.840.113549.1.9.1"

    private val NAMES: Map<String, String> = mapOf(
        // Extensions.
        SUBJECT_DIRECTORY_ATTRIBUTES to "subjectDirectoryAttributes",
        SUBJECT_KEY_IDENTIFIER to "subjectKeyIdentifier",
        KEY_USAGE to "keyUsage",
        PRIVATE_KEY_USAGE_PERIOD to "privateKeyUsagePeriod",
        SUBJECT_ALT_NAME to "subjectAltName",
        ISSUER_ALT_NAME to "issuerAltName",
        BASIC_CONSTRAINTS to "basicConstraints",
        NAME_CONSTRAINTS to "nameConstraints",
        CRL_DISTRIBUTION_POINTS to "cRLDistributionPoints",
        CERTIFICATE_POLICIES to "certificatePolicies",
        POLICY_MAPPINGS to "policyMappings",
        AUTHORITY_KEY_IDENTIFIER to "authorityKeyIdentifier",
        POLICY_CONSTRAINTS to "policyConstraints",
        EXTENDED_KEY_USAGE to "extKeyUsage",
        FRESHEST_CRL to "freshestCRL",
        INHIBIT_ANY_POLICY to "inhibitAnyPolicy",
        AUTHORITY_INFO_ACCESS to "authorityInfoAccess",
        QC_STATEMENTS to "qcStatements",
        SUBJECT_INFO_ACCESS to "subjectInfoAccess",
        LOGOTYPE to "logotype",
        TLS_FEATURE to "tlsfeature",
        OCSP_NO_CHECK to "id-pkix-ocsp-nocheck",
        SCT_LIST to "signedCertificateTimestampList",
        CT_PRECERT_POISON to "precertificate poison",
        MS_CA_VERSION to "Microsoft CA version",
        MS_PREVIOUS_CA_HASH to "Microsoft previous CA certificate hash",
        MS_TEMPLATE_V2 to "Microsoft certificate template",
        MS_APPLICATION_POLICIES to "Microsoft application policies",
        MS_TEMPLATE_NAME to "Microsoft certificate template name",
        NETSCAPE_CERT_TYPE to "netscape-cert-type",
        NETSCAPE_COMMENT to "netscape-comment",
        ICAO_NAME_CHANGE to "ICAO nameChange",
        ICAO_DOCUMENT_TYPE_LIST to "ICAO documentTypeList",
        ENTRUST_VERSION to "Entrust version",
        "2.5.29.1" to "authorityKeyIdentifier (obsolete)",
        "2.5.29.3" to "certificatePolicies (obsolete)",
        "2.5.29.10" to "basicConstraints (obsolete)",
        "1.3.6.1.5.5.7.1.2" to "biometricInfo",
        "1.3.6.1.5.5.7.1.7" to "sbgp-ipAddrBlock",
        "1.3.6.1.5.5.7.1.8" to "sbgp-autonomousSysNum",
        "2.5.29.56" to "noRevAvail",
        "2.5.29.55" to "targetInformation",
        "1.3.6.1.4.1.311.21.4" to "Microsoft CRL next publish",
        "1.3.6.1.4.1.311.25.2" to "Microsoft NTDS CA security",
        "1.3.6.1.4.1.11129.2.1.17" to "Android key attestation",

        ANY_POLICY to "anyPolicy",
        ANY_EKU to "anyExtendedKeyUsage",

        // Extended key usages.
        KP_SERVER_AUTH to "id-kp-serverAuth",
        KP_CLIENT_AUTH to "id-kp-clientAuth",
        KP_CODE_SIGNING to "id-kp-codeSigning",
        KP_EMAIL_PROTECTION to "id-kp-emailProtection",
        "1.3.6.1.5.5.7.3.5" to "id-kp-ipsecEndSystem",
        "1.3.6.1.5.5.7.3.6" to "id-kp-ipsecTunnel",
        "1.3.6.1.5.5.7.3.7" to "id-kp-ipsecUser",
        KP_TIME_STAMPING to "id-kp-timeStamping",
        KP_OCSP_SIGNING to "id-kp-OCSPSigning",
        "1.3.6.1.5.5.7.3.17" to "id-kp-ipsecIKE",
        "1.3.6.1.5.5.7.3.21" to "id-kp-secureShellClient",
        "1.3.6.1.5.5.7.3.22" to "id-kp-secureShellServer",
        KP_DOCUMENT_SIGNING to "id-kp-documentSigning",
        "1.3.6.1.5.5.7.3.37" to "id-kp-jwt",
        "1.3.6.1.5.5.7.3.38" to "id-kp-httpContentEncrypt",
        "1.3.6.1.5.5.7.3.39" to "id-kp-oauthAccessTokenSigning",
        KP_MDOC_DS to "id-mdlDS (mdoc document signer)",
        "1.0.18013.5.1.3" to "id-mdlJWS",
        KP_MDOC_READER to "id-mdlReaderAuth (mdoc reader authentication)",
        KP_MDOC_IACA to "id-mdlIACA",
        KP_MDOC_READER_CA to "id-mdlReaderAuthCA / VICAL signer",
        KP_C2PA_CLAIM_SIGNING to "c2pa-kp-claimSigning",
        KP_ADOBE_AUTHENTIC_DOCUMENTS to "Adobe Authentic Documents Trust",
        KP_MS_DOCUMENT_SIGNING to "Microsoft document signing",
        KP_MS_SMARTCARD_LOGON to "Microsoft smart card logon",
        "1.3.6.1.4.1.311.10.3.4" to "Microsoft encrypting file system",
        "1.3.6.1.4.1.311.10.3.3" to "Microsoft server gated crypto",
        "1.3.6.1.4.1.311.2.1.21" to "Microsoft individual code signing",
        "1.3.6.1.4.1.311.2.1.22" to "Microsoft commercial code signing",
        "1.3.6.1.4.1.311.10.3.13" to "Microsoft lifetime signing",
        "1.3.6.1.4.1.311.61.1.1" to "Microsoft kernel mode code signing",
        "2.16.840.1.113730.4.1" to "Netscape server gated crypto",
        "1.3.6.1.5.2.3.4" to "id-pkinit-KPClientAuth",
        "1.3.6.1.5.2.3.5" to "id-pkinit-KPKdc",
        "2.23.136.1.1.3" to "ICAO CSCA master list signing",
        "2.23.136.1.1.8" to "ICAO deviation list signing",

        // Algorithms.
        "1.2.840.113549.1.1.1" to "rsaEncryption",
        "1.2.840.113549.1.1.2" to "md2WithRSAEncryption",
        "1.2.840.113549.1.1.4" to "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" to "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" to "RSASSA-PSS",
        "1.2.840.113549.1.1.11" to "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" to "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" to "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.14" to "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.8" to "id-mgf1",
        "1.2.840.10040.4.1" to "id-dsa",
        "1.2.840.10040.4.3" to "id-dsa-with-sha1",
        "2.16.840.1.101.3.4.3.1" to "id-dsa-with-sha224",
        "2.16.840.1.101.3.4.3.2" to "id-dsa-with-sha256",
        "1.2.840.10045.2.1" to "id-ecPublicKey",
        "1.2.840.10045.4.1" to "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1" to "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" to "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" to "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" to "ecdsa-with-SHA512",
        "2.16.840.1.101.3.4.3.10" to "id-ecdsa-with-sha3-256",
        "2.16.840.1.101.3.4.3.11" to "id-ecdsa-with-sha3-384",
        "2.16.840.1.101.3.4.3.12" to "id-ecdsa-with-sha3-512",
        "1.3.101.110" to "X25519",
        "1.3.101.111" to "X448",
        "1.3.101.112" to "Ed25519",
        "1.3.101.113" to "Ed448",
        "1.2.156.10197.1.301" to "SM2",
        "1.2.156.10197.1.501" to "SM3withSM2",
        "1.2.156.10197.1.401" to "SM3",
        "1.3.14.3.2.26" to "SHA-1",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
        "2.16.840.1.101.3.4.2.4" to "SHA-224",
        "1.2.643.7.1.1.1.1" to "GOST R 34.10-2012 256",
        "1.2.643.7.1.1.3.2" to "GOST R 34.10-2012 with GOST R 34.11-2012 (256)",

        // Elliptic curves.
        "1.2.840.10045.3.1.1" to "secp192r1 (P-192)",
        "1.3.132.0.33" to "secp224r1 (P-224)",
        "1.2.840.10045.3.1.7" to "secp256r1 (P-256)",
        "1.3.132.0.34" to "secp384r1 (P-384)",
        "1.3.132.0.35" to "secp521r1 (P-521)",
        "1.3.132.0.10" to "secp256k1",
        "1.3.36.3.3.2.8.1.1.1" to "brainpoolP160r1",
        "1.3.36.3.3.2.8.1.1.3" to "brainpoolP192r1",
        "1.3.36.3.3.2.8.1.1.5" to "brainpoolP224r1",
        "1.3.36.3.3.2.8.1.1.7" to "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.9" to "brainpoolP320r1",
        "1.3.36.3.3.2.8.1.1.11" to "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" to "brainpoolP512r1",

        // Name attributes (RFC 5280 4.1.2.4, X.520).
        "2.5.4.3" to "CN",
        "2.5.4.4" to "SN",
        "2.5.4.5" to "serialNumber",
        "2.5.4.6" to "C",
        "2.5.4.7" to "L",
        "2.5.4.8" to "ST",
        "2.5.4.9" to "street",
        "2.5.4.10" to "O",
        "2.5.4.11" to "OU",
        "2.5.4.12" to "title",
        "2.5.4.13" to "description",
        "2.5.4.15" to "businessCategory",
        "2.5.4.17" to "postalCode",
        "2.5.4.20" to "telephoneNumber",
        "2.5.4.41" to "name",
        "2.5.4.42" to "GN",
        "2.5.4.43" to "initials",
        "2.5.4.44" to "generationQualifier",
        "2.5.4.45" to "x500UniqueIdentifier",
        "2.5.4.46" to "dnQualifier",
        "2.5.4.65" to "pseudonym",
        "2.5.4.72" to "role",
        "2.5.4.97" to "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" to "UID",
        "0.9.2342.19200300.100.1.25" to "DC",
        EMAIL_ADDRESS to "emailAddress",
        "1.2.840.113549.1.9.2" to "unstructuredName",
        "1.3.6.1.4.1.311.60.2.1.1" to "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" to "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" to "jurisdictionC",
        "1.3.6.1.5.5.7.9.1" to "dateOfBirth",
        "1.3.6.1.5.5.7.9.2" to "placeOfBirth",
        "1.3.6.1.5.5.7.9.3" to "gender",
        "1.3.6.1.5.5.7.9.4" to "countryOfCitizenship",
        "1.3.6.1.5.5.7.9.5" to "countryOfResidence",

        // Certificate policy qualifiers and access methods.
        "1.3.6.1.5.5.7.2.1" to "id-qt-cps",
        "1.3.6.1.5.5.7.2.2" to "id-qt-unotice",
        "1.3.6.1.5.5.7.48.1" to "id-ad-ocsp",
        "1.3.6.1.5.5.7.48.2" to "id-ad-caIssuers",
        "1.3.6.1.5.5.7.48.3" to "id-ad-timeStamping",
        "1.3.6.1.5.5.7.48.5" to "id-ad-caRepository",

        // Well-known certificate policies.
        "2.23.140.1.1" to "CA/B EV",
        "2.23.140.1.2.1" to "CA/B domain validated",
        "2.23.140.1.2.2" to "CA/B organization validated",
        "2.23.140.1.2.3" to "CA/B individual validated",
        "2.23.140.1.3" to "CA/B EV code signing",
        "2.23.140.1.4.1" to "CA/B code signing",
        "0.4.0.194112.1.0" to "ETSI QCP-n",
        "0.4.0.194112.1.1" to "ETSI QCP-l",
        "0.4.0.194112.1.2" to "ETSI QCP-n-qscd",
        "0.4.0.194112.1.3" to "ETSI QCP-l-qscd",
        "0.4.0.194112.1.4" to "ETSI QCP-w",
        "0.4.0.2042.1.1" to "ETSI NCP",
        "0.4.0.2042.1.2" to "ETSI NCP+",
        "0.4.0.2042.1.3" to "ETSI LCP",
        "0.4.0.2042.1.4" to "ETSI EVCP",
        "0.4.0.2042.1.6" to "ETSI DVCP",
        "0.4.0.2042.1.7" to "ETSI OVCP",

        // QC statements (RFC 3739, ETSI EN 319 412-5).
        "1.3.6.1.5.5.7.11.1" to "id-qcs-pkixQCSyntax-v1",
        "1.3.6.1.5.5.7.11.2" to "id-qcs-pkixQCSyntax-v2",
        "0.4.0.1862.1.1" to "id-etsi-qcs-QcCompliance",
        "0.4.0.1862.1.2" to "id-etsi-qcs-QcLimitValue",
        "0.4.0.1862.1.3" to "id-etsi-qcs-QcRetentionPeriod",
        "0.4.0.1862.1.4" to "id-etsi-qcs-QcSSCD",
        "0.4.0.1862.1.5" to "id-etsi-qcs-QcPDS",
        "0.4.0.1862.1.6" to "id-etsi-qcs-QcType",
        "0.4.0.1862.1.6.1" to "id-etsi-qct-esign",
        "0.4.0.1862.1.6.2" to "id-etsi-qct-eseal",
        "0.4.0.1862.1.6.3" to "id-etsi-qct-web",
        "0.4.0.1862.1.7" to "id-etsi-qcs-QcCClegislation",
        "0.4.0.194121.1.1" to "id-etsi-qcs-semanticsId-Natural",
        "0.4.0.194121.1.2" to "id-etsi-qcs-semanticsId-Legal",
        "0.4.0.194121.1.3" to "id-etsi-qcs-semanticsId-eIDASNatural",
        "0.4.0.194121.1.4" to "id-etsi-qcs-semanticsId-eIDASLegal",
        "0.4.0.19495.2" to "id-etsi-psd2-qcStatement",
    )

    fun oid(oid: String): String? = NAMES[oid]

    /** "name (oid)" when the name is known, else the OID. */
    fun label(oid: String): String = NAMES[oid]?.let { "$it ($oid)" } ?: oid

    /** Short name of a distinguished name attribute, or its OID. */
    fun attribute(oid: String): String = NAMES[oid] ?: oid

    val KEY_USAGE_BITS = listOf(
        "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement",
        "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
    )

    /** Bit sizes of the named curves (keys on other curves are reported without a size). */
    val CURVE_BITS: Map<String, Int> = mapOf(
        "1.2.840.10045.3.1.1" to 192, "1.3.132.0.33" to 224, "1.2.840.10045.3.1.7" to 256, "1.3.132.0.34" to 384,
        "1.3.132.0.35" to 521, "1.3.132.0.10" to 256, "1.3.36.3.3.2.8.1.1.1" to 160, "1.3.36.3.3.2.8.1.1.3" to 192,
        "1.3.36.3.3.2.8.1.1.5" to 224, "1.3.36.3.3.2.8.1.1.7" to 256, "1.3.36.3.3.2.8.1.1.9" to 320,
        "1.3.36.3.3.2.8.1.1.11" to 384, "1.3.36.3.3.2.8.1.1.13" to 512, "1.2.156.10197.1.301" to 256,
    )
}

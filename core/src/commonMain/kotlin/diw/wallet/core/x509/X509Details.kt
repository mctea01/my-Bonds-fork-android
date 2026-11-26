package diw.wallet.core.x509

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.i18n.ct
import diw.wallet.core.jose.PlatformCrypto
import org.multipaz.crypto.X509Cert
import kotlin.time.Instant

/** An AlgorithmIdentifier: the OID, its name and its parameters as text. */
data class AlgorithmId(val oid: String, val name: String?, val parameters: String?) {
    val label: String get() = name?.let { "$it ($oid)" } ?: oid
}

/** One attribute of a relative distinguished name. */
data class NameAttribute(val oid: String, val value: String) {
    val name: String get() = X509Names.attribute(oid)
}

/** A distinguished name as encoded: its RDNs in order, each with its attributes and its DER (for name matching). */
data class DistinguishedName(val rdns: List<List<NameAttribute>>, val rdnEncodings: List<ByteArray>) {
    val attributes: List<NameAttribute> get() = rdns.flatten()
    val empty: Boolean get() = rdns.isEmpty()

    /** RFC 4514 order (last RDN first), as most certificate viewers print names. */
    val text: String get() = rdns.reversed().joinToString(", ") { rdn -> rdn.joinToString(" + ") { "${it.name}=${it.value}" } }

    fun first(oid: String): String? = attributes.firstOrNull { it.oid == oid }?.value
}

enum class KeyType { RSA, RSA_PSS, EC, SM2, DSA, ED25519, ED448, X25519, X448, OTHER }

/** The subject public key: its algorithm, size and the hashes viewers compare. */
data class PublicKeyInfo(
    val algorithm: AlgorithmId,
    val type: KeyType,
    /** Modulus size for RSA, prime size for DSA, field size of the named curve for EC; null when unknown. */
    val bits: Int?,
    val curveOid: String?,
    val rsaExponent: String?,
    val keyHex: String,
    val spkiSha256Hex: String,
) {
    val curveName: String? get() = curveOid?.let { X509Names.oid(it) ?: it }
}

/** One field of an extension's decoded value: the field name of the specification and its value. */
data class ExtField(val label: String, val value: String)

/**
 * One extension: OID, the specification's name, the critical flag, the raw value, and its fields when the reader
 * decodes the extension ([known]); an extension it does not know is outlined from its ASN.1 structure.
 */
data class CertExtension(
    val oid: String,
    val critical: Boolean,
    val known: Boolean,
    val value: ByteArray,
    val fields: List<ExtField>,
    val error: String?,
) {
    val name: String? get() = X509Names.oid(oid)
    val label: String get() = X509Names.label(oid)
    val valueHex: String get() = Der.hex(value)
}

/** A GeneralName (RFC 5280 4.2.1.6). */
data class GeneralName(val type: Type, val value: String, val raw: ByteArray, val directory: DistinguishedName? = null) {
    enum class Type(val specName: String) {
        OTHER_NAME("otherName"), RFC822("rfc822Name"), DNS("dNSName"), X400("x400Address"), DIRECTORY("directoryName"),
        EDI_PARTY("ediPartyName"), URI("uniformResourceIdentifier"), IP("iPAddress"), REGISTERED_ID("registeredID"),
    }

    val text: String get() = "${type.specName}: $value"
}

/**
 * Every field of an X.509 v1 to v3 certificate (RFC 5280 4.1), with every extension decoded where a specification
 * defines it and outlined where it is unknown. Parsing does not judge the certificate: [problems] lists only how
 * its encoding departs from RFC 5280; usage and path rules are checked by [CertificateConstraints].
 */
class X509Details private constructor(
    val der: ByteArray,
    /** 1, 2 or 3. */
    val version: Int,
    val serialHex: String,
    val signatureAlgorithm: AlgorithmId,
    val tbsSignatureAlgorithm: AlgorithmId,
    val issuer: DistinguishedName,
    val subject: DistinguishedName,
    val notBefore: Instant,
    val notAfter: Instant,
    val publicKey: PublicKeyInfo,
    val issuerUniqueId: String?,
    val subjectUniqueId: String?,
    val extensions: List<CertExtension>,
    val signatureHex: String,
    val problems: List<String>,
) {
    val sha256Hex: String get() = Der.hex(PlatformCrypto.sha256(der))
    val sha1Hex: String get() = Der.hex(DocCrypto.digest("SHA-1", der))

    fun extension(oid: String): CertExtension? = extensions.firstOrNull { it.oid == oid }

    /** Subject and issuer are the same name (RFC 5280 6.1: self-issued). */
    val selfIssued: Boolean get() = subject.rdnEncodings.size == issuer.rdnEncodings.size &&
        subject.rdnEncodings.indices.all { sameRdn(subject.rdns[it], issuer.rdns[it], subject.rdnEncodings[it], issuer.rdnEncodings[it]) }

    // Typed views of the extensions that the usage and path checks rely on. A malformed extension reads as absent
    // here; [problems] and the extension's error say so, and the checks treat it as a violation.

    /** keyUsage bits set, by bit number (RFC 5280 4.2.1.3); null without the extension. */
    val keyUsage: Set<Int>? by lazy { extension(X509Names.KEY_USAGE)?.let { e -> runCatching { keyUsageBits(Der.parse(e.value)) }.getOrNull() } }

    /** extKeyUsage purposes (RFC 5280 4.2.1.12); null without the extension. */
    val extendedKeyUsage: List<String>? by lazy {
        extension(X509Names.EXTENDED_KEY_USAGE)?.let { e -> runCatching { Der.parse(e.value).children().map { it.oid() } }.getOrNull() }
    }

    /** basicConstraints cA and pathLenConstraint (RFC 5280 4.2.1.9); null without the extension. */
    val basicConstraints: Pair<Boolean, Long?>? by lazy {
        extension(X509Names.BASIC_CONSTRAINTS)?.let { e -> runCatching { basicConstraintsOf(Der.parse(e.value)) }.getOrNull() }
    }

    val subjectAltNames: List<GeneralName> by lazy {
        extension(X509Names.SUBJECT_ALT_NAME)?.let { e -> runCatching { generalNames(Der.parse(e.value)) }.getOrNull() }.orEmpty()
    }

    /** nameConstraints permitted and excluded subtrees (RFC 5280 4.2.1.10); null without the extension. */
    val nameConstraints: Pair<List<GeneralName>, List<GeneralName>>? by lazy {
        extension(X509Names.NAME_CONSTRAINTS)?.let { e ->
            runCatching {
                var permitted = emptyList<GeneralName>()
                var excluded = emptyList<GeneralName>()
                for (c in Der.parse(e.value).children()) {
                    val subtrees = c.children().map { generalName(it.children().first()) }
                    if (c.isContext(0)) permitted = subtrees else if (c.isContext(1)) excluded = subtrees
                }
                permitted to excluded
            }.getOrNull()
        }
    }

    /** certificatePolicies policy identifiers (RFC 5280 4.2.1.4); null without the extension. */
    val policies: List<String>? by lazy {
        extension(X509Names.CERTIFICATE_POLICIES)?.let { e -> runCatching { Der.parse(e.value).children().map { it.children().first().oid() } }.getOrNull() }
    }

    /** policyMappings issuerDomainPolicy to subjectDomainPolicy (RFC 5280 4.2.1.5); null without the extension. */
    val policyMappings: List<Pair<String, String>>? by lazy {
        extension(X509Names.POLICY_MAPPINGS)?.let { e ->
            runCatching { Der.parse(e.value).children().map { m -> m.children().let { it[0].oid() to it[1].oid() } } }.getOrNull()
        }
    }

    /** policyConstraints requireExplicitPolicy and inhibitPolicyMapping (RFC 5280 4.2.1.11); null without the extension. */
    val policyConstraints: Pair<Long?, Long?>? by lazy {
        extension(X509Names.POLICY_CONSTRAINTS)?.let { e ->
            runCatching {
                var require: Long? = null
                var inhibit: Long? = null
                for (c in Der.parse(e.value).children()) {
                    if (c.isContext(0)) require = implicitInt(c) else if (c.isContext(1)) inhibit = implicitInt(c)
                }
                require to inhibit
            }.getOrNull()
        }
    }

    /** inhibitAnyPolicy SkipCerts (RFC 5280 4.2.1.14); null without the extension. */
    val inhibitAnyPolicy: Long? by lazy { extension(X509Names.INHIBIT_ANY_POLICY)?.let { e -> runCatching { Der.parse(e.value).long() }.getOrNull() } }

    companion object {
        /** The details of [cert]. */
        fun of(cert: X509Cert): X509Details = parse(cert.encoded.toByteArray())

        /** The details of [cert], or null when its encoding cannot be read. */
        fun orNull(cert: X509Cert): X509Details? = runCatching { of(cert) }.getOrNull()

        /** Parses a DER certificate; throws [DerException] when its structure is not a certificate. */
        fun parse(der: ByteArray): X509Details {
            val problems = mutableListOf<String>()
            val cert = Der.parse(der).children()
            if (cert.size != 3) throw DerException("A certificate has three elements")
            val tbs = cert[0].children()
            val outerAlg = algorithm(cert[1])
            val signature = cert[2].bitStringBytes()
            var i = 0
            var version = 1
            if (tbs[i].isContext(0)) {
                version = tbs[i].inner().long().toInt() + 1
                i++
            }
            val serial = tbs[i++]
            val serialBytes = serial.content
            if (serialBytes.isEmpty() || serialBytes.size > 20 || serialBytes[0] < 0 || (serialBytes.size > 1 && serialBytes[0].toInt() == 0 && serialBytes[1] >= 0)) {
                problems.add(ct("core_x509_p_serial"))
            }
            val tbsAlg = algorithm(tbs[i++])
            if (!sameAlgorithm(cert[1], tbs[i - 1])) problems.add(ct("core_x509_p_alg_mismatch"))
            val issuer = name(tbs[i++])
            val validity = tbs[i++].children()
            val notBefore = validity[0].time()
            val notAfter = validity[1].time()
            val subject = name(tbs[i++])
            val spki = publicKey(tbs[i++])
            var issuerUid: String? = null
            var subjectUid: String? = null
            val extensions = mutableListOf<CertExtension>()
            while (i < tbs.size) {
                val e = tbs[i++]
                when {
                    e.isContext(1) -> issuerUid = Der.hex(e.content.drop(1).toByteArray())
                    e.isContext(2) -> subjectUid = Der.hex(e.content.drop(1).toByteArray())
                    e.isContext(3) -> {
                        if (version != 3) problems.add(ct("core_x509_p_ext_version", version))
                        for (x in e.inner().children()) extensions.add(extension(x))
                    }
                }
            }
            extensions.groupBy { it.oid }.filter { it.value.size > 1 }.keys.forEach { problems.add(ct("core_x509_p_duplicate_ext", X509Names.label(it))) }
            extensions.filter { it.error != null }.forEach { problems.add(ct("core_x509_p_ext_malformed", it.label, it.error)) }
            return X509Details(
                der, version, Der.colonHex(serialBytes), outerAlg, tbsAlg, issuer, subject, notBefore, notAfter, spki,
                issuerUid, subjectUid, extensions, Der.hex(signature), problems,
            )
        }

        /** The same AlgorithmIdentifier; an absent parameter and a NULL one are taken as the same (RFC 4055 2.1 allows both). */
        private fun sameAlgorithm(a: Der, b: Der): Boolean {
            if (a.encoded.contentEquals(b.encoded)) return true
            val x = a.children()
            val y = b.children()
            fun nullish(p: Der?) = p == null || p.isUniversal(Der.NULL)
            return x[0].oid() == y[0].oid() && nullish(x.getOrNull(1)) && nullish(y.getOrNull(1))
        }

        private fun algorithm(d: Der): AlgorithmId {
            val parts = d.children()
            val oid = parts[0].oid()
            val params = parts.getOrNull(1)
            val text = when {
                params == null -> null
                params.isUniversal(Der.NULL) -> "NULL"
                params.isUniversal(Der.OID) -> params.oid().let { X509Names.label(it) }
                oid == "1.2.840.113549.1.1.10" -> pssParameters(params)
                else -> params.outline()
            }
            return AlgorithmId(oid, X509Names.oid(oid), text)
        }

        /** RSASSA-PSS-params (RFC 4055 3.1): hash, mask generation, salt length, trailer field; defaults per the RFC. */
        private fun pssParameters(d: Der): String {
            var hash = "SHA-1"
            var mgf = "id-mgf1 SHA-1"
            var salt = 20L
            var trailer = 1L
            for (p in d.children()) {
                when {
                    p.isContext(0) -> hash = p.inner().children().first().oid().let { X509Names.oid(it) ?: it }
                    p.isContext(1) -> p.inner().children().let { m ->
                        mgf = (X509Names.oid(m[0].oid()) ?: m[0].oid()) + (m.getOrNull(1)?.children()?.firstOrNull()?.oid()?.let { " " + (X509Names.oid(it) ?: it) } ?: "")
                    }
                    p.isContext(2) -> salt = p.inner().long()
                    p.isContext(3) -> trailer = p.inner().long()
                }
            }
            return "hashAlgorithm $hash, maskGenAlgorithm $mgf, saltLength $salt, trailerField $trailer"
        }

        fun name(d: Der): DistinguishedName {
            val rdns = mutableListOf<List<NameAttribute>>()
            val encodings = mutableListOf<ByteArray>()
            for (rdn in d.children()) {
                encodings.add(rdn.encoded)
                rdns.add(rdn.children().map { atv ->
                    val parts = atv.children()
                    val value = parts[1]
                    NameAttribute(parts[0].oid(), if (value.isString) value.string() else value.outline())
                })
            }
            return DistinguishedName(rdns, encodings)
        }

        private fun publicKey(d: Der): PublicKeyInfo {
            val parts = d.children()
            val alg = algorithm(parts[0])
            val keyBytes = parts[1].bitStringBytes()
            val algParams = parts[0].children().getOrNull(1)
            var curve: String? = null
            var bits: Int? = null
            var exponent: String? = null
            val type = when (alg.oid) {
                "1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10" -> {
                    runCatching {
                        val rsa = Der.parse(keyBytes).children()
                        val modulus = rsa[0].content.dropWhile { it.toInt() == 0 }
                        bits = if (modulus.isEmpty()) 0 else (modulus.size - 1) * 8 + (32 - (modulus[0].toInt() and 0xFF).countLeadingZeroBits())
                        exponent = rsa[1].content.let { e -> if (e.size <= 8) Der.parse(rsa[1].encoded).long().toString() else "0x" + Der.hex(e) }
                    }
                    if (alg.oid == "1.2.840.113549.1.1.10") KeyType.RSA_PSS else KeyType.RSA
                }
                "1.2.840.10045.2.1" -> {
                    curve = runCatching { algParams?.takeIf { it.isUniversal(Der.OID) }?.oid() }.getOrNull()
                    bits = curve?.let { X509Names.CURVE_BITS[it] }
                        ?: if (algParams != null && algParams.isUniversal(Der.SEQUENCE)) explicitCurveBits(algParams) else null
                    if (curve == "1.2.156.10197.1.301") KeyType.SM2 else KeyType.EC
                }
                "1.2.156.10197.1.301" -> { curve = alg.oid; bits = 256; KeyType.SM2 }
                "1.2.840.10040.4.1" -> {
                    bits = runCatching { algParams?.children()?.first()?.content?.dropWhile { it.toInt() == 0 }?.let { p -> (p.size - 1) * 8 + (32 - (p[0].toInt() and 0xFF).countLeadingZeroBits()) } }.getOrNull()
                    KeyType.DSA
                }
                "1.3.101.112" -> { bits = 256; KeyType.ED25519 }
                "1.3.101.113" -> { bits = 456; KeyType.ED448 }
                "1.3.101.110" -> { bits = 255; KeyType.X25519 }
                "1.3.101.111" -> { bits = 448; KeyType.X448 }
                else -> KeyType.OTHER
            }
            return PublicKeyInfo(alg, type, bits, curve, exponent, Der.hex(keyBytes), Der.hex(PlatformCrypto.sha256(d.encoded)))
        }

        /** ECParameters with explicit curve parameters (travel document CSCAs use them): the size of the prime field. */
        private fun explicitCurveBits(params: Der): Int? = runCatching {
            val fieldId = params.children()[1].children()
            val p = fieldId[1].content.dropWhile { it.toInt() == 0 }
            (p.size - 1) * 8 + (32 - (p[0].toInt() and 0xFF).countLeadingZeroBits())
        }.getOrNull()

        private fun extension(d: Der): CertExtension {
            val parts = d.children()
            val oid = parts[0].oid()
            var critical = false
            var valueIndex = 1
            if (parts.size == 3) {
                critical = parts[1].bool()
                valueIndex = 2
            }
            val value = parts[valueIndex].content
            val decoded = runCatching { ExtensionDecoders.decode(oid, value) }
            val fields = decoded.getOrNull()
            return CertExtension(
                oid = oid, critical = critical, known = fields != null || decoded.isFailure && ExtensionDecoders.knows(oid),
                value = value,
                fields = fields ?: runCatching { listOf(ExtField("value", Der.parse(value).outline())) }.getOrElse { listOf(ExtField("value", Der.hex(value))) },
                error = decoded.exceptionOrNull()?.let { it.message ?: it::class.simpleName },
            )
        }

        fun keyUsageBits(d: Der): Set<Int> = buildSet { for (b in 0 until 9) if (d.bit(b)) add(b) }

        fun basicConstraintsOf(d: Der): Pair<Boolean, Long?> {
            var ca = false
            var path: Long? = null
            for (c in d.children()) {
                if (c.isUniversal(Der.BOOLEAN)) ca = c.bool() else if (c.isUniversal(Der.INTEGER)) path = c.long()
            }
            return ca to path
        }

        private fun implicitInt(d: Der): Long {
            val c = d.content
            var v = c[0].toLong()
            for (k in 1 until c.size) v = (v shl 8) or (c[k].toLong() and 0xFF)
            return v
        }

        fun generalNames(d: Der): List<GeneralName> = d.children().map { generalName(it) }

        fun generalName(d: Der): GeneralName {
            val raw = d.content
            return when (d.tag) {
                0 -> {
                    val parts = d.children()
                    val typeId = parts[0].oid()
                    val value = runCatching { parts[1].inner().let { if (it.isString) it.string() else it.outline() } }.getOrElse { parts.getOrNull(1)?.outline() ?: "" }
                    GeneralName(GeneralName.Type.OTHER_NAME, "${X509Names.label(typeId)} $value", d.encoded)
                }
                1 -> GeneralName(GeneralName.Type.RFC822, raw.decodeToString(), raw)
                2 -> GeneralName(GeneralName.Type.DNS, raw.decodeToString(), raw)
                3 -> GeneralName(GeneralName.Type.X400, d.outline(), raw)
                4 -> name(d.inner()).let { GeneralName(GeneralName.Type.DIRECTORY, it.text, raw, it) }
                5 -> GeneralName(GeneralName.Type.EDI_PARTY, d.outline(), raw)
                6 -> GeneralName(GeneralName.Type.URI, raw.decodeToString(), raw)
                7 -> GeneralName(GeneralName.Type.IP, ipText(raw), raw)
                8 -> GeneralName(GeneralName.Type.REGISTERED_ID, Der.decodeOid(raw).let { X509Names.label(it) }, raw)
                else -> throw DerException("Unknown GeneralName tag ${d.tag}")
            }
        }

        /** An IPv4 or IPv6 address, or (in name constraints) an address with its mask. */
        fun ipText(b: ByteArray): String {
            fun v4(o: Int) = (0 until 4).joinToString(".") { (b[o + it].toInt() and 0xFF).toString() }
            fun v6(o: Int) = (0 until 8).joinToString(":") { (((b[o + 2 * it].toInt() and 0xFF) shl 8) or (b[o + 2 * it + 1].toInt() and 0xFF)).toString(16) }
            return when (b.size) {
                4 -> v4(0)
                8 -> v4(0) + "/" + v4(4)
                16 -> v6(0)
                32 -> v6(0) + "/" + v6(16)
                else -> "0x" + Der.hex(b)
            }
        }

        /** Two RDNs are the same name when their encodings are equal or their attributes compare equal after RFC 5280 7.1 folding. */
        fun sameRdn(a: List<NameAttribute>, b: List<NameAttribute>, aDer: ByteArray, bDer: ByteArray): Boolean =
            aDer.contentEquals(bDer) || (a.size == b.size && a.map { it.oid to fold(it.value) }.toSet() == b.map { it.oid to fold(it.value) }.toSet())

        /** Case folding and white space compression for comparing name strings (RFC 5280 7.1, RFC 4518 in short). */
        fun fold(s: String): String = s.trim().lowercase().replace(Regex("\\s+"), " ")
    }
}

package diw.wallet.core.x509

import kotlin.time.Instant

/**
 * Decoders for the extension values the specifications define, giving each field under the name the specification
 * uses (RFC 5280 4.2, RFC 3739, ETSI EN 319 412-5, RFC 6962, RFC 7633, ICAO 9303-12, Microsoft and Netscape
 * extensions). Unknown extensions return null and are outlined from their ASN.1 structure instead.
 */
internal object ExtensionDecoders {
    private val decoders: Map<String, (Der) -> List<ExtField>> = mapOf(
        X509Names.SUBJECT_KEY_IDENTIFIER to { d -> listOf(ExtField("keyIdentifier", Der.colonHex(d.content))) },
        X509Names.AUTHORITY_KEY_IDENTIFIER to ::authorityKeyIdentifier,
        X509Names.KEY_USAGE to { d -> X509Details.keyUsageBits(d).sorted().map { ExtField("KeyUsage", X509Names.KEY_USAGE_BITS[it]) } },
        X509Names.EXTENDED_KEY_USAGE to { d -> d.children().map { ExtField("KeyPurposeId", X509Names.label(it.oid())) } },
        X509Names.BASIC_CONSTRAINTS to { d ->
            val (ca, path) = X509Details.basicConstraintsOf(d)
            listOfNotNull(ExtField("cA", ca.toString().uppercase()), path?.let { ExtField("pathLenConstraint", it.toString()) })
        },
        X509Names.SUBJECT_ALT_NAME to ::names,
        X509Names.ISSUER_ALT_NAME to ::names,
        X509Names.NAME_CONSTRAINTS to ::nameConstraints,
        X509Names.CERTIFICATE_POLICIES to ::certificatePolicies,
        X509Names.POLICY_MAPPINGS to { d ->
            d.children().map { m -> m.children().let { ExtField("issuerDomainPolicy -> subjectDomainPolicy", X509Names.label(it[0].oid()) + " -> " + X509Names.label(it[1].oid())) } }
        },
        X509Names.POLICY_CONSTRAINTS to { d ->
            d.children().mapNotNull { c ->
                when {
                    c.isContext(0) -> ExtField("requireExplicitPolicy", unsigned(c.content).toString())
                    c.isContext(1) -> ExtField("inhibitPolicyMapping", unsigned(c.content).toString())
                    else -> null
                }
            }
        },
        X509Names.INHIBIT_ANY_POLICY to { d -> listOf(ExtField("SkipCerts", d.long().toString())) },
        X509Names.CRL_DISTRIBUTION_POINTS to ::distributionPoints,
        X509Names.FRESHEST_CRL to ::distributionPoints,
        X509Names.AUTHORITY_INFO_ACCESS to ::accessDescriptions,
        X509Names.SUBJECT_INFO_ACCESS to ::accessDescriptions,
        X509Names.PRIVATE_KEY_USAGE_PERIOD to { d ->
            d.children().mapNotNull { c ->
                val t = runCatching { generalizedTime(c.content) }.getOrNull()?.toString() ?: Der.hex(c.content)
                when {
                    c.isContext(0) -> ExtField("notBefore", t)
                    c.isContext(1) -> ExtField("notAfter", t)
                    else -> null
                }
            }
        },
        X509Names.SUBJECT_DIRECTORY_ATTRIBUTES to { d ->
            d.children().map { a ->
                val parts = a.children()
                ExtField(X509Names.label(parts[0].oid()), parts[1].children().joinToString(", ") { valueText(it) })
            }
        },
        X509Names.QC_STATEMENTS to ::qcStatements,
        X509Names.SCT_LIST to ::signedCertificateTimestamps,
        X509Names.OCSP_NO_CHECK to { _ -> listOf(ExtField("id-pkix-ocsp-nocheck", "NULL")) },
        X509Names.CT_PRECERT_POISON to { _ -> listOf(ExtField("poison", "NULL")) },
        X509Names.ICAO_NAME_CHANGE to { d -> listOf(ExtField("nameChange", if (d.isUniversal(Der.NULL)) "NULL" else d.outline())) },
        X509Names.TLS_FEATURE to { d ->
            d.children().map { f ->
                val v = f.long()
                ExtField("Feature", when (v) { 5L -> "status_request (5)"; 17L -> "status_request_v2 (17)"; else -> v.toString() })
            }
        },
        X509Names.ICAO_DOCUMENT_TYPE_LIST to { d ->
            val parts = d.children()
            listOf(ExtField("version", parts[0].long().toString())) +
                parts[1].children().map { ExtField("docType", it.string()) }
        },
        X509Names.MS_TEMPLATE_V2 to { d ->
            val parts = d.children()
            listOfNotNull(
                ExtField("templateID", X509Names.label(parts[0].oid())),
                parts.getOrNull(1)?.let { ExtField("templateMajorVersion", it.long().toString()) },
                parts.getOrNull(2)?.let { ExtField("templateMinorVersion", it.long().toString()) },
            )
        },
        X509Names.MS_CA_VERSION to { d ->
            val v = d.long()
            listOf(ExtField("certificate index", (v and 0xFFFF).toString()), ExtField("key index", (v shr 16).toString()))
        },
        X509Names.MS_TEMPLATE_NAME to { d -> listOf(ExtField("name", valueText(d))) },
        X509Names.MS_APPLICATION_POLICIES to { d ->
            d.children().map { p -> ExtField("policyIdentifier", X509Names.label(p.children().first().oid())) }
        },
        X509Names.NETSCAPE_CERT_TYPE to { d ->
            val names = listOf("SSL client", "SSL server", "S/MIME", "Object Signing", "Reserved", "SSL CA", "S/MIME CA", "Object Signing CA")
            names.indices.filter { d.bit(it) }.map { ExtField("netscape-cert-type", names[it]) }
        },
        X509Names.NETSCAPE_COMMENT to { d -> listOf(ExtField("netscape-comment", valueText(d))) },
    )

    fun knows(oid: String): Boolean = oid in decoders

    /** The fields of extension [oid] with DER [value]; null when the extension is unknown. Throws when it is malformed. */
    fun decode(oid: String, value: ByteArray): List<ExtField>? {
        val decoder = decoders[oid] ?: return null
        return decoder(Der.parse(value))
    }

    private fun unsigned(b: ByteArray): Long {
        var v = 0L
        for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
        return v
    }

    private fun generalizedTime(content: ByteArray): Instant {
        val s = content.decodeToString()
        return Instant.parse("${s.substring(0, 4)}-${s.substring(4, 6)}-${s.substring(6, 8)}T${s.substring(8, 10)}:${s.substring(10, 12)}:${s.substring(12, 14)}Z")
    }

    private fun valueText(d: Der): String = when {
        d.isString -> d.string()
        d.isUniversal(Der.UTC_TIME) || d.isUniversal(Der.GENERALIZED_TIME) -> d.time().toString()
        d.isUniversal(Der.OID) -> X509Names.label(d.oid())
        else -> d.outline()
    }

    private fun names(d: Der): List<ExtField> = X509Details.generalNames(d).map { ExtField(it.type.specName, it.value) }

    private fun authorityKeyIdentifier(d: Der): List<ExtField> = d.children().mapNotNull { c ->
        when {
            c.isContext(0) -> ExtField("keyIdentifier", Der.colonHex(c.content))
            c.isContext(1) -> ExtField("authorityCertIssuer", X509Details.generalNames(c).joinToString("; ") { it.text })
            c.isContext(2) -> ExtField("authorityCertSerialNumber", Der.colonHex(c.content))
            else -> null
        }
    }

    private fun nameConstraints(d: Der): List<ExtField> = d.children().flatMap { c ->
        val label = if (c.isContext(0)) "permittedSubtrees" else "excludedSubtrees"
        c.children().map { subtree ->
            val parts = subtree.children()
            val base = X509Details.generalName(parts[0])
            val range = parts.drop(1).mapNotNull { p ->
                when {
                    p.isContext(0) -> "minimum ${unsigned(p.content)}"
                    p.isContext(1) -> "maximum ${unsigned(p.content)}"
                    else -> null
                }
            }
            ExtField(label, base.text + if (range.isEmpty()) "" else " (" + range.joinToString(", ") + ")")
        }
    }

    private fun certificatePolicies(d: Der): List<ExtField> = d.children().flatMap { info ->
        val parts = info.children()
        val out = mutableListOf(ExtField("policyIdentifier", X509Names.label(parts[0].oid())))
        parts.getOrNull(1)?.children()?.forEach { q ->
            val qp = q.children()
            when (qp[0].oid()) {
                "1.3.6.1.5.5.7.2.1" -> out.add(ExtField("cPSuri", qp[1].string()))
                "1.3.6.1.5.5.7.2.2" -> qp.getOrNull(1)?.children()?.forEach { n ->
                    if (n.isUniversal(Der.SEQUENCE)) {
                        val ref = n.children()
                        out.add(ExtField("noticeRef", ref[0].string() + " " + ref[1].children().joinToString(",") { it.long().toString() }))
                    } else if (n.isString) out.add(ExtField("explicitText", n.string()))
                }
                else -> out.add(ExtField(X509Names.label(qp[0].oid()), qp.getOrNull(1)?.let { valueText(it) } ?: ""))
            }
        }
        out
    }

    private fun distributionPoints(d: Der): List<ExtField> = d.children().flatMap { dp ->
        val out = mutableListOf<ExtField>()
        for (c in dp.children()) {
            when {
                c.isContext(0) -> {
                    val name = c.children().first()
                    if (name.isContext(0)) X509Details.generalNames(name).forEach { out.add(ExtField("distributionPoint fullName", it.text)) }
                    else out.add(ExtField("distributionPoint nameRelativeToCRLIssuer", name.outline()))
                }
                c.isContext(1) -> {
                    val reasons = listOf("unused", "keyCompromise", "cACompromise", "affiliationChanged", "superseded",
                        "cessationOfOperation", "certificateHold", "privilegeWithdrawn", "aACompromise")
                    out.add(ExtField("reasons", reasons.indices.filter { bitOf(c.content, it) }.joinToString(", ") { reasons[it] }))
                }
                c.isContext(2) -> X509Details.generalNames(c).forEach { out.add(ExtField("cRLIssuer", it.text)) }
            }
        }
        out
    }

    private fun bitOf(content: ByteArray, n: Int): Boolean {
        val i = 1 + n / 8
        return i < content.size && (content[i].toInt() shr (7 - n % 8)) and 1 == 1
    }

    private fun accessDescriptions(d: Der): List<ExtField> = d.children().map { a ->
        val parts = a.children()
        ExtField(X509Names.label(parts[0].oid()), X509Details.generalName(parts[1]).text)
    }

    private fun qcStatements(d: Der): List<ExtField> = d.children().flatMap { s ->
        val parts = s.children()
        val id = parts[0].oid()
        val info = parts.getOrNull(1)
        val label = X509Names.label(id)
        if (info == null) return@flatMap listOf(ExtField("statementId", label))
        val details: List<String> = when (id) {
            "0.4.0.1862.1.6" -> info.children().map { X509Names.label(it.oid()) }
            "0.4.0.1862.1.5" -> info.children().map { p -> p.children().let { it[0].string() + " (" + it[1].string() + ")" } }
            "0.4.0.1862.1.3" -> listOf(info.long().toString() + " years")
            "0.4.0.1862.1.2" -> info.children().let { v ->
                val currency = if (v[0].isString) v[0].string() else v[0].long().toString()
                listOf("$currency ${v[1].long()} x 10^${v[2].long()}")
            }
            "0.4.0.1862.1.7" -> info.children().map { it.string() }
            "1.3.6.1.5.5.7.11.1", "1.3.6.1.5.5.7.11.2" -> info.children().map { p ->
                if (p.isUniversal(Der.OID)) "semanticsIdentifier " + X509Names.label(p.oid())
                else "nameRegistrationAuthorities " + X509Details.generalNames(p).joinToString("; ") { it.text }
            }
            "0.4.0.19495.2" -> info.children().map { p ->
                if (p.isUniversal(Der.SEQUENCE)) "rolesOfPSP " + p.children().joinToString(", ") { r -> r.children().let { X509Names.label(it[0].oid()) + " " + it[1].string() } }
                else valueText(p)
            }
            else -> listOf(info.outline())
        }
        listOf(ExtField("statementId", label)) + details.map { ExtField("statementInfo", it) }
    }

    /** SignedCertificateTimestampList (RFC 6962 3.3): the TLS-encoded list inside an OCTET STRING. */
    private fun signedCertificateTimestamps(d: Der): List<ExtField> {
        val b = d.content
        fun u16(i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
        val out = mutableListOf<ExtField>()
        var pos = 2
        val end = 2 + u16(0)
        while (pos + 2 <= end && pos + 2 <= b.size) {
            val len = u16(pos)
            val sct = pos + 2
            if (sct + len > b.size || len < 43) break
            val version = b[sct].toInt() and 0xFF
            val logId = b.copyOfRange(sct + 1, sct + 33)
            var ts = 0L
            for (k in 0 until 8) ts = (ts shl 8) or (b[sct + 33 + k].toLong() and 0xFF)
            out.add(ExtField("SignedCertificateTimestamp", "v${version + 1} logID ${Der.hex(logId)} timestamp ${Instant.fromEpochMilliseconds(ts)}"))
            pos = sct + len
        }
        return out
    }
}

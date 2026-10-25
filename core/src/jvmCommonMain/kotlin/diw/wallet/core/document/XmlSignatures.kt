package diw.wallet.core.document

import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.cert.X509CertificateHolder
import org.w3c.dom.Document
import org.w3c.dom.Element
import java.math.BigInteger
import java.util.Base64
import kotlin.time.Clock
import kotlin.time.Instant

/** XML Signature (XMLDSig 1.0/1.1) and XAdES (ETSI EN 319 132) verification and enveloped signing. */
internal object XmlDsig {
    const val DS = "http://www.w3.org/2000/09/xmldsig#"
    const val XADES = "http://uri.etsi.org/01903/v1.3.2#"
    const val XADES141 = "http://uri.etsi.org/01903/v1.4.1#"
    const val ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    const val BASE64 = "http://www.w3.org/2000/09/xmldsig#base64"
    const val FILTER2 = "http://www.w3.org/2002/06/xmldsig-filter2"
    const val SIGNED_PROPERTIES_TYPE = "http://uri.etsi.org/01903#SignedProperties"
    const val SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
    const val RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    const val ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"

    fun digestName(uri: String?): String? = when (uri) {
        "http://www.w3.org/2000/09/xmldsig#sha1" -> "SHA-1"
        "http://www.w3.org/2001/04/xmldsig-more#sha224" -> "SHA-224"
        // The online approval files (.si) of Taiwan's official documents write SHA-256 under the xmldsig-more namespace.
        SHA256, "http://www.w3.org/2001/04/xmldsig-more#sha256" -> "SHA-256"
        "http://www.w3.org/2001/04/xmldsig-more#sha384" -> "SHA-384"
        "http://www.w3.org/2001/04/xmlenc#sha512" -> "SHA-512"
        "http://www.w3.org/2007/05/xmldsig-more#sm3", "http://www.w3.org/2001/04/xmldsig-more#sm3" -> "SM3"
        else -> null
    }

    /** JCA signature name and whether the value is raw r||s (XML ECDSA) for a SignatureMethod URI. */
    fun signatureName(uri: String?): Pair<String, Boolean>? = when (uri) {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" -> "SHA1withRSA" to false
        RSA_SHA256 -> "SHA256withRSA" to false
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" -> "SHA384withRSA" to false
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" -> "SHA512withRSA" to false
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1" -> "SHA1withECDSA" to true
        ECDSA_SHA256 -> "SHA256withECDSA" to true
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" -> "SHA384withECDSA" to true
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" -> "SHA512withECDSA" to true
        // RSASSA-PSS with MGF1 of the same digest and a salt of the digest length (RFC 6931 2.3.10).
        "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" -> "SHA256withRSAandMGF1" to false
        "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1" -> "SHA384withRSAandMGF1" to false
        "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1" -> "SHA512withRSAandMGF1" to false
        "http://www.w3.org/2007/05/xmldsig-more#sm2-sm3", "http://www.w3.org/2001/04/xmldsig-more#sm2-sm3" -> "SM3withSM2" to false
        else -> null
    }

    fun rawToDer(raw: ByteArray): ByteArray {
        val half = raw.size / 2
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(0, half))))
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(half, raw.size))))
        return DERSequence(v).encoded
    }

    fun derToRaw(der: ByteArray, size: Int = 32): ByteArray {
        val seq = ASN1Sequence.getInstance(der)
        fun fixed(i: BigInteger): ByteArray {
            val b = i.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(size - b.size) + b
        }
        return fixed(ASN1Integer.getInstance(seq.getObjectAt(0)).value) + fixed(ASN1Integer.getInstance(seq.getObjectAt(1)).value)
    }

    /**
     * Verifies every ds:Signature in [bytes]. [resolve] returns the content of a detached reference (a file in the
     * same container), or null when it is not available.
     */
    suspend fun verify(
        bytes: ByteArray,
        label: String,
        checks: CmsChecks,
        now: Instant,
        resolve: (String) -> ByteArray? = { null },
    ): List<SignatureInfo> {
        val doc = XmlParsing.parse(bytes)
        val sigs = XmlParsing.descendants(doc, DS, "Signature").filter { XmlParsing.child(it, DS, "SignedInfo") != null }
        return sigs.mapIndexed { i, s -> verifyOne(doc, s, if (sigs.size > 1) "$label（簽章 ${i + 1}）" else label, checks, now, resolve) }
    }

    private suspend fun verifyOne(
        doc: Document,
        sig: Element,
        label: String,
        checks: CmsChecks,
        now: Instant,
        resolve: (String) -> ByteArray?,
    ): SignatureInfo {
        val checked = integrity(doc, sig, resolve)
        val problems = checked.problems
        val notes = checked.notes
        val qp = checked.qualifyingProperties
        val format = if (qp != null) SignatureFormat.XADES else SignatureFormat.XMLDSIG
        val certs = checked.certificates
        val signer = checked.signer
        val integrity = checked.integrity
        val coversWhole = checked.coversWhole
        val method = checked.method
        val alg = signatureName(method)

        // XAdES properties: signing time, signing certificate, signature time stamp, validation data.
        var claimed: Long? = null
        var timestamp: TimestampInfo? = null
        val ocsps = ArrayList<ByteArray>()
        val crls = ArrayList<ByteArray>()
        val extra = ArrayList<X509CertificateHolder>()
        val archives = ArrayList<TimestampInfo>()
        if (qp != null) {
            XmlParsing.descendants(qp, null, "SigningTime").firstOrNull()?.let { claimed = runCatching { Instant.parse(it.textContent.trim()).epochSeconds }.getOrNull() }
            val certDigests = XmlParsing.descendants(qp, null, "CertDigest")
            if (signer != null && certDigests.isNotEmpty()) {
                val bound = certDigests.any { cd ->
                    val a = digestName(XmlParsing.child(cd, DS, "DigestMethod")?.getAttribute("Algorithm")) ?: return@any false
                    val v = runCatching { Base64.getMimeDecoder().decode(XmlParsing.text(XmlParsing.child(cd, DS, "DigestValue")).orEmpty()) }.getOrNull()
                    v != null && DocCrypto.digest(a, signer.encoded).contentEquals(v)
                }
                if (!bound) problems.add("XAdES 簽署憑證屬性與附上的憑證不符")
            } else if (signer != null) notes.add("XAdES 沒有簽署憑證屬性（SigningCertificate）")
            XmlParsing.descendants(qp, null, "SignatureTimeStamp").firstOrNull()?.let { ts ->
                val token = XmlParsing.descendants(ts, null, "EncapsulatedTimeStamp").firstOrNull()?.textContent?.trim()
                    ?.let { runCatching { Base64.getMimeDecoder().decode(it) }.getOrNull() }
                val sv = XmlParsing.child(sig, DS, "SignatureValue")
                if (token != null && sv != null) {
                    val alg2 = XmlParsing.child(ts, DS, "CanonicalizationMethod")?.getAttribute("Algorithm")?.takeIf { it in XmlC14n.supported } ?: XmlC14n.C14N
                    timestamp = checks.timestamp(token, XmlC14n.canonicalize(sv, alg2))
                }
            }
            // Archive time stamps (B-LTA), each over the signature and the unsigned properties before it.
            XmlParsing.descendants(qp, null, "ArchiveTimeStamp").forEach { ats ->
                val token = XmlParsing.descendants(ats, null, "EncapsulatedTimeStamp").firstOrNull()?.textContent?.trim()
                    ?.let { runCatching { Base64.getMimeDecoder().decode(it) }.getOrNull() } ?: return@forEach
                val alg2 = XmlParsing.child(ats, DS, "CanonicalizationMethod")?.getAttribute("Algorithm")?.takeIf { it in XmlC14n.supported } ?: XmlC14n.C14N
                val input = archiveInput(doc, sig, ats, alg2, resolve)
                if (input == null) notes.add("保存時戳涵蓋的檔案不在檔案內，無法檢查")
                else archives.add(checks.timestamp(token, input))
            }
            XmlParsing.descendants(qp, null, "EncapsulatedOCSPValue").forEach { e -> runCatching { ocsps.add(Base64.getMimeDecoder().decode(e.textContent.trim())) } }
            XmlParsing.descendants(qp, null, "EncapsulatedCRLValue").forEach { e -> runCatching { crls.add(Base64.getMimeDecoder().decode(e.textContent.trim())) } }
            XmlParsing.descendants(qp, null, "EncapsulatedX509Certificate").forEach { e ->
                runCatching { Bc.holder(Base64.getMimeDecoder().decode(e.textContent.trim()))?.let { extra.add(it) } }
            }
        }
        if (method == "http://www.w3.org/2000/09/xmldsig#rsa-sha1") notes.add("使用較弱的簽章演算法 RSA SHA-1")
        if (qp != null) {
            notes.add("XAdES 等級：" + baselineLevel(timestamp != null, ocsps.isNotEmpty() || crls.isNotEmpty(), archives.isNotEmpty()))
            archives.forEach { notes.add(archiveNote(it)) }
            archives.filter { it.imprint == Check.FAIL || it.signature == Check.FAIL }.forEach { problems.add("保存時戳無效：" + it.problems.joinToString("；")) }
        }
        return checks.evaluate(
            format = format,
            label = label,
            algorithm = alg?.first?.replace("with", " ")?.replace("SHA", "SHA-"),
            signer = signer,
            pool = certs + extra,
            integrity = integrity,
            claimed = claimed,
            timestamp = timestamp,
            ocsps = ocsps,
            crls = crls,
            now = now,
            problems = problems,
            notes = notes,
            coversWhole = coversWhole,
        )
    }

    /** The baseline level a signature reaches: B-B, B-T (signature time stamp), B-LT (revocation data), B-LTA (archive time stamp). */
    fun baselineLevel(timestamp: Boolean, revocation: Boolean, archive: Boolean): String = when {
        timestamp && revocation && archive -> "B-LTA"
        timestamp && revocation -> "B-LT"
        timestamp -> "B-T"
        else -> "B-B"
    }

    /** One line on an archive time stamp for the report. */
    fun archiveNote(ts: TimestampInfo): String {
        val ok = ts.imprint == Check.PASS && ts.signature == Check.PASS
        val time = kotlin.time.Instant.fromEpochSeconds(ts.time).toString().replace('T', ' ').removeSuffix("Z") + " UTC"
        return "保存時戳（${ts.tsa ?: "時戳機構"}，$time）" + if (ok) "涵蓋簽章與長期驗證資料，檢查通過" else "檢查未通過"
    }

    /** What the integrity check of one signature found; [integrity] covers every reference and the signature value. */
    class Integrity(
        val integrity: Check,
        val problems: MutableList<String>,
        val notes: MutableList<String>,
        val signer: X509CertificateHolder?,
        val certificates: List<X509CertificateHolder>,
        val coversWhole: Boolean,
        val method: String?,
        val qualifyingProperties: Element?,
    )

    /**
     * Checks [sig] of [doc] for integrity only: each reference digest (detached references through [resolve]) and the
     * signature value over the canonical SignedInfo with the first certificate in KeyInfo.
     */
    fun integrity(doc: Document, sig: Element, resolve: (String) -> ByteArray? = { null }, ns: String? = DS): Integrity {
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val signedInfo = XmlParsing.child(sig, ns, "SignedInfo")!!
        val c14nEl = XmlParsing.child(signedInfo, ns, "CanonicalizationMethod")
        val c14n = c14nEl?.getAttribute("Algorithm").orEmpty()
        val method = XmlParsing.child(signedInfo, ns, "SignatureMethod")?.getAttribute("Algorithm")
        val qp = XmlParsing.descendants(sig, null, "QualifyingProperties").firstOrNull { it.namespaceURI == XADES || it.namespaceURI == XADES141 || it.namespaceURI?.startsWith("http://uri.etsi.org/01903") == true }
        val certs = XmlParsing.descendants(sig, ns, "X509Certificate").mapNotNull { e ->
            runCatching { Base64.getMimeDecoder().decode(e.textContent.trim()) }.getOrNull()?.let { Bc.holder(it) }
        }
        val signer = certs.firstOrNull()

        // References.
        var integrity = Check.PASS
        var coversWhole = false
        var signedPropsCovered = false
        val signedProps = qp?.let { XmlParsing.descendants(it, null, "SignedProperties").firstOrNull() }
        for (ref in XmlParsing.childrenNamed(signedInfo, ns, "Reference")) {
            val uri = if (ref.hasAttribute("URI")) ref.getAttribute("URI") else null
            val transforms = XmlParsing.child(ref, ns, "Transforms")?.let { XmlParsing.childrenNamed(it, ns, "Transform") }.orEmpty()
            val digestAlg = digestName(XmlParsing.child(ref, ns, "DigestMethod")?.getAttribute("Algorithm"))
            val expected = runCatching { Base64.getMimeDecoder().decode(XmlParsing.text(XmlParsing.child(ref, ns, "DigestValue")).orEmpty()) }.getOrNull()
            if (digestAlg == null || expected == null) { problems.add("參照 ${uri ?: ""} 的摘要演算法不支援"); integrity = worst(integrity, Check.NOT_CHECKED); continue }
            val data: ByteArray? = try {
                referenceData(doc, sig, uri, transforms, resolve)
            } catch (e: UnsupportedOperationException) {
                problems.add(e.message ?: "不支援的轉換"); integrity = worst(integrity, Check.NOT_CHECKED); continue
            }
            if (data == null) {
                notes.add("參照的檔案「${uri ?: ""}」不在檔案內，無法檢查")
                integrity = worst(integrity, Check.NOT_CHECKED)
                continue
            }
            if (!DocCrypto.digest(digestAlg, data).contentEquals(expected)) {
                problems.add("參照「${uri?.ifEmpty { "整份文件" } ?: "整份文件"}」的內容在簽署後被修改")
                integrity = Check.FAIL
            }
            if (uri == "" && transforms.any { it.getAttribute("Algorithm") in setOf(ENVELOPED, FILTER2) }) coversWhole = true
            if (uri != null && uri.startsWith("#") && signedProps != null && signedProps.getAttribute("Id") == uri.removePrefix("#")) signedPropsCovered = true
            if (uri != null && uri.startsWith("#")) {
                val target = XmlParsing.byId(doc, uri.removePrefix("#"))
                if (target != null && target === doc.documentElement) coversWhole = true
            }
        }
        if (qp != null && signedProps != null && !signedPropsCovered) problems.add("XAdES 的簽署屬性沒有被簽章涵蓋")

        // Signature value over the canonical SignedInfo.
        val alg = signatureName(method)
        val value = runCatching { Base64.getMimeDecoder().decode(XmlParsing.text(XmlParsing.child(sig, ns, "SignatureValue")).orEmpty()) }.getOrNull()
        when {
            signer == null -> { problems.add("簽章沒有附上簽署者憑證"); integrity = worst(integrity, Check.NOT_CHECKED) }
            alg == null || value == null -> { problems.add("不支援的簽章演算法 $method"); integrity = worst(integrity, Check.NOT_CHECKED) }
            c14n !in XmlC14n.supported -> { problems.add("不支援的標準化方法 $c14n"); integrity = worst(integrity, Check.NOT_CHECKED) }
            else -> {
                val prefixes = inclusivePrefixes(c14nEl)
                val canonical = XmlC14n.canonicalize(signedInfo, c14n, inclusivePrefixes = prefixes)
                val sigBytes = if (alg.second) runCatching { rawToDer(value) }.getOrDefault(value) else value
                val ok = runCatching {
                    val key = org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(signer).publicKey
                    val s = java.security.Signature.getInstance(alg.first, Bc.provider)
                    s.initVerify(key)
                    s.update(canonical)
                    s.verify(sigBytes)
                }.getOrDefault(false)
                if (!ok) { problems.add("簽章值不符"); integrity = Check.FAIL }
            }
        }

        return Integrity(integrity, problems, notes, signer, certs, coversWhole, method, qp)
    }

    /**
     * The certificate that signed [bytes] with an enveloped signature covering the whole document (a trusted list),
     * when the signature is intact; null otherwise. The certificate's trust is for the caller to decide.
     */
    fun envelopedSigner(bytes: ByteArray): X509CertificateHolder? {
        val doc = XmlParsing.parse(bytes)
        val sig = XmlParsing.childrenNamed(doc.documentElement, DS, "Signature").firstOrNull() ?: return null
        val r = integrity(doc, sig)
        return r.signer.takeIf { r.integrity == Check.PASS && r.coversWhole }
    }

    private fun withoutComments(alg: String): String = when (alg) {
        XmlC14n.EXC_COMMENTS -> XmlC14n.EXC
        XmlC14n.C14N_COMMENTS -> XmlC14n.C14N
        XmlC14n.C14N11_COMMENTS -> XmlC14n.C14N11
        else -> alg
    }

    private fun worst(a: Check, b: Check): Check = if (a == Check.FAIL || b == Check.FAIL) Check.FAIL else if (a == Check.PASS) b else a

    private fun inclusivePrefixes(method: Element?): Set<String> = method?.let {
        XmlParsing.descendants(it, null, "InclusiveNamespaces").firstOrNull()?.getAttribute("PrefixList")
    }?.split(' ', '\t', '\n')?.filter { it.isNotBlank() }?.toSet().orEmpty()

    private fun referenceData(doc: Document, sig: Element, uri: String?, transforms: List<Element>, resolve: (String) -> ByteArray?): ByteArray? {
        // Same-document references are node sets; detached ones are octets.
        var nodeSet: org.w3c.dom.Node? = null
        var octets: ByteArray? = null
        when {
            uri == null -> return resolve("")
            uri == "" -> nodeSet = doc
            uri.startsWith("#xpointer(id(") -> nodeSet = XmlParsing.byId(doc, uri.substringAfter("id(").trim('\'', '"', ')', ' ').substringBefore("'").substringBefore("\"")) ?: return null
            uri == "#xpointer(/)" -> nodeSet = doc
            uri.startsWith("#") -> nodeSet = XmlParsing.byId(doc, uri.removePrefix("#")) ?: return null
            // A file name as written first (official document names may hold "+" or "%"), then URI-decoded.
            else -> octets = resolve(uri) ?: runCatching { resolve(java.net.URLDecoder.decode(uri, "UTF-8")) }.getOrNull() ?: return null
        }
        val exclude = ArrayList<org.w3c.dom.Node>()
        for (t in transforms) {
            val alg = t.getAttribute("Algorithm")
            when {
                alg == ENVELOPED -> exclude.add(sig)
                alg == FILTER2 -> {
                    // XPath Filter 2.0 as signers use it: subtract this signature or every signature.
                    for (x in XmlParsing.children(t)) {
                        val expr = x.textContent.trim()
                        when {
                            x.getAttribute("Filter") != "subtract" -> throw UnsupportedOperationException("不支援的 XPath 篩選 ${x.getAttribute("Filter")}")
                            expr.matches(Regex("/descendant::\\w*:?Signature")) -> exclude.addAll(XmlParsing.descendants(doc, DS, "Signature"))
                            expr.matches(Regex("here\\(\\)/ancestor::\\w*:?Signature\\[1]")) -> exclude.add(sig)
                            else -> throw UnsupportedOperationException("不支援的 XPath 篩選 $expr")
                        }
                    }
                }
                alg in XmlC14n.supported -> {
                    val node = nodeSet ?: octets?.let { XmlParsing.parse(it) } ?: return null
                    // URI="" and bare-name references never keep comments (XMLDSig 4.4.3.3).
                    val sameDocument = uri == "" || (uri != null && uri.startsWith("#") && !uri.startsWith("#xpointer"))
                    octets = XmlC14n.canonicalize(node, if (sameDocument) withoutComments(alg) else alg, exclude, inclusivePrefixes(t))
                    nodeSet = null
                }
                alg == BASE64 -> {
                    val text = nodeSet?.textContent ?: octets?.decodeToString() ?: return null
                    octets = Base64.getMimeDecoder().decode(text.filter { !it.isWhitespace() })
                    nodeSet = null
                }
                else -> throw UnsupportedOperationException("不支援的轉換 $alg")
            }
        }
        if (nodeSet != null) octets = XmlC14n.canonicalize(nodeSet, XmlC14n.C14N, exclude)
        return octets
    }

    /**
     * The data an xadesv141:ArchiveTimeStamp covers (ETSI EN 319 132-1 5.5.2.2): the processed data of each reference
     * in order, then SignedInfo, SignatureValue and KeyInfo, the unsigned signature properties before [ats] (all of
     * them when it is null), and any ds:Object other than the one with the qualifying properties, each canonicalized
     * with [c14n]. Null when a reference cannot be read.
     */
    fun archiveInput(doc: Document, sig: Element, ats: Element?, c14n: String, resolve: (String) -> ByteArray? = { null }): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val signedInfo = XmlParsing.child(sig, DS, "SignedInfo") ?: return null
        for (ref in XmlParsing.childrenNamed(signedInfo, DS, "Reference")) {
            val uri = if (ref.hasAttribute("URI")) ref.getAttribute("URI") else null
            val transforms = XmlParsing.child(ref, DS, "Transforms")?.let { XmlParsing.childrenNamed(it, DS, "Transform") }.orEmpty()
            out.write(runCatching { referenceData(doc, sig, uri, transforms, resolve) }.getOrNull() ?: return null)
        }
        out.write(XmlC14n.canonicalize(signedInfo, c14n))
        XmlParsing.child(sig, DS, "SignatureValue")?.let { out.write(XmlC14n.canonicalize(it, c14n)) }
        XmlParsing.child(sig, DS, "KeyInfo")?.let { out.write(XmlC14n.canonicalize(it, c14n)) }
        XmlParsing.descendants(sig, null, "UnsignedSignatureProperties").firstOrNull()?.let { usp ->
            for (c in XmlParsing.children(usp)) {
                if (c === ats) break
                out.write(XmlC14n.canonicalize(c, c14n))
            }
        }
        for (o in XmlParsing.childrenNamed(sig, DS, "Object")) {
            if (XmlParsing.descendants(o, null, "QualifyingProperties").isEmpty()) out.write(XmlC14n.canonicalize(o, c14n))
        }
        return out.toByteArray()
    }

    /**
     * Signs [xml] with an enveloped XAdES baseline signature (B-B, or B-T when [timestamper] is given): exclusive
     * canonicalization, SHA-256, the signer certificate chain in KeyInfo, SigningTime and SigningCertificateV2.
     * The signature is inserted as the last child of the root element, without touching the rest of the file.
     */
    suspend fun signEnveloped(
        xml: ByteArray,
        signer: DocumentSigner,
        now: Instant = Clock.System.now(),
        timestamper: (suspend (ByteArray) -> ByteArray)? = null,
        /** Validation data for the signer and the time-stamp authority of the token (baseline LT), when wanted. */
        validation: (suspend (ByteArray?) -> diw.wallet.core.document.sign.ValidationData)? = null,
        /** Add an ArchiveTimeStamp over the signature and its validation data (B-LTA); needs [timestamper]. */
        archive: Boolean = false,
    ): ByteArray {
        if (archive && timestamper == null) throw IllegalArgumentException("B-LTA 需要時戳機構")
        val text = xml.decodeToString().removePrefix("﻿")
        val declared = Regex("<\\?xml[^>]*encoding=[\"']([^\"']+)[\"']").find(text.take(200))?.groupValues?.get(1)
        if (declared != null && !declared.equals("UTF-8", true) && !declared.equals("UTF8", true)) throw IllegalArgumentException("只能簽署 UTF-8 編碼的 XML（此檔案為 $declared）")
        val doc0 = XmlParsing.parse(xml)
        val root = doc0.documentElement ?: throw IllegalArgumentException("XML 沒有根元素")
        val endTag = "</" + root.nodeName
        val insertAt = text.lastIndexOf(endTag)
        if (insertAt < 0) throw IllegalArgumentException("XML 的根元素沒有結束標籤")
        val id = DocCryptoUtil.hex(DocCrypto.randomBytes(8))
        val certs = signer.certificateChain
        val leaf = certs.first()
        val method = if (signer.keyType == SignerKeyType.RSA) RSA_SHA256 else ECDSA_SHA256
        val b64 = Base64.getEncoder()
        val time = Instant.fromEpochSeconds(now.epochSeconds).toString()
        fun signature(docDigest: String, propDigest: String, value: String, unsigned: String) = buildString {
            append("<ds:Signature xmlns:ds=\"$DS\" Id=\"sig-$id\">")
            append("<ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"${XmlC14n.EXC}\"/><ds:SignatureMethod Algorithm=\"$method\"/>")
            append("<ds:Reference Id=\"ref-$id\" URI=\"\"><ds:Transforms><ds:Transform Algorithm=\"$ENVELOPED\"/><ds:Transform Algorithm=\"${XmlC14n.EXC}\"/></ds:Transforms>")
            append("<ds:DigestMethod Algorithm=\"$SHA256\"/><ds:DigestValue>$docDigest</ds:DigestValue></ds:Reference>")
            append("<ds:Reference Type=\"$SIGNED_PROPERTIES_TYPE\" URI=\"#xades-$id\"><ds:Transforms><ds:Transform Algorithm=\"${XmlC14n.EXC}\"/></ds:Transforms>")
            append("<ds:DigestMethod Algorithm=\"$SHA256\"/><ds:DigestValue>$propDigest</ds:DigestValue></ds:Reference></ds:SignedInfo>")
            append("<ds:SignatureValue Id=\"value-$id\">$value</ds:SignatureValue>")
            append("<ds:KeyInfo><ds:X509Data>")
            certs.forEach { append("<ds:X509Certificate>" + b64.encodeToString(it) + "</ds:X509Certificate>") }
            append("</ds:X509Data></ds:KeyInfo>")
            append("<ds:Object><xades:QualifyingProperties xmlns:xades=\"$XADES\" Target=\"#sig-$id\"><xades:SignedProperties Id=\"xades-$id\"><xades:SignedSignatureProperties>")
            append("<xades:SigningTime>$time</xades:SigningTime><xades:SigningCertificateV2><xades:Cert><xades:CertDigest>")
            append("<ds:DigestMethod Algorithm=\"$SHA256\"/><ds:DigestValue>" + b64.encodeToString(DocCrypto.digest("SHA-256", leaf)) + "</ds:DigestValue>")
            append("</xades:CertDigest></xades:Cert></xades:SigningCertificateV2></xades:SignedSignatureProperties>")
            // XAdES baseline B requires a DataObjectFormat for each signed data object (EN 319 132-1 6.3 k).
            append("<xades:SignedDataObjectProperties><xades:DataObjectFormat ObjectReference=\"#ref-$id\"><xades:MimeType>text/xml</xades:MimeType></xades:DataObjectFormat></xades:SignedDataObjectProperties></xades:SignedProperties>")
            append(unsigned)
            append("</xades:QualifyingProperties></ds:Object></ds:Signature>")
        }
        fun assemble(sigXml: String) = (text.substring(0, insertAt) + sigXml + text.substring(insertAt)).toByteArray(Charsets.UTF_8)

        // Digests of the document (signature excluded) and of the signed properties.
        val draft = XmlParsing.parse(assemble(signature("", "", "", "")))
        val draftSig = XmlParsing.descendants(draft, DS, "Signature").first { it.getAttribute("Id") == "sig-$id" }
        val docDigest = b64.encodeToString(DocCrypto.digest("SHA-256", XmlC14n.canonicalize(draft, XmlC14n.EXC, listOf(draftSig))))
        val props = XmlParsing.byId(draft, "xades-$id")!!
        val propDigest = b64.encodeToString(DocCrypto.digest("SHA-256", XmlC14n.canonicalize(props, XmlC14n.EXC)))

        // Signature over the canonical SignedInfo.
        val withDigests = XmlParsing.parse(assemble(signature(docDigest, propDigest, "", "")))
        val si = XmlParsing.descendants(withDigests, DS, "Signature").first { it.getAttribute("Id") == "sig-$id" }
            .let { XmlParsing.child(it, DS, "SignedInfo")!! }
        val raw = signer.sign(XmlC14n.canonicalize(si, XmlC14n.EXC))
        val value = b64.encodeToString(if (signer.keyType == SignerKeyType.EC_P256) derToRaw(raw) else raw)
        if (timestamper == null && validation == null) return assemble(signature(docDigest, propDigest, value, ""))

        // XAdES-T: a time stamp over the canonical SignatureValue element.
        val token = timestamper?.let { ts ->
            val signed = XmlParsing.parse(assemble(signature(docDigest, propDigest, value, "")))
            ts(XmlC14n.canonicalize(XmlParsing.byId(signed, "value-$id")!!, XmlC14n.EXC))
        }
        val unsigned = StringBuilder("<xades:UnsignedProperties><xades:UnsignedSignatureProperties>")
        token?.let {
            unsigned.append("<xades:SignatureTimeStamp><ds:CanonicalizationMethod Algorithm=\"${XmlC14n.EXC}\"/><xades:EncapsulatedTimeStamp>")
                .append(b64.encodeToString(it)).append("</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>")
        }
        // XAdES baseline LT: the certificates and revocation values of the signer and the time-stamp authority.
        validation?.invoke(token)?.let { v ->
            if (v.certificates.isNotEmpty()) {
                unsigned.append("<xades:CertificateValues>")
                v.certificates.forEach { unsigned.append("<xades:EncapsulatedX509Certificate>").append(it).append("</xades:EncapsulatedX509Certificate>") }
                unsigned.append("</xades:CertificateValues>")
            }
            if (!v.empty) {
                unsigned.append("<xades:RevocationValues>")
                if (v.crls.isNotEmpty()) {
                    unsigned.append("<xades:CRLValues>")
                    v.crls.forEach { unsigned.append("<xades:EncapsulatedCRLValue>").append(it).append("</xades:EncapsulatedCRLValue>") }
                    unsigned.append("</xades:CRLValues>")
                }
                if (v.ocsps.isNotEmpty()) {
                    unsigned.append("<xades:OCSPValues>")
                    v.ocsps.forEach { unsigned.append("<xades:EncapsulatedOCSPValue>").append(it).append("</xades:EncapsulatedOCSPValue>") }
                    unsigned.append("</xades:OCSPValues>")
                }
                unsigned.append("</xades:RevocationValues>")
            }
        }
        // An empty UnsignedSignatureProperties is not allowed; without a token or data nothing is added.
        if (unsigned.endsWith("<xades:UnsignedSignatureProperties>")) return assemble(signature(docDigest, propDigest, value, ""))
        val close = "</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
        // XAdES baseline LTA: an archive time stamp over the signature and everything before it.
        if (archive) {
            val draftLt = XmlParsing.parse(assemble(signature(docDigest, propDigest, value, unsigned.toString() + close)))
            val sigLt = XmlParsing.descendants(draftLt, DS, "Signature").first { it.getAttribute("Id") == "sig-$id" }
            val input = archiveInput(draftLt, sigLt, null, XmlC14n.EXC) ?: throw IllegalStateException("無法計算保存時戳涵蓋的資料")
            unsigned.append("<xadesv141:ArchiveTimeStamp xmlns:xadesv141=\"$XADES141\"><ds:CanonicalizationMethod Algorithm=\"${XmlC14n.EXC}\"/><xades:EncapsulatedTimeStamp>")
                .append(b64.encodeToString(timestamper!!(input))).append("</xades:EncapsulatedTimeStamp></xadesv141:ArchiveTimeStamp>")
        }
        unsigned.append(close)
        return assemble(signature(docDigest, propDigest, value, unsigned.toString()))
    }
}

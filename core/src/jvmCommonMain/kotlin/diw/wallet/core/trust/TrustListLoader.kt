package diw.wallet.core.trust

import diw.wallet.core.document.Bc
import diw.wallet.core.document.XmlDsig
import diw.wallet.core.document.XmlParsing
import diw.wallet.core.document.pdf.PdfArray
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfSignatures
import diw.wallet.core.document.pdf.PdfStream
import diw.wallet.core.document.pdf.PdfString
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.readRawBytes
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.isSuccess
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.multipaz.crypto.X509Cert
import org.w3c.dom.Element
import java.util.Base64
import kotlin.time.Clock
import kotlin.time.Instant

/** A trust list could not be fetched or did not verify. */
class TrustListException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Fetches and verifies the public trust lists:
 *
 * - AATL: Adobe's security settings PDF, whose signature must chain to the pinned Adobe Root CA G2 and cover the whole
 *   file; the trusted identities come from the SecuritySettings.xml it carries.
 * - EUTL: the EU list of trusted lists (ETSI TS 119 612), signed by a certificate pinned here or announced by the last
 *   verified list, then each national list signed by a certificate the EU list names for it. Qualified CAs for
 *   e-signatures and e-seals anchor document signatures, qualified time-stamp services anchor time stamps, each for the
 *   periods its supervisor granted it.
 *
 * Downloads are conditional (ETag, Last-Modified): an unchanged list is kept from [TrustListSnapshot] as it was.
 */
class TrustListLoader(
    private val http: HttpClient,
    private val now: () -> Instant = { Clock.System.now() },
    private val aatlUrl: String = AATL_URL,
    private val lotlUrl: String = LOTL_URL,
    private val adobeRootPins: Set<String> = ADOBE_ROOT_PINS,
    private val lotlSignerPins: Set<String> = LOTL_SIGNER_PINS,
    /** National lists fetched and parsed at once; each parsed list is held in memory as a DOM tree. */
    private val parallelism: Int = 4,
) {
    private class Fetched(val bytes: ByteArray?, val etag: String?, val lastModified: String?)

    private suspend fun fetch(url: String, etag: String?, lastModified: String?): Fetched {
        if (!url.startsWith("https://") && !url.startsWith("http://")) throw TrustListException("不支援的網址：$url")
        val resp: HttpResponse = http.get(url) {
            etag?.let { header(HttpHeaders.IfNoneMatch, it) }
            lastModified?.let { header(HttpHeaders.IfModifiedSince, it) }
        }
        if (resp.status == HttpStatusCode.NotModified) return Fetched(null, etag, lastModified)
        if (!resp.status.isSuccess()) throw TrustListException("HTTP ${resp.status.value}")
        val bytes = resp.readRawBytes()
        if (bytes.size > MAX_LIST_BYTES) throw TrustListException("清單超過 ${MAX_LIST_BYTES / 1024 / 1024} MB")
        return Fetched(bytes, resp.headers[HttpHeaders.ETag], resp.headers[HttpHeaders.LastModified])
    }

    /** The AATL, or [previous] with a new fetch time when Adobe reports it unchanged. */
    suspend fun aatl(previous: TrustListSnapshot?): TrustListSnapshot {
        val f = fetch(aatlUrl, previous?.etag, previous?.lastModified)
        val at = now().epochSeconds
        if (f.bytes == null && previous != null) return previous.copy(fetchedAt = at)
        val (services, signer) = aatlFromPdf(f.bytes ?: throw TrustListException("沒有內容"), adobeRootPins, now())
        return TrustListSnapshot(
            kind = TrustListKind.AATL.id, fetchedAt = at, etag = f.etag, lastModified = f.lastModified, signer = signer,
            parts = listOf(TrustListPart("AATL", aatlUrl, services = services)),
        )
    }

    /**
     * The EUTL. [territories] limits the national lists fetched (all when null); a national list that fails keeps its
     * previous services and records the error, so one unreachable member state does not drop the others.
     */
    suspend fun eutl(previous: TrustListSnapshot?, territories: Set<String>? = null): TrustListSnapshot = coroutineScope {
        val pins = lotlSignerPins + previous?.signerPins.orEmpty()
        val f = fetch(lotlUrl, previous?.etag, previous?.lastModified)
        val lotlBytes = f.bytes
        val lotl = if (lotlBytes != null) parseLotl(lotlBytes, pins) else null
        // An unchanged EU list leaves the national lists to be refreshed with the signers it named last time.
        val pointers = lotl?.pointers ?: previous?.parts?.map { Pointer(it.territory, it.url, it.signerPins.toSet()) }
            ?: throw TrustListException("沒有內容")
        val wanted = pointers.filter { territories == null || it.territory in territories }
        val before = previous?.parts.orEmpty().associateBy { it.territory }
        val gate = Semaphore(parallelism)
        val parts = wanted.map { p ->
            async {
                gate.withPermit {
                    val old = before[p.territory]
                    try {
                        // A list kept from before the signers were recorded waits for the next EU list.
                        if (p.signerPins.isEmpty()) return@withPermit old ?: TrustListPart(p.territory, p.url, error = "歐盟清單未更新")
                        val sameUrl = old?.url == p.url
                        val r = fetch(p.url, old?.etag?.takeIf { sameUrl }, old?.lastModified?.takeIf { sameUrl })
                        val bytes = r.bytes ?: return@withPermit old!!.copy(error = null, signerPins = p.signerPins.sorted())
                        parseTl(bytes, p, r.etag, r.lastModified)
                    } catch (e: Exception) {
                        if (e is kotlinx.coroutines.CancellationException) throw e
                        (old ?: TrustListPart(p.territory, p.url)).copy(error = e.message ?: e::class.simpleName)
                    }
                }
            }
        }.map { it.await() }
        TrustListSnapshot(
            kind = TrustListKind.EUTL.id,
            fetchedAt = now().epochSeconds,
            issued = lotl?.issued ?: previous?.issued,
            nextUpdate = lotl?.nextUpdate ?: previous?.nextUpdate,
            etag = f.etag,
            lastModified = f.lastModified,
            signer = lotl?.signer ?: previous?.signer,
            signerPins = lotl?.selfPins?.takeIf { it.isNotEmpty() } ?: previous?.signerPins.orEmpty(),
            parts = parts,
        )
    }

    /** A national list the EU list points to, with the certificates allowed to sign it. */
    class Pointer(val territory: String, val url: String, val signerPins: Set<String>)

    /** The verified EU list: where the national lists are, and the signers it announces for itself. */
    class Lotl(val pointers: List<Pointer>, val selfPins: List<String>, val issued: Long?, val nextUpdate: Long?, val signer: String)

    companion object {
        const val AATL_URL = "https://trustlist.adobe.com/tl12.acrobatsecuritysettings"
        const val LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"
        const val MAX_LIST_BYTES = 32 * 1024 * 1024

        /** SHA-256 of Adobe Root CA G2, the root of the certificate that signs the AATL. */
        val ADOBE_ROOT_PINS = setOf("458e0e219698b18d2d4093d6336a12547953a54c05dd967c3a5a268b772d1b22")

        /**
         * SHA-256 of the certificates the European Commission announced for signing the EU list of trusted lists
         * (the list's pointer to itself, as published in the Official Journal). Later lists may announce others, which
         * are trusted once a list signed with one of these has been verified.
         */
        val LOTL_SIGNER_PINS = setOf(
            "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
            "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
            "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
            "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
            "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
            "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
        )

        private const val TSL = "http://uri.etsi.org/02231/v2#"
        private const val SVC_TYPE = "http://uri.etsi.org/TrstSvc/Svctype/"
        private const val SVC_STATUS = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/"
        private const val TSL_MIME = "application/vnd.etsi.tsl+xml"
        private const val FOR_SIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"
        private const val FOR_SEALS = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals"
        private const val FOR_WEB = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"

        /** Statuses under which a service counted as qualified or approved (current and pre-eIDAS names). */
        private val GRANTED = setOf("granted", "undersupervision", "accredited", "supervisionincessation")

        /**
         * The trusted identities of the AATL security settings PDF [pdf]: its signature must cover the whole file and
         * chain to a certificate with one of [rootPins]. Returns the services and the signer's name.
         */
        fun aatlFromPdf(pdf: ByteArray, rootPins: Set<String>, at: Instant): Pair<List<ListedService>, String> {
            val file = PdfFile(pdf)
            val field = PdfSignatures(file).fields().firstOrNull { it.contents.isNotEmpty() } ?: throw TrustListException("AATL 沒有簽章")
            if (field.signedLength != pdf.size.toLong()) throw TrustListException("AATL 簽章後有變更")
            val cms = runCatching { CMSSignedData(CMSProcessableByteArray(field.signedData(pdf)), field.contents.trimDer()) }
                .getOrElse { throw TrustListException("AATL 簽章無法解析", it) }
            val certs = cms.certificates.getMatches(null).map { it as X509CertificateHolder }
            val info = cms.signerInfos.signers.firstOrNull() ?: throw TrustListException("AATL 沒有簽署者")
            val signer = certs.firstOrNull { info.sid.match(it) } ?: throw TrustListException("AATL 沒有附上簽署者憑證")
            val intact = runCatching { info.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(Bc.provider).build(signer)) }.getOrDefault(false)
            if (!intact) throw TrustListException("AATL 簽章值不符")
            val settings = embeddedFile(file, "SecuritySettings.xml") ?: throw TrustListException("AATL 沒有 SecuritySettings.xml")
            val services = parseAatl(settings)
            // The pinned root may come from the signature or from the list itself: only its fingerprint decides.
            val roots = (certs.map { it.encoded } + services.map { it.der }).filter { TrustLists.pin(it) in rootPins }
                .map { X509Cert(ByteString(it)) }
            val chain = arrayListOf(signer)
            while (chain.size < 8) {
                val cur = chain.last()
                if (cur.subject == cur.issuer) break
                chain.add(certs.firstOrNull { it !in chain && it.subject == cur.issuer } ?: break)
            }
            val anchor = Pkix.anchorOf(chain.map { X509Cert(ByteString(it.encoded)) }, roots, at)
                ?: throw TrustListException("AATL 簽署者沒有連到 Adobe Root CA G2")
            check(TrustLists.pin(anchor.encoded.toByteArray()) in rootPins)
            return services to (Bc.cn(signer) ?: signer.subject.toString())
        }

        /** The trusted identities of AATL SecuritySettings.xml, for document signatures and time stamps. */
        fun parseAatl(xml: ByteArray): List<ListedService> {
            val doc = XmlParsing.parse(xml)
            return XmlParsing.descendants(doc, null, "Identity").mapNotNull { id ->
                val b64 = XmlParsing.text(XmlParsing.child(id, null, "Certificate")) ?: return@mapNotNull null
                val der = runCatching { Base64.getMimeDecoder().decode(b64) }.getOrNull() ?: return@mapNotNull null
                val h = Bc.holder(der) ?: return@mapNotNull null
                val policies = XmlParsing.descendants(id, null, "CertificatePolicies").flatMap { cp ->
                    XmlParsing.descendants(cp, null, "OID").mapNotNull { XmlParsing.text(it)?.takeIf { s -> s.isNotEmpty() } }
                }
                ListedService(
                    certificate = TrustLists.encodeCertificate(der),
                    name = Bc.cn(h) ?: h.subject.toString(),
                    provider = Bc.org(h),
                    country = Bc.country(h),
                    roles = setOf(TrustRole.DOCUMENT.id, TrustRole.TSA.id),
                    policies = policies,
                )
            }
        }

        /** The EU list of trusted lists in [xml], when signed by a certificate with one of [pins]. */
        fun parseLotl(xml: ByteArray, pins: Set<String>): Lotl {
            val signer = XmlDsig.envelopedSigner(xml) ?: throw TrustListException("歐盟清單的簽章不成立")
            if (TrustLists.pin(signer.encoded) !in pins) throw TrustListException("歐盟清單的簽署憑證不在公告的憑證中")
            val root = XmlParsing.parse(xml).documentElement
            val scheme = XmlParsing.child(root, TSL, "SchemeInformation") ?: throw TrustListException("歐盟清單格式不符")
            val pointers = ArrayList<Pointer>()
            var selfPins = emptyList<String>()
            for (p in XmlParsing.descendants(scheme, TSL, "OtherTSLPointer")) {
                val url = XmlParsing.text(XmlParsing.child(p, TSL, "TSLLocation")) ?: continue
                val territory = XmlParsing.descendants(p, null, "SchemeTerritory").firstOrNull()?.let { XmlParsing.text(it) } ?: continue
                val mime = XmlParsing.descendants(p, null, "MimeType").firstOrNull()?.let { XmlParsing.text(it) }
                val certs = XmlParsing.descendants(p, TSL, "X509Certificate").mapNotNull { e ->
                    runCatching { Base64.getMimeDecoder().decode(e.textContent.trim()) }.getOrNull()
                }
                if (territory == "EU") { selfPins = certs.map { TrustLists.pin(it) }; continue }
                if (mime != TSL_MIME) continue
                pointers.add(Pointer(territory, url, certs.map { TrustLists.pin(it) }.toSet()))
            }
            return Lotl(pointers, selfPins, time(scheme, "ListIssueDateTime"), nextUpdate(scheme), Bc.cn(signer) ?: signer.subject.toString())
        }

        /** The national list in [xml] for [pointer]: signed by one of the pointer's certificates, for its territory. */
        fun parseTl(xml: ByteArray, pointer: Pointer, etag: String? = null, lastModified: String? = null): TrustListPart {
            val signer = XmlDsig.envelopedSigner(xml) ?: throw TrustListException("簽章不成立")
            if (TrustLists.pin(signer.encoded) !in pointer.signerPins) throw TrustListException("簽署憑證不是歐盟清單公告的憑證")
            val root = XmlParsing.parse(xml).documentElement
            val scheme = XmlParsing.child(root, TSL, "SchemeInformation") ?: throw TrustListException("清單格式不符")
            val territory = XmlParsing.text(XmlParsing.child(scheme, TSL, "SchemeTerritory"))
            if (territory != null && territory != pointer.territory) throw TrustListException("清單的國別 $territory 與歐盟清單不符")
            val services = ArrayList<ListedService>()
            for (tsp in XmlParsing.descendants(root, TSL, "TrustServiceProvider")) {
                val provider = XmlParsing.child(tsp, TSL, "TSPInformation")?.let { name(XmlParsing.child(it, TSL, "TSPName")) }
                for (svc in XmlParsing.descendants(tsp, TSL, "TSPService")) service(svc, provider, pointer.territory)?.let { services.addAll(it) }
            }
            return TrustListPart(pointer.territory, pointer.url, etag, lastModified, time(scheme, "ListIssueDateTime"), nextUpdate(scheme), services,
                signerPins = pointer.signerPins.sorted())
        }

        private fun service(svc: Element, provider: String?, territory: String): List<ListedService>? {
            val info = XmlParsing.child(svc, TSL, "ServiceInformation") ?: return null
            val type = XmlParsing.text(XmlParsing.child(info, TSL, "ServiceTypeIdentifier"))?.removePrefix(SVC_TYPE) ?: return null
            val role = when (type) {
                "CA/QC" -> TrustRole.DOCUMENT
                "TSA/QTST" -> TrustRole.TSA
                else -> return null
            }
            // A qualified CA that only issues website certificates does not anchor document signatures.
            val uses = XmlParsing.descendants(info, TSL, "AdditionalServiceInformation").mapNotNull { XmlParsing.text(XmlParsing.child(it, TSL, "URI")) }
            if (role == TrustRole.DOCUMENT && uses.isNotEmpty() && FOR_SIGNATURES !in uses && FOR_SEALS !in uses && FOR_WEB in uses) return null
            val events = ArrayList<Pair<Long, String>>()
            status(info)?.let { events.add(it) }
            XmlParsing.descendants(svc, TSL, "ServiceHistoryInstance").forEach { h -> status(h)?.let { events.add(it) } }
            events.sortBy { it.first }
            val granted = events.mapIndexedNotNull { i, (from, st) ->
                if (st !in GRANTED) null else GrantedPeriod(from, events.getOrNull(i + 1)?.first)
            }
            if (granted.isEmpty()) return null
            val name = name(XmlParsing.child(info, TSL, "ServiceName")) ?: provider ?: type
            val identity = XmlParsing.child(info, TSL, "ServiceDigitalIdentity") ?: return null
            return XmlParsing.descendants(identity, TSL, "X509Certificate").mapNotNull { e ->
                val der = runCatching { Base64.getMimeDecoder().decode(e.textContent.trim()) }.getOrNull() ?: return@mapNotNull null
                if (Bc.holder(der) == null) return@mapNotNull null
                ListedService(
                    certificate = TrustLists.encodeCertificate(der), name = name, provider = provider, country = territory,
                    roles = setOf(role.id), qualified = true, granted = granted,
                )
            }.distinctBy { it.certificate }
        }

        private fun status(e: Element): Pair<Long, String>? {
            val st = XmlParsing.text(XmlParsing.child(e, TSL, "ServiceStatus"))?.removePrefix(SVC_STATUS) ?: return null
            val from = XmlParsing.text(XmlParsing.child(e, TSL, "StatusStartingTime"))?.let { parseTime(it) } ?: return null
            return from to st
        }

        /** The English name of a multilingual name element, or its first name. */
        private fun name(e: Element?): String? {
            e ?: return null
            val names = XmlParsing.childrenNamed(e, TSL, "Name")
            val en = names.firstOrNull { it.getAttributeNS("http://www.w3.org/XML/1998/namespace", "lang").startsWith("en", ignoreCase = true) }
            return XmlParsing.text(en ?: names.firstOrNull())?.takeIf { it.isNotEmpty() }
        }

        private fun time(scheme: Element, name: String): Long? = XmlParsing.text(XmlParsing.child(scheme, TSL, name))?.let { parseTime(it) }

        private fun nextUpdate(scheme: Element): Long? =
            XmlParsing.child(scheme, TSL, "NextUpdate")?.let { XmlParsing.text(XmlParsing.child(it, TSL, "dateTime")) }?.let { parseTime(it) }

        private fun parseTime(s: String): Long? = runCatching { Instant.parse(s.trim()).epochSeconds }.getOrNull()

        /** The embedded file named [name] (document-level attachments) of [pdf], decoded. */
        private fun embeddedFile(pdf: PdfFile, name: String): ByteArray? {
            val names = pdf.dict(pdf.dict(pdf.catalog["Names"])?.get("EmbeddedFiles")) ?: return null
            fun walk(node: diw.wallet.core.document.pdf.PdfDict, depth: Int): ByteArray? {
                if (depth > 8) return null
                val entries = pdf.array(node["Names"])
                if (entries != null) {
                    for (i in 0 until entries.size - 1 step 2) {
                        val key = (pdf.resolveOrNull(entries[i]) as? PdfString)?.text()
                        val spec = pdf.dict(entries[i + 1]) ?: continue
                        val file = (pdf.resolveOrNull(spec["UF"]) as? PdfString)?.text() ?: (pdf.resolveOrNull(spec["F"]) as? PdfString)?.text() ?: key
                        if (file != name && key != name) continue
                        val stream = pdf.resolveOrNull(pdf.dict(spec["EF"])?.get("F")) as? PdfStream ?: continue
                        return pdf.decode(stream)
                    }
                }
                (pdf.resolveOrNull(node["Kids"]) as? PdfArray)?.forEach { kid -> pdf.dict(kid)?.let { walk(it, depth + 1)?.let { b -> return b } } }
                return null
            }
            return walk(names, 0)
        }

        /** /Contents is padded with zeros after the DER signature. */
        private fun ByteArray.trimDer(): ByteArray = runCatching {
            val parsed = org.bouncycastle.asn1.ASN1InputStream(this).use { it.readObject() }
            parsed.encoded
        }.getOrDefault(this)
    }
}

package diw.wallet.core.document.sign

import diw.wallet.core.document.Bc
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.CRLDistPoint
import org.bouncycastle.asn1.x509.DistributionPointName
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.X509CRLHolder
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.cert.ocsp.UnknownStatus
import java.util.Base64
import kotlin.time.Clock

/**
 * Collects the validation data of a certificate chain for long-term signatures (PAdES B-LT, CAdES and XAdES
 * baseline LT, time stamps kept with their revocation data): completes the chain through AIA caIssuers links (and
 * [known] certificates such as the built-in intermediates), then for every certificate below the root asks its
 * OCSP responder and falls back to the CRL distribution points. Responses are checked with the issuer (or the
 * responder certificate the issuer delegated to) before they are kept.
 */
internal object ValidationCollector {
    private const val MAX_DEPTH = 6

    suspend fun collect(chainDer: List<ByteArray>, fetch: HttpFetch, known: List<ByteArray> = emptyList()): ValidationData {
        val chain = complete(chainDer.mapNotNull { Bc.holder(it) }, known.mapNotNull { Bc.holder(it) }, fetch)
        val certs = LinkedHashMap<String, ByteArray>()
        chain.forEach { certs[b64(it.encoded)] = it.encoded }
        val ocsps = ArrayList<ByteArray>()
        val crls = ArrayList<ByteArray>()
        val statuses = ArrayList<RevocationStatus>()
        for ((i, cert) in chain.withIndex()) {
            if (selfSigned(cert)) continue
            val subject = Bc.cn(cert) ?: cert.subject.toString()
            val issuer = chain.getOrNull(i + 1)?.takeIf { issued(cert, it) }
            if (issuer == null) {
                statuses.add(RevocationStatus(subject, "NONE", "UNAVAILABLE", "缺少發行者憑證"))
                continue
            }
            val ocsp = ocsp(cert, issuer, fetch)
            if (ocsp != null) {
                ocsps.add(ocsp.response)
                ocsp.responderCerts.forEach { certs[b64(it)] = it }
                statuses.add(RevocationStatus(subject, "OCSP", ocsp.status, ocsp.detail))
                continue
            }
            val crl = crl(cert, issuer, fetch)
            if (crl != null) {
                crls.add(crl.first)
                statuses.add(RevocationStatus(subject, "CRL", crl.second, crl.third))
            } else {
                statuses.add(RevocationStatus(subject, "NONE", "UNAVAILABLE", "憑證沒有可用的 OCSP 或 CRL 位址，或連線失敗"))
            }
        }
        return ValidationData(
            certificates = certs.keys.toList(),
            ocsps = ocsps.map { b64(it) },
            crls = crls.map { b64(it) },
            statuses = statuses,
            collectedAt = Clock.System.now().epochSeconds,
        )
    }

    /** [chain] followed by its issuers up to a self-signed root, from [known] or through AIA caIssuers. */
    private suspend fun complete(chain: List<X509CertificateHolder>, known: List<X509CertificateHolder>, fetch: HttpFetch): List<X509CertificateHolder> {
        if (chain.isEmpty()) return chain
        val out = ArrayList<X509CertificateHolder>()
        // Order what was given from the leaf up.
        out.add(chain.first())
        val pool = (chain.drop(1) + known).toMutableList()
        while (out.size < MAX_DEPTH && !selfSigned(out.last())) {
            val cur = out.last()
            var next = pool.firstOrNull { it.subject == cur.issuer && issued(cur, it) && out.none { o -> o == it } }
            if (next == null) {
                for (url in Bc.caIssuers(cur)) {
                    val got = fetch.fetch(url, null, null)?.let { Bc.certificates(it) }.orEmpty().mapNotNull { Bc.holder(it) }
                    pool.addAll(got)
                    next = got.firstOrNull { it.subject == cur.issuer && issued(cur, it) }
                    if (next != null) break
                }
            }
            if (next == null) break
            out.add(next)
        }
        return out
    }

    private class OcspResult(val response: ByteArray, val status: String, val detail: String?, val responderCerts: List<ByteArray>)

    private suspend fun ocsp(cert: X509CertificateHolder, issuer: X509CertificateHolder, fetch: HttpFetch): OcspResult? {
        val urls = runCatching {
            AuthorityInformationAccess.fromExtensions(cert.extensions)?.accessDescriptions.orEmpty()
                .filter { it.accessMethod == AccessDescription.id_ad_ocsp }
                .mapNotNull { d -> d.accessLocation.takeIf { it.tagNo == GeneralName.uniformResourceIdentifier }?.name?.toString() }
        }.getOrDefault(emptyList())
        if (urls.isEmpty()) return null
        val id = CertificateID(Bc.digestProvider().get(CertificateID.HASH_SHA1), issuer, cert.serialNumber)
        val request = OCSPReqBuilder().addRequest(id).build().encoded
        for (url in urls) {
            val raw = fetch.fetch(url, request, "application/ocsp-request") ?: continue
            val resp = runCatching { OCSPResp(raw) }.getOrNull() ?: continue
            if (resp.status != OCSPResp.SUCCESSFUL) continue
            val basic = resp.responseObject as? BasicOCSPResp ?: continue
            val single = basic.responses.firstOrNull { it.certID.serialNumber == cert.serialNumber && it.certID.matchesIssuer(issuer, Bc.digestProvider()) } ?: continue
            // The response is signed by the issuer or by a responder certificate the issuer issued.
            val responder = (listOf(issuer) + basic.certs).firstOrNull { r ->
                runCatching { basic.isSignatureValid(Bc.contentVerifier(r)) }.getOrDefault(false) && (r == issuer || issued(r, issuer))
            } ?: continue
            val (status, detail) = when (val s = single.certStatus) {
                null -> "GOOD" to null
                is RevokedStatus -> "REVOKED" to "撤銷於 ${s.revocationTime.toInstant()}"
                is UnknownStatus -> "UNKNOWN" to "回應者不認得這張憑證"
                else -> "UNKNOWN" to null
            }
            return OcspResult(raw, status, detail, listOfNotNull(responder.takeIf { it != issuer }?.encoded))
        }
        return null
    }

    /** The CRL (DER), the status of [cert] in it and a note; null when no CRL could be fetched and checked. */
    private suspend fun crl(cert: X509CertificateHolder, issuer: X509CertificateHolder, fetch: HttpFetch): Triple<ByteArray, String, String?>? {
        val urls = runCatching {
            val dp = CRLDistPoint.fromExtensions(cert.extensions) ?: return null
            dp.distributionPoints.flatMap { p ->
                val name = p.distributionPoint?.takeIf { it.type == DistributionPointName.FULL_NAME }?.name as? GeneralNames
                name?.names.orEmpty().filter { it.tagNo == GeneralName.uniformResourceIdentifier }.map { it.name.toString() }
            }.filter { it.startsWith("http://") || it.startsWith("https://") }
        }.getOrDefault(emptyList())
        for (url in urls) {
            val raw = fetch.fetch(url, null, null) ?: continue
            val crl = runCatching { X509CRLHolder(raw) }.getOrNull() ?: continue
            if (crl.issuer != issuer.subject || !runCatching { crl.isSignatureValid(Bc.contentVerifier(issuer)) }.getOrDefault(false)) continue
            val entry = crl.getRevokedCertificate(cert.serialNumber)
            return if (entry != null) Triple(crl.encoded, "REVOKED", "撤銷於 ${entry.revocationDate.toInstant()}")
            else Triple(crl.encoded, "GOOD", null)
        }
        return null
    }

    private fun issued(child: X509CertificateHolder, issuer: X509CertificateHolder): Boolean =
        child.issuer == issuer.subject && runCatching { child.isSignatureValid(Bc.contentVerifier(issuer)) }.getOrDefault(false)

    private fun selfSigned(h: X509CertificateHolder) = h.subject == h.issuer && issued(h, h)

    private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

}

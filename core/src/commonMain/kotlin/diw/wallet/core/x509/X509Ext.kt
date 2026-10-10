package diw.wallet.core.x509

import diw.wallet.core.jose.PlatformCrypto
import org.multipaz.asn1.ASN1
import org.multipaz.asn1.ASN1Sequence
import org.multipaz.asn1.ASN1TagClass
import org.multipaz.asn1.ASN1TaggedObject
import org.multipaz.crypto.X509Cert
import org.multipaz.util.toBase64Url

private const val OID_SUBJECT_ALT_NAME = "2.5.29.17"

/** Subject alternative names of a certificate, split by type. */
data class SubjectAltNames(val dnsNames: List<String>, val uris: List<String>, val emails: List<String>)

fun X509Cert.subjectAltNames(): SubjectAltNames {
    val ext = getExtensionValue(OID_SUBJECT_ALT_NAME) ?: return SubjectAltNames(emptyList(), emptyList(), emptyList())
    val seq = ASN1.decode(ext) as? ASN1Sequence ?: return SubjectAltNames(emptyList(), emptyList(), emptyList())
    val dns = mutableListOf<String>()
    val uris = mutableListOf<String>()
    val emails = mutableListOf<String>()
    for (e in seq.elements) {
        if (e !is ASN1TaggedObject || e.cls != ASN1TagClass.CONTEXT_SPECIFIC) continue
        when (e.tag) {
            1 -> emails.add(e.content.decodeToString())
            2 -> dns.add(e.content.decodeToString())
            6 -> uris.add(e.content.decodeToString())
        }
    }
    return SubjectAltNames(dns, uris, emails)
}

/** base64url(SHA-256(DER)) as used by the OpenID4VP x509_hash client identifier prefix. */
fun X509Cert.x509Hash(): String = PlatformCrypto.sha256(encoded.toByteArray()).toBase64Url()

/** Case-insensitive DNS name match with single-label wildcard support on the certificate side. */
fun dnsMatches(certName: String, host: String): Boolean {
    val c = certName.lowercase().trimEnd('.')
    val h = host.lowercase().trimEnd('.')
    if (c == h) return true
    if (c.startsWith("*.")) {
        val suffix = c.substring(1)
        val firstDot = h.indexOf('.')
        return firstDot > 0 && h.substring(firstDot) == suffix
    }
    return false
}

/** Common name or full subject for display. */
fun X509Cert.displaySubject(): String {
    val name = subject.name
    val cn = name.split(',').map { it.trim() }.firstOrNull { it.startsWith("CN=") }?.removePrefix("CN=")
    return cn ?: name
}

fun X509Cert.organization(): String? =
    subject.name.split(',').map { it.trim() }.firstOrNull { it.startsWith("O=") }?.removePrefix("O=")

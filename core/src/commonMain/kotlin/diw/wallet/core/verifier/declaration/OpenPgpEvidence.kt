package diw.wallet.core.verifier.declaration

import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.pgp.OpenPgp
import diw.wallet.core.document.pgp.OpenPgpTrust
import diw.wallet.core.document.pgp.OpenPgpTrustedKey
import diw.wallet.core.i18n.ct
import diw.wallet.core.document.Check as DocCheck

/**
 * The holder's check of an OpenPGP evidence signature, done by the document inspector against the holder's OpenPGP
 * list. A certificate the verifier sent and the holder does not list joins only for this check, as unverified (T3):
 * the signature is then genuine for that key, but who owns the key is not proven.
 */
class InspectorOpenPgpEvidenceVerifier(private val trust: DocumentTrustSource) : OpenPgpEvidenceVerifier {
    override suspend fun verify(data: ByteArray, signature: ByteArray, certificate: ByteArray?): OpenPgpEvidenceResult {
        val listed = trust.openPgpKeys()
        val listedFingerprints = listed.flatMap { k -> runCatching { OpenPgp.certificates(k.certificate).map { it.first.fingerprint } }.getOrDefault(emptyList()) }.toSet()
        val sent = certificate?.let { c -> runCatching { OpenPgp.certificates(c) }.getOrNull()?.firstOrNull() }
            ?.takeIf { (info, _) -> info.fingerprint !in listedFingerprints }
            ?.let { (info, binary) -> OpenPgpTrustedKey(binary, info.name, OpenPgpTrust.UNVERIFIED) }
        val source = if (sent == null) trust else object : DocumentTrustSource by trust {
            override suspend fun openPgpKeys(): List<OpenPgpTrustedKey> = listed + sent
        }
        val report = DocumentInspector.inspect(signature, "verifier-evidence.asc", source, detachedContent = data)
        val sig = report.signatures.singleOrNull()
            ?: return OpenPgpEvidenceResult(false, null, null, null, report.problems.ifEmpty { listOf(ct("core_vd_openpgp_unreadable")) })
        val valid = sig.integrity == DocCheck.PASS && sig.certificateValidity == DocCheck.PASS
        return OpenPgpEvidenceResult(
            valid = valid,
            fingerprint = sig.signer?.serialHex?.takeIf { it.isNotEmpty() },
            userId = sig.signerName ?: sig.signer?.commonName,
            trust = sig.trust?.decision(),
            problems = sig.problems,
        )
    }
}

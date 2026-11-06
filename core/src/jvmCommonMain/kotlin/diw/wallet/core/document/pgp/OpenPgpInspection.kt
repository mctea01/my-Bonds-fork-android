package diw.wallet.core.document.pgp

import diw.wallet.core.i18n.ct
import diw.wallet.core.document.CertInfo
import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentReport
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.SignatureFormat
import diw.wallet.core.document.SignatureInfo
import diw.wallet.core.document.TrustSummary
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.io.ByteArrayInputStream
import kotlin.time.Instant

/**
 * Checks OpenPGP files for [diw.wallet.core.document.DocumentInspector]: detached signatures (with the content the
 * user linked), cleartext signed and signed messages, certificates, and encrypted messages (recipients only). A
 * signature is checked against the certificates in the wallet's OpenPGP list; its trust is the user's trust in that
 * certificate, raised from unverified to verified by a certification from a key the user made an introducer.
 */
internal object OpenPgpInspection {
    private val EXTENSIONS = setOf("asc", "sig", "gpg", "pgp")

    /** Whether [b] is OpenPGP data: an armor header, or a binary packet sequence that parses as one. */
    fun detect(b: ByteArray, name: String?): Boolean {
        if (b.isEmpty()) return false
        val head = b.copyOfRange(0, minOf(b.size, 4096)).decodeToString()
        if (head.trimStart().startsWith("-----BEGIN PGP ")) return true
        val h = b[0].toInt() and 0xFF
        if (h and 0x80 == 0) return false
        val tag = if (h and 0x40 != 0) h and 0x3F else (h shr 2) and 0x0F
        if (tag !in setOf(1, 2, 3, 4, 5, 6, 8, 10, 11, 18)) return false
        val ext = name?.substringAfterLast('.', "")?.lowercase()
        val first = runCatching { BcPGPObjectFactory(ByteArrayInputStream(b)).nextObject() }.getOrNull() ?: return false
        return when (first) {
            is PGPSignatureList -> first.size() > 0
            is PGPPublicKeyRing, is PGPSecretKeyRing, is PGPEncryptedDataList, is PGPOnePassSignatureList -> true
            is PGPCompressedData, is PGPLiteralData, is PGPMarker -> ext in EXTENSIONS
            else -> false
        }
    }

    private class Keyring(val entries: List<Entry>) {
        class Entry(val ring: PGPPublicKeyRing, val key: OpenPgpTrustedKey)

        /** The ring and key named by the signature's issuer fingerprint, else by its key ID. */
        fun find(sig: PGPSignature): Pair<Entry, PGPPublicKey>? {
            val ids = sig.keyIdentifiers
            val fprs = ids.mapNotNull { it.fingerprint }
            for (e in entries) for (k in e.ring.publicKeys) {
                val hit = if (fprs.isNotEmpty()) fprs.any { it.contentEquals(k.fingerprint) } else ids.any { it.keyId == k.keyID }
                if (hit) return e to k
            }
            return null
        }
    }

    suspend fun inspect(data: ByteArray, detached: ByteArray?, base: DocumentReport, trust: DocumentTrustSource, now: Instant): DocumentReport {
        val keyring = Keyring(trust.openPgpKeys().mapNotNull { k ->
            runCatching { Keyring.Entry(PGPPublicKeyRing(k.certificate, OpenPgp.calculator), k) }.getOrNull()
        })
        val text = runCatching { data.decodeToString(throwOnInvalidSequence = true) }.getOrNull()
        if (text != null && text.trimStart().startsWith("-----BEGIN PGP SIGNED MESSAGE-----")) return cleartext(text, base, keyring, now)
        val report = base.copy(format = DocumentFormat.OPENPGP)
        val sigs = ArrayList<PGPSignature>()
        val keys = ArrayList<OpenPgpKeyInfo>()
        var secret = false
        var literal: ByteArray? = null
        var literalName: String? = null
        var encrypted: PGPEncryptedDataList? = null
        var onePass = false
        fun walk(f: BcPGPObjectFactory, depth: Int) {
            if (depth > 4) return
            while (true) {
                when (val o = f.nextObject() ?: return) {
                    is PGPSignatureList -> sigs.addAll(o.asSequence())
                    is PGPOnePassSignatureList -> onePass = true
                    is PGPCompressedData -> walk(BcPGPObjectFactory(o.dataStream), depth + 1)
                    is PGPLiteralData -> {
                        literalName = o.fileName.takeIf { it.isNotBlank() && it != PGPLiteralData.CONSOLE }
                        literal = OpenPgp.readCapped(o.inputStream)
                    }
                    is PGPPublicKeyRing -> keys.add(OpenPgp.describe(o, false))
                    is PGPSecretKeyRing -> {
                        secret = true
                        keys.add(OpenPgp.describe(PGPPublicKeyRing(o.publicKeys.asSequence().toList()), true))
                    }
                    is PGPEncryptedDataList -> { encrypted = o; return }
                    else -> {}
                }
            }
        }
        for (block in OpenPgp.blocks(data)) walk(BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(block))), 0)

        encrypted?.let { list -> return encryptedReport(list, report) }
        if (keys.isNotEmpty() && sigs.isEmpty() && literal == null) {
            return report.copy(
                openPgp = OpenPgpReport(if (secret) OpenPgpKind.SECRET_KEYS else OpenPgpKind.PUBLIC_KEYS, keys = keys),
                notes = listOf(
                    if (secret) ct("core_pgpi_secret_file")
                    else ct("core_pgpi_public_file"),
                ),
            )
        }
        val content = literal
        if (content != null) {
            val infos = sigs.mapIndexed { i, s -> verify(s, content, keyring, label(i, sigs.size, ct("core_pgpi_signed_message")), now) }
            return report.copy(
                signatures = infos,
                openPgp = OpenPgpReport(
                    if (sigs.isEmpty() && !onePass) OpenPgpKind.LITERAL else OpenPgpKind.SIGNED_MESSAGE,
                    literalName = literalName, literalSize = content.size.toLong(), signers = signers(sigs),
                ),
                notes = listOf(ct("core_pgpi_content_start") + (literalName ?: ct("core_pgpi_unnamed")) + ct("core_pgpi_content_end", content.size)),
            )
        }
        if (sigs.isEmpty()) return report.copy(problems = listOf(ct("core_pgpi_nothing")))
        val infos = sigs.mapIndexed { i, s ->
            if (detached == null) missingContent(s, label(i, sigs.size, ct("core_pgpi_detached")))
            else verify(s, detached, keyring, label(i, sigs.size, ct("core_pgpi_detached")), now)
        }
        return report.copy(
            signatures = infos,
            openPgp = OpenPgpReport(OpenPgpKind.DETACHED_SIGNATURE, signers = signers(sigs)),
            notes = if (detached == null) listOf(ct("core_pgpi_detached_choose")) else emptyList(),
        )
    }

    private fun label(i: Int, n: Int, what: String) = if (n > 1) "$what ${i + 1}" else what

    private fun signers(sigs: List<PGPSignature>): List<String> = sigs.mapNotNull { s ->
        s.keyIdentifiers.firstNotNullOfOrNull { it.fingerprint }?.let { OpenPgp.hex(it) }
            ?: s.keyIdentifiers.firstOrNull()?.keyId?.takeIf { it != 0L }?.let { java.lang.Long.toHexString(it).uppercase().padStart(16, '0') }
    }.distinct()

    /** A cleartext signed message (RFC 9580 7): dash-escaping removed, trailing whitespace dropped, CRLF lines. */
    private fun cleartext(text: String, base: DocumentReport, keyring: Keyring, now: Instant): DocumentReport {
        val lines = text.trimStart().split("\n").map { it.removeSuffix("\r") }
        var i = 1
        while (i < lines.size && lines[i].isNotEmpty()) i++
        i++
        val body = ArrayList<String>()
        while (i < lines.size && lines[i] != "-----BEGIN PGP SIGNATURE-----") {
            body.add(lines[i].let { if (it.startsWith("- ")) it.substring(2) else it }.trimEnd(' ', '\t'))
            i++
        }
        if (i >= lines.size) return base.copy(format = DocumentFormat.OPENPGP, problems = listOf(ct("core_pgpi_clear_no_block")))
        val signed = body.joinToString("\r\n")
        val armored = lines.subList(i, lines.size).joinToString("\n").encodeToByteArray()
        val sigs = (BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(armored))).nextObject() as? PGPSignatureList)?.asSequence()?.toList().orEmpty()
        val infos = sigs.mapIndexed { n, s -> verify(s, signed.encodeToByteArray(), keyring, label(n, sigs.size, ct("core_pgpi_cleartext")), now) }
        return base.copy(
            format = DocumentFormat.OPENPGP,
            signatures = infos,
            openPgp = OpenPgpReport(OpenPgpKind.CLEARTEXT_SIGNED, clearText = body.joinToString("\n"), signers = signers(sigs)),
            problems = if (sigs.isEmpty()) listOf(ct("core_pgpi_clear_bad_block")) else emptyList(),
        )
    }

    private fun encryptedReport(list: PGPEncryptedDataList, report: DocumentReport): DocumentReport {
        val recipients = list.encryptedDataObjects.asSequence().mapNotNull { d ->
            when (d) {
                is PGPPublicKeyEncryptedData -> OpenPgpRecipient(
                    d.keyIdentifier.fingerprint?.let { OpenPgp.hex(it) }
                        ?: java.lang.Long.toHexString(d.keyID).uppercase().padStart(16, '0'),
                    OpenPgp.publicKeyAlgorithmName(d.algorithm),
                )
                is PGPPBEEncryptedData -> OpenPgpRecipient(ct("core_pgpi_passphrase"), ct("core_pgpi_skesk", d.version))
                else -> null
            }
        }.toList()
        val protection = when {
            list.isEmpty -> null
            list[0].isAEAD -> ct("core_pgpi_aead")
            list.isIntegrityProtected -> ct("core_pgpi_seipd1")
            else -> ct("core_pgpi_sed")
        }
        return report.copy(
            encrypted = true,
            openPgp = OpenPgpReport(OpenPgpKind.ENCRYPTED, recipients = recipients, encryption = protection),
            notes = listOf(ct("core_pgpi_encrypted", recipients.size)),
            problems = if (protection?.startsWith(ct("core_pgpi_legacy")) == true) listOf(ct("core_pgpi_no_integrity")) else emptyList(),
        )
    }

    private fun missingContent(s: PGPSignature, label: String) = SignatureInfo(
        format = SignatureFormat.OPENPGP,
        label = label,
        algorithm = OpenPgp.publicKeyAlgorithmName(s.keyAlgorithm) + " / " + OpenPgp.hashName(s.hashAlgorithm),
        signer = null,
        chain = emptyList(),
        integrity = Check.NOT_CHECKED,
        coversWholeDocument = null,
        claimedTime = s.creationTime.time / 1000,
        trust = null,
        certificateValidity = Check.NOT_CHECKED,
        problems = listOf(ct("core_pgpi_detached_needs")),
    )

    /** Verifies [s] over [content] with the list's certificates and judges the key's validity at the signing time. */
    private fun verify(s: PGPSignature, content: ByteArray, keyring: Keyring, label: String, now: Instant): SignatureInfo {
        val created = s.creationTime.time / 1000
        val algorithm = OpenPgp.publicKeyAlgorithmName(s.keyAlgorithm) + " / " + OpenPgp.hashName(s.hashAlgorithm)
        val type = when (s.signatureType) {
            PGPSignature.BINARY_DOCUMENT -> ct("core_pgpi_binary")
            PGPSignature.CANONICAL_TEXT_DOCUMENT -> ct("core_pgpi_text")
            else -> ct("core_pgpi_type") + s.signatureType.toString(16)
        }
        val found = keyring.find(s) ?: return SignatureInfo(
            format = SignatureFormat.OPENPGP,
            label = label,
            algorithm = algorithm,
            signer = null,
            chain = emptyList(),
            integrity = Check.NOT_CHECKED,
            coversWholeDocument = true,
            claimedTime = created,
            trust = null,
            certificateValidity = Check.NOT_CHECKED,
            problems = listOf(
                ct("core_pgpi_no_signer_key") + (signers(listOf(s)).firstOrNull() ?: ct("core_pgpi_unlabeled")) +
                    ct("core_pgpi_no_signer_key_end"),
            ),
            notes = listOf(ct("core_pgpi_sig_type", type)),
        )
        val (entry, key) = found
        val master = entry.ring.publicKey
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        notes += ct("core_pgpi_sig_type", type)
        notes += ct("core_pgpi_signing_key") + OpenPgpPackets.fingerprintText(key.fingerprint) + ct("core_paren_open_space") + OpenPgp.algorithmName(key) + ct("core_paren_close")
        if (!key.isMasterKey) notes += ct("core_pgpi_primary_key") + OpenPgpPackets.fingerprintText(master.fingerprint)

        val integrity = runCatching {
            s.init(BcPGPContentVerifierBuilderProvider(), key)
            s.update(content)
            s.verify()
        }.getOrElse { problems += ct("core_pgpi_unverifiable") + (it.message ?: it.javaClass.simpleName); false }
        var integrityCheck = if (integrity) Check.PASS else Check.FAIL
        if (integrity && s.hashAlgorithm in setOf(1, 2, 3)) {
            integrityCheck = Check.WARN
            problems += ct("core_pgpi_uses") + OpenPgp.hashName(s.hashAlgorithm) + ct("core_pgpi_insecure")
        }
        if (!integrity) problems += ct("core_pgpi_mismatch")

        var validity = Check.PASS
        val keyCreated = key.creationTime.time / 1000
        if (created < keyCreated) { validity = Check.FAIL; problems += ct("core_pgpi_before_key") }
        if (key.validSeconds > 0 && created > keyCreated + key.validSeconds) { validity = Check.FAIL; problems += ct("core_pgpi_key_expired") }
        if (s.hashedSubPackets?.signatureExpirationTime?.let { it > 0 && now.epochSeconds > created + it } == true) {
            validity = Check.FAIL
            problems += ct("core_pgpi_sig_expired")
        }
        // Only a key the wallet read from the holder's card may lack a binding; anything else could be a foreign
        // subkey placed under a trusted primary key in a copy stripped of its signatures.
        if (!key.isMasterKey && OpenPgp.hex(key.fingerprint) !in entry.key.cardKeys) {
            val binding = OpenPgp.validBinding(master, key)
            if (binding == null) { validity = Check.FAIL; problems += ct("core_pgpi_subkey_unbound") }
            else {
                val flags = binding.hashedSubPackets?.keyFlags ?: 0
                if (flags != 0 && flags and KeyFlags.SIGN_DATA == 0) { validity = Check.FAIL; problems += ct("core_pgpi_subkey_no_sign") }
            }
        }
        for (k in listOfNotNull(master, key.takeIf { !it.isMasterKey })) {
            val rev = OpenPgp.revocation(k, master) ?: continue
            val soft = soft(rev)
            val revokedAt = rev.creationTime.time / 1000
            if (!soft || created >= revokedAt) {
                validity = Check.FAIL
                problems += (if (k.isMasterKey) ct("core_pgpi_primary") else ct("core_pgpi_subkey")) + ct("core_pgpi_revoked") + (if (soft) ct("core_pgpi_signed_after") else ct("core_pgpi_compromised"))
            } else notes += (if (k.isMasterKey) ct("core_pgpi_primary") else ct("core_pgpi_subkey")) + ct("core_pgpi_retired")
        }

        val (tier, anchor) = tierOf(entry, keyring, now)
        if (entry.key.trust == OpenPgpTrust.DISTRUSTED) problems += ct("core_pgpi_distrusted")
        if (tier == "T3") problems += ct("core_pgpi_unverified")
        val uid = master.userIDs.asSequence().firstOrNull()
        val expires = key.validSeconds.takeIf { it > 0 }?.let { keyCreated + it } ?: 253402300799L
        val signer = CertInfo(
            subject = uid ?: entry.key.name,
            issuer = ct("core_pgpi_issuer_start") + entry.key.trust.title + ct("core_paren_close"),
            commonName = uid ?: entry.key.name,
            serialHex = OpenPgp.hex(key.fingerprint),
            notBefore = keyCreated,
            notAfter = expires,
            der = "",
            publicKey = OpenPgp.algorithmName(key),
        )
        return SignatureInfo(
            format = SignatureFormat.OPENPGP,
            label = label,
            algorithm = algorithm,
            signer = signer,
            chain = listOf(signer),
            integrity = integrityCheck,
            coversWholeDocument = true,
            claimedTime = created,
            trust = TrustSummary(tier, null, false, anchor, if (tier == "T4") listOf("UNKNOWN_ANCHOR") else listOf("USER_ANCHOR")),
            certificateValidity = validity,
            signerName = uid,
            problems = problems,
            notes = notes,
        )
    }

    /**
     * The tier of a signature by [entry]: the user's own trust, raised from unverified to T2 when a user ID carries a
     * valid certification by a key the user verified and made an introducer.
     */
    /** A revocation for a superseded, retired or no longer used key: signatures made before it stay valid. */
    private fun soft(rev: PGPSignature): Boolean {
        val reason = rev.hashedSubPackets?.revocationReason?.revocationReason?.toInt()
        return reason == RevocationReasonTags.KEY_SUPERSEDED.toInt() || reason == RevocationReasonTags.KEY_RETIRED.toInt() ||
            reason == RevocationReasonTags.USER_NO_LONGER_VALID.toInt()
    }

    private fun tierOf(entry: Keyring.Entry, keyring: Keyring, now: Instant): Pair<String, String> = when (entry.key.trust) {
        OpenPgpTrust.OWN_CARD, OpenPgpTrust.VERIFIED -> "T2" to entry.key.name + ct("core_paren_open_space") + entry.key.trust.title + ct("core_paren_close")
        OpenPgpTrust.DISTRUSTED -> "T4" to entry.key.name + ct("core_pgpi_anchor_distrusted")
        OpenPgpTrust.UNVERIFIED -> {
            val introducer = introducerOf(entry, keyring, now)
            if (introducer != null) "T2" to entry.key.name + ct("core_pgpi_certified_by") + introducer + ct("core_pgpi_certified_end")
            else "T3" to entry.key.name + ct("core_pgpi_anchor_unverified")
        }
    }


    /**
     * The introducer whose certification of one of [entry]'s user IDs holds: made by the introducer's primary key while
     * it was valid (created, not expired, not revoked as compromised, or made before a retirement), not expired itself,
     * and not withdrawn by a later certification revocation from the same key.
     */
    private fun introducerOf(entry: Keyring.Entry, keyring: Keyring, now: Instant): String? {
        val master = entry.ring.publicKey
        val introducers = keyring.entries.filter { it.key.introducer && (it.key.trust == OpenPgpTrust.VERIFIED || it.key.trust == OpenPgpTrust.OWN_CARD) && it !== entry }
        if (introducers.isEmpty()) return null
        for (uid in master.userIDs.asSequence()) {
            val sigs = master.getSignaturesForID(uid).asSequence().toList()
            for (cert in sigs) {
                if (!cert.isCertification || cert.signatureType == PGPSignature.CERTIFICATION_REVOCATION) continue
                for (intro in introducers) {
                    val introMaster = intro.ring.publicKey
                    if (!issuedBy(cert, introMaster) || !verifies(cert, introMaster, uid, master)) continue
                    if (!introducerValidAt(introMaster, cert, now)) continue
                    val withdrawn = sigs.any { r ->
                        r.signatureType == PGPSignature.CERTIFICATION_REVOCATION && !r.creationTime.before(cert.creationTime) &&
                            issuedBy(r, introMaster) && verifies(r, introMaster, uid, master)
                    }
                    if (!withdrawn) return intro.key.name
                }
            }
        }
        return null
    }

    private fun issuedBy(sig: PGPSignature, key: PGPPublicKey): Boolean =
        sig.keyIdentifiers.any { id -> id.fingerprint?.contentEquals(key.fingerprint) ?: (id.keyId == key.keyID) }

    private fun verifies(sig: PGPSignature, signer: PGPPublicKey, uid: String, subject: PGPPublicKey): Boolean = runCatching {
        sig.init(BcPGPContentVerifierBuilderProvider(), signer)
        sig.verifyCertification(uid, subject)
    }.getOrDefault(false)

    /** Whether the introducer's primary key could certify when [cert] was made, and [cert] has not expired. */
    private fun introducerValidAt(introMaster: PGPPublicKey, cert: PGPSignature, now: Instant): Boolean {
        val made = cert.creationTime.time / 1000
        val created = introMaster.creationTime.time / 1000
        if (made < created) return false
        if (introMaster.validSeconds > 0 && made > created + introMaster.validSeconds) return false
        val expires = cert.hashedSubPackets?.signatureExpirationTime ?: 0L
        if (expires > 0 && now.epochSeconds > made + expires) return false
        val rev = OpenPgp.revocation(introMaster, introMaster) ?: return true
        return soft(rev) && made < rev.creationTime.time / 1000
    }
}

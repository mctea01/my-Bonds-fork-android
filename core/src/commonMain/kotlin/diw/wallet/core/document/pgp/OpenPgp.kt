package diw.wallet.core.document.pgp

import diw.wallet.core.i18n.ct
import kotlinx.serialization.Serializable

/** One key of an OpenPGP certificate: the primary key or a subkey. Times are epoch seconds. */
@Serializable
data class OpenPgpSubkeyInfo(
    val fingerprint: String,
    val algorithm: String,
    val created: Long,
    val expires: Long? = null,
    val revoked: Boolean = false,
    val canSign: Boolean = false,
    val canEncrypt: Boolean = false,
)

/** An OpenPGP certificate (transferable public key) as the wallet lists it. */
@Serializable
data class OpenPgpKeyInfo(
    /** Primary key fingerprint, upper-case hex without spaces. */
    val fingerprint: String,
    val version: Int,
    val userIds: List<String>,
    val primary: OpenPgpSubkeyInfo,
    val subkeys: List<OpenPgpSubkeyInfo> = emptyList(),
    /** The file held a secret key; the wallet keeps only the public part. */
    val hadSecret: Boolean = false,
) {
    val name: String get() = userIds.firstOrNull() ?: ct("core_pgpk_key")
    val canSign: Boolean get() = (listOf(primary) + subkeys).any { it.canSign && !it.revoked }
    val canEncrypt: Boolean get() = (listOf(primary) + subkeys).any { it.canEncrypt && !it.revoked }
    val revoked: Boolean get() = primary.revoked

    /** Whether [fpr] (hex, any case and spacing) or its key ID names this certificate's primary key or a subkey. */
    fun has(fpr: String): Boolean {
        val f = fpr.filter { !it.isWhitespace() }.uppercase()
        return (listOf(primary) + subkeys).any { it.fingerprint == f || (f.length == 16 && it.fingerprint.endsWith(f)) }
    }
}

/** What an OpenPGP file holds. */
@Serializable
enum class OpenPgpKind(private val titleKey: String) {
    DETACHED_SIGNATURE("core_pgpk_detached"),
    CLEARTEXT_SIGNED("core_pgpk_cleartext"),
    SIGNED_MESSAGE("core_pgpk_signed"),
    LITERAL("core_pgpk_literal"),
    PUBLIC_KEYS("core_pgpk_public"),
    SECRET_KEYS("core_pgpk_secret"),
    ENCRYPTED("core_pgpk_encrypted");

    val title: String get() = if (titleKey.startsWith("core_")) ct(titleKey) else titleKey
}

/** One recipient of an encrypted OpenPGP message. */
@Serializable
data class OpenPgpRecipient(
    /** Key ID or fingerprint in hex; all zeros for a hidden recipient; "密碼" for a passphrase (SKESK). */
    val key: String,
    val algorithm: String,
)

/** The OpenPGP part of a document report. */
@Serializable
data class OpenPgpReport(
    val kind: OpenPgpKind,
    val keys: List<OpenPgpKeyInfo> = emptyList(),
    val recipients: List<OpenPgpRecipient> = emptyList(),
    /** Symmetric encryption and integrity protection of an encrypted message. */
    val encryption: String? = null,
    /** File name and size of the literal data in a signed (or plain) message. */
    val literalName: String? = null,
    val literalSize: Long? = null,
    /** The signed text of a cleartext signed message, as signed (dash-escaping removed). */
    val clearText: String? = null,
    /** Fingerprints or key IDs of the signers, for looking their keys up. */
    val signers: List<String> = emptyList(),
)

/**
 * How much the user trusts an OpenPGP certificate in the wallet's list. OpenPGP has no certification authorities, so
 * this is the user's own decision, as GnuPG's validity and owner trust are; it maps onto the wallet's tiers.
 */
@Serializable
enum class OpenPgpTrust(private val titleKey: String, private val detailKey: String) {
    /** The holder's own OpenPGP card, read by this wallet. */
    OWN_CARD("core_pgpt_own", "core_pgpt_own_text"),
    /** The user compared the fingerprint with the owner through a reliable channel. */
    VERIFIED("core_pgpt_verified", "core_pgpt_verified_text"),
    /** Imported or looked up but not compared: the signature is genuine for this key, the key's owner is not proven. */
    UNVERIFIED("core_pgpt_unverified", "core_pgpt_unverified_text"),
    /** Kept in the list but refused: signatures by it are shown as untrusted. */
    DISTRUSTED("core_pgpt_distrusted", "core_pgpt_distrusted_text");

    val detail: String get() = if (detailKey.startsWith("core_")) ct(detailKey) else detailKey

    val title: String get() = if (titleKey.startsWith("core_")) ct(titleKey) else titleKey
}

/**
 * A certificate in the wallet's OpenPGP list as the inspector sees it: the binary certificate, its display [name], the
 * user's [trust], and whether its certifications of other keys count ([introducer], one level, like a fully trusted
 * owner in GnuPG). [cardKeys] are the fingerprints (upper-case hex) of keys the wallet read from the holder's own
 * card: only those may stand in the certificate without a binding signature. Every other subkey needs a valid binding,
 * so a certificate stripped of its signatures cannot slip a foreign subkey under a trusted primary key.
 */
class OpenPgpTrustedKey(
    val certificate: ByteArray,
    val name: String,
    val trust: OpenPgpTrust = OpenPgpTrust.VERIFIED,
    val introducer: Boolean = false,
    val cardKeys: Set<String> = emptySet(),
)

/** The content of a decrypted message: the literal data and the signatures that were inside, as a detached signature. */
class OpenPgpPlaintext(val fileName: String?, val data: ByteArray, val detachedSignature: ByteArray?)

/**
 * OpenPGP operations that need the full packet grammar (RFC 4880, RFC 9580): reading certificates, encrypting to
 * them, decrypting with a session key a card recovered, verifying a signature against a key packet. Backed by
 * Bouncy Castle on the JVM and Android. Signatures and session keys made with an OpenPGP card are built by
 * [OpenPgpPackets] instead, so the card never sits behind a synchronous library callback.
 */
expect object OpenPgp {
    /**
     * The certificates in [data] (armored or binary, one or more), each with its binary public part. Subkeys without
     * a valid binding are listed as usable for nothing, except the keys in [cardKeys] (read from the holder's card).
     */
    fun certificates(data: ByteArray, cardKeys: Set<String> = emptySet()): List<Pair<OpenPgpKeyInfo, ByteArray>>

    /**
     * [old] and [update] (binary certificates of the same primary key) joined: every user ID, subkey and signature of
     * both, so a newer copy that leaves out a revocation cannot remove it.
     */
    fun merge(old: ByteArray, update: ByteArray): ByteArray

    /** The key packet bodies (primary key and subkeys) of the binary certificate [certificate], for matching card keys. */
    fun keyBodies(certificate: ByteArray): List<ByteArray>

    /** The literal data of an unencrypted OpenPGP message (plain or signed), or null when it has none. */
    fun literal(message: ByteArray): OpenPgpPlaintext?

    /** Whether [signature] (a binary or armored v4 signature packet) verifies over [data] with the key packet body [keyBody]. */
    fun verifyDetached(keyBody: ByteArray, data: ByteArray, signature: ByteArray): Boolean

    /**
     * Encrypts [data] to [recipients] (binary certificates, or a key packet the wallet built from a card) with AES-256
     * and integrity protection; [fileName] goes in the literal data. Each certificate's usable encryption key is
     * chosen: a valid, unrevoked, unexpired key whose flags allow encryption; a subkey without a binding only when it
     * is in [cardKeys].
     */
    fun encrypt(data: ByteArray, fileName: String, recipients: List<ByteArray>, armor: Boolean, cardKeys: Set<String> = emptySet()): ByteArray

    /**
     * Decrypts [message] with a session key ([algorithm], [key]) a card recovered. The integrity check (MDC or AEAD)
     * must pass; a message without integrity protection is refused.
     */
    fun decrypt(message: ByteArray, algorithm: Int, key: ByteArray): OpenPgpPlaintext
}

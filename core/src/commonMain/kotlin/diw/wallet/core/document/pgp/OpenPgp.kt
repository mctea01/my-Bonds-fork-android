package diw.wallet.core.document.pgp

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
    val name: String get() = userIds.firstOrNull() ?: "OpenPGP 金鑰"
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
enum class OpenPgpKind(val title: String) {
    DETACHED_SIGNATURE("OpenPGP 分離式簽章"),
    CLEARTEXT_SIGNED("OpenPGP 明文簽章訊息"),
    SIGNED_MESSAGE("OpenPGP 簽章訊息"),
    LITERAL("OpenPGP 資料（未簽章）"),
    PUBLIC_KEYS("OpenPGP 公開金鑰"),
    SECRET_KEYS("OpenPGP 私鑰"),
    ENCRYPTED("OpenPGP 加密訊息"),
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
enum class OpenPgpTrust(val title: String, val detail: String) {
    /** The holder's own OpenPGP card, read by this wallet. */
    OWN_CARD("自己的 OpenPGP 卡", "由這個錢包從你的卡片讀取，T2"),
    /** The user compared the fingerprint with the owner through a reliable channel. */
    VERIFIED("已核對指紋", "已透過可靠管道（當面、電話、官方網站）核對指紋，T2"),
    /** Imported or looked up but not compared: the signature is genuine for this key, the key's owner is not proven. */
    UNVERIFIED("未核對", "簽章可驗證，但無法確認金鑰屬於誰，T3；由你信任的介紹人認證過則升為 T2"),
    /** Kept in the list but refused: signatures by it are shown as untrusted. */
    DISTRUSTED("不信任", "保留在清單中，但它的簽章一律判定為不可信，T4"),
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

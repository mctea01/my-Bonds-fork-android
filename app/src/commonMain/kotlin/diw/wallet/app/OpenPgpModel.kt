package diw.wallet.app

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.card.OpenPgpCardInfo
import diw.wallet.core.document.card.OpenPgpKeySlot
import diw.wallet.core.document.pgp.OpenPgp
import diw.wallet.core.document.pgp.OpenPgpCards
import diw.wallet.core.document.pgp.OpenPgpKeyInfo
import diw.wallet.core.document.pgp.OpenPgpPackets
import diw.wallet.core.document.pgp.OpenPgpTrust
import diw.wallet.core.document.pgp.OpenPgpTrustedKey
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.util.DiwJson
import io.ktor.client.request.get
import io.ktor.client.statement.readRawBytes
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import kotlin.time.Clock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import org.multipaz.storage.StorageTableSpec
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64

/** A certificate in the wallet's OpenPGP list with the user's trust in it. */
@Serializable
data class OpenPgpKeyEntry(
    /** Primary key fingerprint, upper-case hex without spaces. */
    val fingerprint: String,
    /** The binary public certificate, base64. */
    val certificate: String,
    val info: OpenPgpKeyInfo,
    val trust: OpenPgpTrust,
    /** Certifications this key made of other keys raise them from unverified to T2 (one level, like GnuPG full owner trust). */
    val introducer: Boolean = false,
    /** Where it came from: a file, a card, a key server or a domain's Web Key Directory. */
    val source: String,
    val addedAt: Long,
    /** Only the keys a card holds, without user IDs or binding signatures (made by the wallet from the card). */
    val cardOnly: Boolean = false,
) {
    /** Introductions count only from a key the user has checked. */
    val introduces: Boolean get() = introducer && (trust == OpenPgpTrust.OWN_CARD || trust == OpenPgpTrust.VERIFIED)
}

/** Certificates found by a lookup, waiting for the user to add them. */
class OpenPgpFound(val query: String, val source: String, val keys: List<Pair<OpenPgpKeyInfo, ByteArray>>)

/**
 * The wallet's OpenPGP public key list and the user's trust in each key. OpenPGP has no certification authorities, so
 * a key counts only as far as the user decided: the holder's own card read by this wallet and fingerprints compared
 * through a reliable channel are T2, imported or looked-up keys stay unverified (T3) until compared or introduced by
 * a key the user marked as an introducer, and refused keys are T4. Keys are found in files, on OpenPGP cards, in a
 * domain's Web Key Directory and on keys.openpgp.org (which only checks the e-mail address); found keys are never
 * trusted by themselves.
 */
class OpenPgpModel(private val model: WalletModel) {
    val keys = MutableStateFlow<List<OpenPgpKeyEntry>>(emptyList())
    val busy = MutableStateFlow<String?>(null)
    val error = MutableStateFlow<String?>(null)
    /** The card read last on the keys screen or the signing screen, for showing its keys and adding them. */
    val card = MutableStateFlow<OpenPgpCardInfo?>(null)
    /** Keys a lookup found, shown for confirmation before they are added. */
    val found = MutableStateFlow<OpenPgpFound?>(null)

    /** X.509 certificates OpenPGP cards signed for themselves, by signature key fingerprint. */
    private val selfIssued = mutableMapOf<String, ByteArray>()
    private val lock = Mutex()

    suspend fun load() {
        val t = model.storage.getTable(keyTable)
        keys.value = t.enumerate().mapNotNull { k ->
            t.get(k)?.let { runCatching { DiwJson.decodeFromString(OpenPgpKeyEntry.serializer(), it.decodeToString()) }.getOrNull() }
        }.sortedWith(ORDER)
        val c = model.storage.getTable(certTable)
        c.enumerate().forEach { k -> c.get(k)?.let { selfIssued[k] = it.toByteArray() } }
    }

    /** The list as the document inspector uses it: refused keys first, so a key in two entries is never trusted by mistake. */
    fun trustedKeys(): List<OpenPgpTrustedKey> = keys.value.sortedWith(ORDER).mapNotNull { e ->
        runCatching { OpenPgpTrustedKey(e.certificate.fromBase64(), e.info.name, e.trust, e.introduces) }.getOrNull()
    }

    /** Key packet bodies of every listed key, for matching the keys a card holds to their OpenPGP fingerprints. */
    fun knownBodies(): List<ByteArray> = keys.value.flatMap { e -> runCatching { OpenPgp.keyBodies(e.certificate.fromBase64()) }.getOrDefault(emptyList()) }

    fun entry(fingerprint: String): OpenPgpKeyEntry? = keys.value.firstOrNull { it.fingerprint == fingerprint }

    /** The listed key holding [fpr] (a fingerprint or key ID of the primary key or a subkey). */
    fun holder(fpr: String): OpenPgpKeyEntry? = keys.value.sortedWith(ORDER).firstOrNull { it.info.has(fpr) }

    fun selfIssuedCertificate(fingerprint: String): ByteArray? = selfIssued[fingerprint]

    suspend fun keepSelfIssued(fingerprint: String, certificate: ByteArray) {
        selfIssued[fingerprint] = certificate
        val t = model.storage.getTable(certTable)
        if (t.get(fingerprint) == null) t.insert(fingerprint, ByteString(certificate)) else t.update(fingerprint, ByteString(certificate))
    }

    private fun run(progress: String, block: suspend () -> Unit) = model.scope.launch {
        busy.value = progress
        error.value = null
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            error.value = model.describe(e)
        } finally {
            busy.value = null
        }
    }

    // ---------------------------------------------------------------- adding keys

    /**
     * Adds or updates a certificate. A key already listed gets the new certificate (it may carry a revocation or a new
     * expiry) and keeps the user's trust unless [trust] is the holder's own card; card-only entries the new
     * certificate covers are replaced by it, keeping their trust.
     */
    suspend fun put(info: OpenPgpKeyInfo, certificate: ByteArray, trust: OpenPgpTrust, source: String, cardOnly: Boolean = false): OpenPgpKeyEntry = lock.withLock {
        val t = model.storage.getTable(keyTable)
        val existing = keys.value.firstOrNull { it.fingerprint == info.fingerprint }
        val covered = if (cardOnly) emptyList() else keys.value.filter { e ->
            e.cardOnly && e.fingerprint != info.fingerprint && (listOf(e.info.primary) + e.info.subkeys).all { info.has(it.fingerprint) }
        }
        val kept = (listOfNotNull(existing) + covered).map { it.trust }
        val decided = when {
            trust == OpenPgpTrust.OWN_CARD -> OpenPgpTrust.OWN_CARD
            OpenPgpTrust.DISTRUSTED in kept -> OpenPgpTrust.DISTRUSTED
            else -> (kept + trust).minByOrNull { it.ordinal } ?: trust
        }
        // A card-only entry never replaces a full certificate of the same key.
        val keepFull = cardOnly && existing != null && !existing.cardOnly
        val e = OpenPgpKeyEntry(
            fingerprint = info.fingerprint,
            certificate = if (keepFull) existing!!.certificate else certificate.toBase64(),
            info = if (keepFull) existing!!.info else info,
            trust = decided,
            introducer = existing?.introducer ?: false,
            source = existing?.source ?: source,
            addedAt = existing?.addedAt ?: Clock.System.now().epochSeconds,
            cardOnly = if (keepFull) false else cardOnly,
        )
        covered.forEach { t.delete(it.fingerprint) }
        val bytes = DiwJson.encodeToString(OpenPgpKeyEntry.serializer(), e).encodeToByteString()
        if (t.get(e.fingerprint) == null) t.insert(e.fingerprint, bytes) else t.update(e.fingerprint, bytes)
        keys.value = (keys.value.filter { it.fingerprint != e.fingerprint && it !in covered } + e).sortedWith(ORDER)
        e
    }

    /** Adds every certificate in [data] (armored or binary, public or secret keys: only the public part is kept). */
    suspend fun importBytes(data: ByteArray, source: String): List<OpenPgpKeyEntry> {
        val certs = OpenPgp.certificates(data)
        if (certs.isEmpty()) throw SigningException("檔案中沒有 OpenPGP 公開金鑰")
        return certs.map { (info, cert) -> put(info, cert, OpenPgpTrust.UNVERIFIED, source) }
    }

    fun pickAndImport() = run("讀取公開金鑰檔") {
        val picked = model.platform.pickFiles()
        if (picked.isEmpty()) return@run
        val added = picked.flatMap { importBytes(it.bytes, "匯入：" + it.name) }
        val secret = added.count { it.info.hadSecret }
        model.message.value = "已加入 ${added.size} 把公開金鑰（未核對）" + if (secret > 0) "；檔案含私鑰，錢包只保留公開部分" else ""
        model.files.reinspectOpenPgp()
    }

    /** Adds the certificates a stored file holds (a .asc or .gpg key file in the Files tab) as unverified. */
    fun importFromFile(f: StoredFile) = run("加入檔案中的公開金鑰") {
        val added = importBytes(model.files.data(f.id), "文件：" + f.name)
        model.message.value = "已加入 ${added.size} 把公開金鑰（未核對，請與持有人核對指紋）"
        model.files.reinspectOpenPgp()
    }

    /** Reads the OpenPGP card on [reader] without a PIN and shows its keys. */
    fun readCard(reader: NfcReaderOption) = run("讀取 OpenPGP 卡") {
        card.value = OpenPgpCards.read(reader.reader, tapMessage(reader, "讀取卡片上的金鑰"), knownBodies())
    }

    /**
     * Adds the keys of [info] (read by this wallet from the holder's card) as the holder's own: the listed certificate
     * holding the card's keys is marked as the own card, otherwise a certificate of the card's keys alone is made.
     */
    suspend fun addCard(info: OpenPgpCardInfo): OpenPgpKeyEntry {
        val sig = info.key(OpenPgpKeySlot.SIGNATURE)
        val dec = info.key(OpenPgpKeySlot.DECRYPTION)
        val aut = info.key(OpenPgpKeySlot.AUTHENTICATION)
        val fprs = listOfNotNull(sig, dec, aut).mapNotNull { it.fingerprint?.let { f -> DocCryptoUtil.hex(f).uppercase() } }
        if (fprs.isEmpty()) throw SigningException("這張 OpenPGP 卡沒有金鑰")
        keys.value.firstOrNull { e -> !e.cardOnly && fprs.any { e.info.has(it) } }?.let { full ->
            return put(full.info, full.certificate.fromBase64(), OpenPgpTrust.OWN_CARD, full.source)
        }
        val bodies = listOfNotNull(sig ?: dec ?: aut, dec, aut).distinct().mapNotNull { it.packet }.distinctBy { it.toList() }
        if (bodies.isEmpty()) throw SigningException(
            "無法由卡片重建公開金鑰（指紋不符，常見於以 ECDH 參數不同的工具產生的金鑰）。請先匯入你的公開金鑰檔，再讀取卡片標示為自己的卡",
        )
        val cert = OpenPgpPackets.cardCertificate(bodies)
        val (parsed, binary) = OpenPgp.certificates(cert).firstOrNull() ?: throw SigningException("無法建立卡片金鑰的憑證")
        return put(parsed, binary, OpenPgpTrust.OWN_CARD, info.label, cardOnly = true)
    }

    fun addReadCard() = run("加入卡片的公開金鑰") {
        val info = card.value ?: return@run
        val e = addCard(info)
        model.message.value = "已加入：${e.info.name}（自己的 OpenPGP 卡）"
        model.files.reinspectOpenPgp()
    }

    // ---------------------------------------------------------------- trust

    private suspend fun change(fingerprint: String, transform: (OpenPgpKeyEntry) -> OpenPgpKeyEntry) = lock.withLock {
        val current = keys.value.firstOrNull { it.fingerprint == fingerprint } ?: return@withLock
        val e = transform(current)
        model.storage.getTable(keyTable).update(e.fingerprint, DiwJson.encodeToString(OpenPgpKeyEntry.serializer(), e).encodeToByteString())
        keys.value = (keys.value.filter { it.fingerprint != fingerprint } + e).sortedWith(ORDER)
    }

    /** Sets the user's trust; the own-card level is only given by reading the card. */
    fun setTrust(fingerprint: String, trust: OpenPgpTrust) = run("變更信任") {
        if (trust == OpenPgpTrust.OWN_CARD) throw SigningException("「自己的 OpenPGP 卡」只能由讀取卡片設定")
        change(fingerprint) { it.copy(trust = trust) }
        model.files.reinspectOpenPgp()
    }

    fun setIntroducer(fingerprint: String, introducer: Boolean) = run("變更介紹人") {
        change(fingerprint) { it.copy(introducer = introducer) }
        model.files.reinspectOpenPgp()
    }

    fun remove(fingerprint: String) = run("移除公開金鑰") {
        lock.withLock {
            model.storage.getTable(keyTable).delete(fingerprint)
            keys.value = keys.value.filter { it.fingerprint != fingerprint }
        }
        model.files.reinspectOpenPgp()
    }

    /** Saves or shares the certificate as an armored PUBLIC KEY BLOCK. */
    fun export(fingerprint: String, share: Boolean) = run(if (share) "分享公開金鑰" else "匯出公開金鑰") {
        val e = entry(fingerprint) ?: return@run
        val armored = OpenPgpPackets.armor("PUBLIC KEY BLOCK", e.certificate.fromBase64()).encodeToByteArray()
        val name = "0x" + e.fingerprint.takeLast(16) + ".asc"
        val done = if (share) model.platform.shareFile(name, "application/pgp-keys", armored) else model.platform.saveFile(name, "application/pgp-keys", armored)
        if (!done) model.message.value = if (share) "未分享" else "未匯出"
    }

    // ---------------------------------------------------------------- lookup

    /**
     * Looks a key up: an e-mail address in its domain's Web Key Directory first, then on keys.openpgp.org; a
     * fingerprint or key ID on keys.openpgp.org. Only certificates that hold what was asked for are offered.
     */
    fun lookup(query: String) = run("查詢公開金鑰") {
        found.value = null
        found.value = search(query)
    }

    suspend fun search(query: String): OpenPgpFound {
        val q = query.trim()
        val hex = q.removePrefix("0x").removePrefix("0X").filter { !it.isWhitespace() }.uppercase()
        val isHex = hex.isNotEmpty() && hex.all { it in "0123456789ABCDEF" }
        return when {
            isHex && (hex.length == 40 || hex.length == 16) -> {
                val path = if (hex.length == 40) "by-fingerprint/$hex" else "by-keyid/$hex"
                val keys = fetch("$VKS/vks/v1/$path")?.let { OpenPgp.certificates(it) }.orEmpty().filter { it.first.has(hex) }
                OpenPgpFound(q, "keys.openpgp.org", keys)
            }
            Regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$").matches(q) -> {
                val wkd = runCatching { wkd(q) }.getOrNull().orEmpty().filter { k -> k.first.userIds.any { q.lowercase() in it.lowercase() } }
                if (wkd.isNotEmpty()) OpenPgpFound(q, "Web Key Directory（" + q.substringAfter('@').lowercase() + "）", wkd)
                else OpenPgpFound(q, "keys.openpgp.org", fetch("$VKS/vks/v1/by-email/" + q.encodeURLPathPart())
                    ?.let { OpenPgp.certificates(it) }.orEmpty().filter { k -> k.first.userIds.any { q.lowercase() in it.lowercase() } })
            }
            else -> throw SigningException("請輸入 40 位指紋、16 位金鑰 ID 或電子郵件地址")
        }
    }

    /** The certificates a domain publishes for [email] (advanced method first, then direct). */
    private suspend fun wkd(email: String): List<Pair<OpenPgpKeyInfo, ByteArray>> {
        val local = email.substringBeforeLast('@')
        val domain = email.substringAfterLast('@').lowercase()
        val hash = zBase32(DocCrypto.digest("SHA-1", local.lowercase().encodeToByteArray()))
        val l = local.encodeURLParameter()
        val urls = listOf(
            "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/hu/$hash?l=$l",
            "https://$domain/.well-known/openpgpkey/hu/$hash?l=$l",
        )
        for (u in urls) {
            val bytes = runCatching { fetch(u) }.getOrNull() ?: continue
            val certs = runCatching { OpenPgp.certificates(bytes) }.getOrNull().orEmpty()
            if (certs.isNotEmpty()) return certs
        }
        return emptyList()
    }

    /** The body of [url], null when not found; anything over [MAX_KEY_BYTES] is refused. */
    private suspend fun fetch(url: String): ByteArray? {
        val r = model.http.get(url)
        if (r.status == HttpStatusCode.NotFound) return null
        if (!r.status.isSuccess()) throw SigningException("查詢失敗（HTTP ${r.status.value}）")
        val body = r.readRawBytes()
        if (body.size > MAX_KEY_BYTES) throw SigningException("回傳的公開金鑰超過 ${MAX_KEY_BYTES / 1024} KB，已拒絕")
        return body.takeIf { it.isNotEmpty() }
    }

    /** Adds the keys of the last lookup as unverified. */
    fun acceptFound() = run("加入查到的公開金鑰") {
        val f = found.value ?: return@run
        f.keys.forEach { (info, cert) -> put(info, cert, OpenPgpTrust.UNVERIFIED, f.source) }
        found.value = null
        model.message.value = "已加入 ${f.keys.size} 把公開金鑰（未核對，請與持有人核對指紋）"
        model.files.reinspectOpenPgp()
    }

    fun dismissFound() {
        found.value = null
    }

    companion object {
        private val keyTable = StorageTableSpec(name = "DiwOpenPgpKeys", supportPartitions = false, supportExpiration = false)
        private val certTable = StorageTableSpec(name = "DiwOpenPgpCardCerts", supportPartitions = false, supportExpiration = false)
        const val VKS = "https://keys.openpgp.org"
        private const val MAX_KEY_BYTES = 1024 * 1024

        /** Refused keys first, then the own card, compared fingerprints and unverified keys; newest first within each. */
        private val ORDER = compareBy<OpenPgpKeyEntry>({ if (it.trust == OpenPgpTrust.DISTRUSTED) -1 else it.trust.ordinal }, { -it.addedAt })

        /** What to tell the user before a tap on [reader]. */
        fun tapMessage(reader: NfcReaderOption, purpose: String): String =
            if (reader.external) "請讓 OpenPGP 卡或 YubiKey 透過「${reader.name}」保持接上，$purpose，完成前請勿拔除。"
            else "請將 OpenPGP 卡或 YubiKey 貼近手機背面的 NFC 感應區，$purpose，讀取期間保持貼合不要移動。"

        /** z-base-32 (RFC 6189) of [b], as the Web Key Directory names its files. */
        fun zBase32(b: ByteArray): String {
            val alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
            val out = StringBuilder()
            var buffer = 0
            var bits = 0
            for (x in b) {
                buffer = (buffer shl 8) or (x.toInt() and 0xFF)
                bits += 8
                while (bits >= 5) {
                    out.append(alphabet[(buffer shr (bits - 5)) and 0x1F])
                    bits -= 5
                }
            }
            if (bits > 0) out.append(alphabet[(buffer shl (5 - bits)) and 0x1F])
            return out.toString()
        }
    }
}

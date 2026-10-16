package diw.wallet.core.document.card

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException

/**
 * Taiwan GPKI smart cards (citizen digital certificate MOICA, and organisation cards that share the layout) as used
 * by the government's card middleware: a PKCS#15 structure under DF 5030 and RSA-2048 keys in EF 0810.
 *
 * Two generations exist. The first (CLA 80) takes the PIN encrypted with a fixed triple-DES key. The second (the
 * GPPKI applet, CLA 00) requires a GlobalPlatform SCP03 secure channel, with static keys diversified from the card
 * identifier, for the PIN and every private key operation. This is an independent implementation of the publicly
 * documented command sequences; it reads certificates without the PIN and signs only after a PIN the user typed.
 */
class GpkiCard(private val channel: CardChannel) {
    enum class Generation { GEN1, GEN2 }

    /** A signing key on the card with its certificate. */
    class KeyInfo(val label: String, val id: ByteArray, val keyRef: Int, val certificate: ByteArray)

    var generation: Generation = Generation.GEN1
        private set
    private var cla = 0x80
    private var scp: Scp03? = null

    /** Selects the card application and finds out its generation. */
    suspend fun connect(): Generation {
        if (channel.transmit(0x00, 0xA4, 0x04, 0x0C, GPPKI_AID, 256).ok) {
            generation = Generation.GEN2; cla = 0x00
            return generation
        }
        for (c in listOf(0x80, 0x00)) {
            if (channel.transmit(c, 0xA4, 0x00, 0x00, byteArrayOf(0x3F, 0x00), 0).ok) {
                generation = Generation.GEN1; cla = c
                return generation
            }
        }
        throw SigningException("這張卡片不是自然人憑證或政府憑證卡（找不到 GPKI 應用程式）")
    }

    private suspend fun selectMf() {
        val ok = if (generation == Generation.GEN2) channel.transmit(0x00, 0xA4, 0x04, 0x0C, GPPKI_AID, 256).ok
        else channel.transmit(cla, 0xA4, 0x00, 0x00, byteArrayOf(0x3F, 0x00), 0).ok
        if (!ok) throw SigningException("無法選取卡片的應用程式")
    }

    private suspend fun selectFid(fid: Int): Boolean {
        val r = if (generation == Generation.GEN2) channel.transmit(cla, 0xA4, 0x00, 0x04, byteArrayOf((fid shr 8).toByte(), fid.toByte()), 256)
        else channel.transmit(cla, 0xA4, 0x00, 0x00, byteArrayOf((fid shr 8).toByte(), fid.toByte()), 0)
        return r.ok || r.warning
    }

    private suspend fun selectPath(path: ByteArray) {
        var i = 0
        if (path.size >= 2 && path[0] == 0x3F.toByte() && path[1] == 0x00.toByte()) { selectMf(); i = 2 }
        else if (path.size > 2) selectMf()
        else { selectMf(); if (!selectFid(CARD_DF)) throw SigningException("無法選取卡片目錄") }
        while (i + 1 < path.size) {
            val fid = ((path[i].toInt() and 0xFF) shl 8) or (path[i + 1].toInt() and 0xFF)
            if (fid == 0x7FFF && generation == Generation.GEN2) selectMf()
            else if (!selectFid(fid)) throw SigningException("無法選取卡片檔案 " + DocCryptoUtil.hex(path))
            i += 2
        }
    }

    private suspend fun readBinary(offset: Int, want: Int): ByteArray? {
        var w = want
        while (true) {
            val r = channel.transmit(cla, 0xB0, (offset shr 8) and 0x7F, offset and 0xFF, ByteArray(0), w)
            if (r.sw == 0x6987 && w > 16) { w = 16; continue }
            return if (r.ok || r.warning) r.data else null
        }
    }

    private suspend fun readRange(offset: Int, length: Int): ByteArray {
        var out = ByteArray(0)
        var off = offset
        while (out.size < length) {
            val want = minOf(CHUNK, length - out.size)
            val got = readBinary(off, want) ?: break
            if (got.isEmpty()) break
            out += got
            off += got.size
            if (got.size < want) break
        }
        return out
    }

    /** A PKCS#15 directory file under DF 5030, up to the padding after its last record. */
    private suspend fun readDirectory(fid: Int): ByteArray {
        selectMf()
        if (!selectFid(CARD_DF) || !selectFid(fid)) return ByteArray(0)
        var buf = ByteArray(0)
        var off = 0
        while (buf.size < 16 * 1024) {
            val got = readBinary(off, CHUNK) ?: break
            if (got.isEmpty()) break
            buf += got
            off += got.size
            Der.recordsEnd(buf)?.let { return buf.copyOf(it) }
            if (got.size < CHUNK) break
        }
        return buf
    }

    /** The signing key (PKCS#15 PrKDF entry with sign usage, preferring the one labelled SIGN) and its certificate. */
    suspend fun signingKey(): KeyInfo {
        val keys = Der.records(readDirectory(PRKDF)).mapNotNull { parseKey(it) }
        val certs = Der.records(readDirectory(CDF)).mapNotNull { parseCert(it) }
        if (keys.isEmpty() || certs.isEmpty()) throw SigningException("讀不到卡片上的金鑰或憑證")
        val key = keys.filter { it.canSign }.let { s -> s.firstOrNull { it.id.contentEquals(SIGN_ID) || it.label.contains("SIGN", true) } ?: s.firstOrNull() }
            ?: keys.first()
        val cert = certs.firstOrNull { it.first.contentEquals(key.id) } ?: certs.first()
        selectPath(cert.second.path)
        val raw = readRange(cert.second.index, if (cert.second.length > 0) cert.second.length else 4096)
        val der = Der.firstObject(raw) ?: throw SigningException("卡片上的憑證格式錯誤")
        return KeyInfo(key.label, key.id, key.keyRef, der)
    }

    /**
     * RSASSA-PKCS1-v1_5 over a SHA-256 [digest]: verifies the PIN, then has the card apply its private key to the
     * padded DigestInfo. A wrong PIN stops at once with the remaining tries; the PIN is not kept.
     */
    suspend fun signSha256(pin: String, keyRef: Int, digest: ByteArray): ByteArray {
        require(digest.size == 32)
        val block = pkcs1Block(SHA256_DIGEST_INFO + digest)
        return when (generation) {
            Generation.GEN2 -> {
                openScp03()
                smVerify(pin)
                smSelect(CARD_DF)
                smSelect(KEY_EF)
                var out = ByteArray(0)
                for (i in 0 until 2) {
                    val more = i == 0
                    val r = sm(0x80, 0xEA, if (more) 0x82 else 0x02, keyRef, block.copyOfRange(i * 128, i * 128 + 128), if (more) 0 else 0x80, true)
                    if (!r.ok) throw SigningException("卡片拒絕簽章（${hex4(r.sw)}）")
                    out += r.data
                }
                var guard = 0
                while (out.size < RSA_LEN && guard++ < 4) {
                    val r = sm(0x80, 0xC1, 0x00, 0x80, ByteArray(0), 0x80, false)
                    if (!r.ok || r.data.isEmpty()) throw SigningException("讀取簽章結果失敗（${hex4(r.sw)}）")
                    out += r.data
                }
                if (out.size < RSA_LEN) throw SigningException("卡片回傳的簽章長度不正確")
                out.copyOf(RSA_LEN)
            }
            Generation.GEN1 -> {
                selectKeyEf()
                gen1Verify(pin)
                var out = ByteArray(0)
                for (i in 0 until 2) {
                    val r = channel.transmit(0x80, 0xEA, if (i == 0) 0x82 else 0x02, keyRef, block.copyOfRange(i * 128, i * 128 + 128), 0)
                    if (!r.ok) throw SigningException("卡片拒絕簽章（${hex4(r.sw)}）")
                    out += r.data
                }
                var guard = 0
                while (out.size < RSA_LEN && guard++ < 4) {
                    val off = out.size
                    val want = minOf(128, RSA_LEN - off)
                    val r = channel.transmit(0x80, 0xC1, off shr 8, off and 0xFF, ByteArray(0), want)
                    if (!r.ok || r.data.isEmpty()) throw SigningException("讀取簽章結果失敗（${hex4(r.sw)}）")
                    out += r.data
                }
                if (out.size != RSA_LEN) throw SigningException("卡片回傳的簽章長度不正確")
                out
            }
        }
    }

    private suspend fun selectKeyEf() {
        if (selectFid(KEY_EF)) return
        selectMf()
        if (!selectFid(CARD_DF) || !selectFid(KEY_EF)) throw SigningException("無法選取卡片的金鑰檔")
    }

    private fun pinBytes(pin: String): ByteArray {
        if (pin.length !in PIN_MIN..PIN_MAX || pin.any { it.code > 0x7E || it.code < 0x20 }) throw SigningException("PIN 碼格式不正確（應為 $PIN_MIN 至 $PIN_MAX 碼）")
        val b = ByteArray(PIN_MAX) { 0xFF.toByte() }
        pin.encodeToByteArray().copyInto(b)
        return b
    }

    private fun pinResult(sw: Int) {
        when {
            sw == 0x9000 -> {}
            sw == 0x6983 -> throw SigningException("PIN 碼已鎖定，請到戶政事務所或以 PUK 解鎖")
            sw and 0xFFF0 == 0x63C0 -> {
                val left = sw and 0x0F
                throw SigningException(if (left == 0) "PIN 碼錯誤，卡片已鎖定" else "PIN 碼錯誤，還可以再試 $left 次。為避免鎖卡，已停止簽署。")
            }
            else -> throw SigningException("卡片拒絕 PIN 驗證（${hex4(sw)}）")
        }
    }

    private suspend fun gen1Verify(pin: String) {
        val iv = DocCrypto.randomBytes(8)
        val pb = pinBytes(pin)
        val r = channel.transmit(0x8C, 0x20, 0x00, 0x01, iv + gen1PinBlock(pb, iv), 0)
        pinResult(r.sw)
    }

    // ---- GPPKI (second generation): SCP03 ----

    private class Scp03(val sEnc: ByteArray, val sMac: ByteArray, var mcv: ByteArray, var counter: Int)

    private suspend fun staticKeys(): Pair<ByteArray, ByteArray> {
        if (!channel.transmit(0x00, 0xA4, 0x04, 0x00, ISD_CM_AID, 0).let { it.ok || it.warning }) throw SigningException("無法選取卡片管理程式")
        val e0 = channel.transmit(0x80, 0xCA, 0x00, 0xE0, ByteArray(0), 256)
        if (!e0.ok || e0.data.size < 8 || e0.data[0] != 0xE0.toByte() || e0.data[7].toInt() != 16) throw SigningException("卡片的安全通道參數不支援")
        if (!channel.transmit(0x00, 0xA4, 0x04, 0x00, ISD_AID, 0).let { it.ok || it.warning }) throw SigningException("無法選取卡片管理程式")
        val t45 = channel.transmit(0x80, 0xCA, 0x00, 0x45, ByteArray(0), 256)
        if (!t45.ok || t45.data.size < 12 || t45.data[0] != 0x45.toByte() || t45.data[1] != 0x0A.toByte()) throw SigningException("讀不到卡片識別碼")
        val cardId = t45.data.copyOfRange(2, 12)
        return diversify(cardId)
    }

    private suspend fun openScp03() {
        scp = null
        val (kEnc, kMac) = staticKeys()
        if (!channel.transmit(0x00, 0xA4, 0x04, 0x0C, GPPKI_AID, 256).ok) throw SigningException("無法選取卡片的應用程式")
        val host = DocCrypto.randomBytes(8)
        val iu = channel.transmit(0x80, 0x50, 0x01, 0x00, host, 256)
        if (!iu.ok || iu.data.size < 29 || iu.data[11].toInt() != 0x03) throw SigningException("卡片不接受安全通道（${hex4(iu.sw)}）")
        val session = establish(kEnc, kMac, host, iu.data.copyOfRange(13, 21), iu.data.copyOfRange(21, 29))
            ?: throw SigningException("卡片的安全通道驗證失敗")
        val ea = channel.transmit(0x84, 0x82, 0x03, 0x00, session.second, 0)
        if (!ea.ok) throw SigningException("卡片拒絕安全通道（${hex4(ea.sw)}）")
        scp = session.first
    }

    private suspend fun sm(cla0: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int, encrypt: Boolean): CardResponse {
        val s = scp ?: throw SigningException("安全通道尚未建立")
        val (header, body) = wrap(s, cla0, ins, p1, p2, data, encrypt)
        return channel.transmit(header[0].toInt() and 0xFF, ins, p1, p2, body, le)
    }

    private suspend fun smVerify(pin: String) = pinResult(sm(0x00, 0x20, 0x00, 0x01, pinBytes(pin), 0, true).sw)

    private suspend fun smSelect(fid: Int) {
        val r = sm(0x00, 0xA4, 0x00, 0x04, byteArrayOf((fid shr 8).toByte(), fid.toByte()), 0, true)
        if (!r.ok && !r.warning) throw SigningException("無法選取卡片的金鑰檔（${hex4(r.sw)}）")
    }

    // ---- PKCS#15 ----

    private class Path(val path: ByteArray, val index: Int, val length: Int)
    private class Key(val label: String, val id: ByteArray, val keyRef: Int, val canSign: Boolean)

    private fun parseKey(entry: Der.Tlv): Key? {
        val parts = Der.children(entry.value)
        if (parts.size < 2) return null
        val label = Der.children(parts[0].value).firstOrNull { it.tag in setOf(0x0C, 0x13, 0x16) }?.value?.decodeToString()?.trim { it.code == 0 || it.code == 0xFF || it.isWhitespace() }.orEmpty()
        var id = ByteArray(0)
        var usage = 0
        var keyRef = -1
        for (el in Der.children(parts[1].value)) when (el.tag) {
            0x04 -> if (id.isEmpty()) id = el.value
            0x03 -> usage = Der.bits(el.value)
            0x02 -> if (keyRef < 0) keyRef = Der.uint(el.value)
        }
        if (keyRef < 0) {
            // Some cards keep the key reference in the class attributes ([0]) or the type attributes.
            keyRef = parts.drop(2).firstNotNullOfOrNull { p -> Der.findInteger(p.value) { it in 0..255 } } ?: return null
        }
        val canSign = usage and ((1 shl 2) or (1 shl 3) or (1 shl 9)) != 0
        return Key(label, id, keyRef, canSign)
    }

    private fun parseCert(entry: Der.Tlv): Pair<ByteArray, Path>? {
        val parts = Der.children(entry.value)
        if (parts.size < 3) return null
        val id = Der.children(parts[1].value).firstOrNull { it.tag == 0x04 }?.value ?: ByteArray(0)
        val typeAttrs = parts[2]
        val inner = Der.children(typeAttrs.value).firstOrNull() ?: return null
        val pathSeq = Der.children(inner.value).firstOrNull() ?: return null
        return id to (parsePath(pathSeq) ?: return null)
    }

    private fun parsePath(t: Der.Tlv): Path? {
        if (t.tag != 0x30) return null
        val els = Der.children(t.value)
        val first = els.firstOrNull() ?: return null
        if (first.tag == 0x30) return parsePath(first)
        if (first.tag != 0x04 || first.value.isEmpty()) return null
        var index = 0
        var length = 0
        for (e in els.drop(1)) when (e.tag) {
            0x02 -> index = Der.uint(e.value)
            0x80 -> length = Der.uint(e.value)
        }
        return Path(first.value, index, length)
    }

    companion object {
        /** PIN length accepted by the card; the PIN block is [PIN_MAX] bytes padded with FF. */
        const val PIN_MIN = 6
        const val PIN_MAX = 10
        private const val CHUNK = 0xC8
        private const val RSA_LEN = 256
        private const val CARD_DF = 0x5030
        private const val KEY_EF = 0x0810
        private const val PRKDF = 0x4100
        private const val CDF = 0x4104
        private val SIGN_ID = "SIGN".encodeToByteArray()

        val GPPKI_AID = DocCryptoUtil.unhex("A0000002830000062201696400010101")
        val ISD_CM_AID = DocCryptoUtil.unhex("A000000283FF088692535389C00014")
        val ISD_AID = DocCryptoUtil.unhex("A0000001510000")
        private val MASTER_ENC = DocCryptoUtil.unhex("eee765099e9b8d52a33734760dd0305e")
        private val DIVERSE_KEK = DocCryptoUtil.unhex("434854204869434f53504b4353233131")
        private val GEN1_PIN_KEY = DocCryptoUtil.unhex("434854544c3866304869436172645632")
        val SHA256_DIGEST_INFO = DocCryptoUtil.unhex("3031300d060960864801650304020105000420")

        fun hex4(sw: Int) = sw.toString(16).uppercase().padStart(4, '0')

        /** EMSA-PKCS1-v1_5 encoding of [t] for a 2048-bit key. */
        fun pkcs1Block(t: ByteArray): ByteArray {
            require(t.size <= RSA_LEN - 11)
            val b = ByteArray(RSA_LEN) { 0xFF.toByte() }
            b[0] = 0; b[1] = 1
            b[RSA_LEN - t.size - 1] = 0
            t.copyInto(b, RSA_LEN - t.size)
            return b
        }

        /** Static SCP03 keys (K-ENC, K-MAC) of a card from its 10-byte identifier (ISD tag 45). */
        fun diversify(cardId: ByteArray): Pair<ByteArray, ByteArray> {
            val master = DocCrypto.aesEcb(false, DIVERSE_KEK, MASTER_ENC)
            return deriveKey(master, 0x04, cardId) to deriveKey(master, 0x06, cardId)
        }

        private fun deriveKey(master: ByteArray, constant: Int, cardId: ByteArray): ByteArray {
            require(cardId.size == 10)
            val s = ByteArray(32)
            s[0x10] = when (constant) { 0x04 -> 1; 0x06 -> 2; else -> 3 }.toByte()
            cardId.copyInto(s, 0x11, 0, 10)
            ISD_CM_AID.copyInto(s, 0x1B, 10, 15)
            s[0x0B] = constant.toByte()
            s[0x0D] = 0
            s[0x0E] = 0x80.toByte()
            s[0x0F] = 1
            return DocCryptoUtil.aesCmac(master, s)
        }

        fun kdf(key: ByteArray, constant: Int, context: ByteArray, bits: Int): ByteArray {
            val len = (bits + 7) / 8
            var out = ByteArray(0)
            var counter = 1
            while (out.size < len) {
                val block = ByteArray(11) + byteArrayOf(constant.toByte(), 0, (bits shr 8).toByte(), bits.toByte(), counter.toByte()) + context
                out += DocCryptoUtil.aesCmac(key, block)
                counter++
            }
            return out.copyOf(len)
        }

        /** Session keys and the EXTERNAL AUTHENTICATE data (host cryptogram and C-MAC), or null for a wrong card cryptogram. */
        private fun establish(kEnc: ByteArray, kMac: ByteArray, host: ByteArray, cardChallenge: ByteArray, cardCryptogram: ByteArray): Pair<Scp03, ByteArray>? {
            val context = host + cardChallenge
            val sMac = kdf(kMac, 0x06, context, 128)
            val sEnc = kdf(kEnc, 0x04, context, 128)
            val hostCrypto = kdf(sMac, 0x01, context, 64)
            if (!kdf(sMac, 0x00, context, 64).contentEquals(cardCryptogram)) return null
            val header = byteArrayOf(0x84.toByte(), 0x82.toByte(), 0x03, 0x00, 0x10)
            val mac = DocCryptoUtil.aesCmac(sMac, ByteArray(16) + header + hostCrypto)
            return Scp03(sEnc, sMac, mac, 1) to (hostCrypto + mac.copyOf(8))
        }

        /** A command under SCP03 (C-DECRYPTION and C-MAC): the header with the secure messaging CLA and the body. */
        private fun wrap(s: Scp03, cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, encrypt: Boolean): Pair<ByteArray, ByteArray> {
            val smCla = cla or 0x04
            val cipher = if (encrypt && data.isNotEmpty()) {
                val counterBlock = ByteArray(16).also {
                    it[12] = (s.counter ushr 24).toByte(); it[13] = (s.counter ushr 16).toByte(); it[14] = (s.counter ushr 8).toByte(); it[15] = s.counter.toByte()
                }
                val iv = DocCrypto.aesEcb(true, s.sEnc, counterBlock)
                s.counter++
                DocCrypto.aesCbc(true, s.sEnc, iv, pad80(data))
            } else ByteArray(0)
            val header = byteArrayOf(smCla.toByte(), ins.toByte(), p1.toByte(), p2.toByte(), (cipher.size + 8).toByte())
            val mac = DocCryptoUtil.aesCmac(s.sMac, s.mcv + header + cipher)
            s.mcv = mac
            return header to (cipher + mac.copyOf(8))
        }

        /** Test hook: the body of a wrapped command for a session made from known challenges. */
        fun wrapForTest(kEnc: ByteArray, kMac: ByteArray, host: ByteArray, cardChallenge: ByteArray, data: ByteArray): ByteArray {
            val context = host + cardChallenge
            val sMac = kdf(kMac, 0x06, context, 128)
            val cardCrypto = kdf(sMac, 0x00, context, 64)
            val (s, _) = establish(kEnc, kMac, host, cardChallenge, cardCrypto)!!
            return wrap(s, 0x00, 0x20, 0x00, 0x01, data, true).second
        }

        private fun pad80(d: ByteArray): ByteArray {
            val n = (d.size / 16 + 1) * 16
            val out = d.copyOf(n)
            out[d.size] = 0x80.toByte()
            return out
        }

        /** First generation PIN block: 3DES-CBC(PIN padded with FF to 10 bytes, CBC-MAC of it), with PKCS#5-style padding. */
        fun gen1PinBlock(pin10: ByteArray, iv: ByteArray): ByteArray {
            fun pad(d: ByteArray): ByteArray { val p = 8 - d.size % 8; return d + ByteArray(p) { p.toByte() } }
            val macInput = pad(pin10)
            val mac = DocCrypto.desEdeCbc(true, GEN1_PIN_KEY, iv, macInput).let { it.copyOfRange(it.size - 8, it.size) }
            return DocCrypto.desEdeCbc(true, GEN1_PIN_KEY, iv, pad(pin10 + mac))
        }
    }
}

/**
 * A [DocumentSigner] backed by a GPKI card in the reader now. The PIN is held only for this signing session and
 * the card must stay on the reader until the signature is made.
 */
class GpkiCardSigner(
    private val card: GpkiCard,
    private val key: GpkiCard.KeyInfo,
    private val pin: String,
    intermediates: List<ByteArray> = emptyList(),
) : DocumentSigner {
    override val certificateChain: List<ByteArray> = listOf(key.certificate) + intermediates
    override val keyType = SignerKeyType.RSA
    override val source = SignerSource.SMART_CARD

    override suspend fun sign(data: ByteArray): ByteArray = card.signSha256(pin, key.keyRef, DocCrypto.digest("SHA-256", data))
}

/** Minimal DER reading for PKCS#15 directory files. */
internal object Der {
    class Tlv(val tag: Int, val value: ByteArray, val headerLength: Int) {
        val totalLength get() = headerLength + value.size
    }

    fun read(b: ByteArray, off: Int): Tlv? {
        if (off + 2 > b.size) return null
        var p = off
        val tag = b[p++].toInt() and 0xFF
        if (tag and 0x1F == 0x1F) return null
        var len = b[p++].toInt() and 0xFF
        if (len and 0x80 != 0) {
            val n = len and 0x7F
            if (n == 0 || n > 3 || p + n > b.size) return null
            len = 0
            repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xFF) }
        }
        if (p + len > b.size) return null
        return Tlv(tag, b.copyOfRange(p, p + len), p - off)
    }

    fun children(b: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var off = 0
        while (off < b.size) {
            val t = read(b, off) ?: break
            out.add(t)
            off += t.totalLength
        }
        return out
    }

    /** Top-level SEQUENCE records until padding (00 or FF). */
    fun records(b: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var off = 0
        while (off < b.size && b[off] != 0.toByte() && b[off] != 0xFF.toByte()) {
            val t = read(b, off) ?: break
            if (t.tag == 0x30) out.add(t)
            off += t.totalLength
        }
        return out
    }

    fun recordsEnd(b: ByteArray): Int? {
        var off = 0
        while (off < b.size) {
            if (b[off] == 0.toByte() || b[off] == 0xFF.toByte()) return off
            val t = read(b, off) ?: return null
            off += t.totalLength
        }
        return null
    }

    fun firstObject(b: ByteArray): ByteArray? = read(b, 0)?.let { b.copyOf(it.totalLength) }

    fun uint(v: ByteArray): Int = v.takeLast(4).fold(0) { a, x -> (a shl 8) or (x.toInt() and 0xFF) }

    /** BIT STRING flags with bit 0 being the first named bit. */
    fun bits(v: ByteArray): Int {
        var bits = 0
        for (i in 1 until minOf(v.size, 5)) for (j in 0 until 8) if (v[i].toInt() and (0x80 shr j) != 0) bits = bits or (1 shl ((i - 1) * 8 + j))
        return bits
    }

    /** The first INTEGER in a nested structure that satisfies [accept]. */
    fun findInteger(b: ByteArray, accept: (Int) -> Boolean): Int? {
        for (t in children(b)) {
            if (t.tag == 0x02) { val v = uint(t.value); if (accept(v)) return v }
            if (t.tag and 0x20 != 0) findInteger(t.value, accept)?.let { return it }
        }
        return null
    }
}

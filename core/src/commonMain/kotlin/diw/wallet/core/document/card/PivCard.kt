package diw.wallet.core.document.card

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.jose.PlatformCrypto

/**
 * A PIV card (NIST SP 800-73-4), as a YubiKey, PIVKey, Nitrokey or a US PIV/CAC card presents over USB or NFC. This
 * is an independent implementation of the publicly documented command set, not a YubiKey library: SELECT the PIV
 * application, GET DATA for a slot's X.509 certificate, VERIFY the PIN, and GENERAL AUTHENTICATE to sign. It reads
 * a certificate without the PIN and signs only after a PIN the user typed. RSA-2048 and EC P-256 keys are supported;
 * other key sizes and curves are refused because the document formats this wallet writes cannot use them. Every slot
 * the standard defines is read, not only a card's first one, so any certificate on the card can be chosen.
 */
class PivCard(private val channel: CardChannel) {
    /** A PIV key slot, the certificate it holds and a human label for the slot. */
    class KeyInfo(val slot: Int, val keyType: SignerKeyType, val certificate: ByteArray, val slotName: String)

    /** Selects the PIV application. */
    suspend fun connect() {
        if (!channel.transmit(0x00, 0xA4, 0x04, 0x00, PIV_AID, 256).let { it.ok || it.warning }) {
            throw SigningException("這張卡片不是 PIV 卡（找不到 PIV 應用程式）")
        }
    }

    /**
     * The certificate and key type of the first usable slot, trying Digital Signature (9C) then PIV Authentication
     * (9A), Key Management (9D), Card Authentication (9E) and the retired Key Management slots (82-95); or the one
     * slot [only], when given.
     */
    suspend fun signingKey(only: Int? = null): KeyInfo {
        val slots = only?.let { listOf(it) } ?: ALL_SLOTS
        var lastError: String? = null
        for (slot in slots) {
            val cert = runCatching { readCertificate(slot) }.getOrElse { lastError = it.message; null } ?: continue
            val type = runCatching { keyTypeOf(cert) }.getOrElse { lastError = it.message; null } ?: continue
            return KeyInfo(slot, type, cert, slotName(slot))
        }
        throw SigningException(lastError ?: "這張 PIV 卡沒有可用的簽章憑證")
    }

    /**
     * Every slot this card holds a usable certificate in (RSA-2048 or EC P-256), in the standard's slot order, so the
     * user can pick which certificate to sign with instead of the wallet choosing one. A slot without a certificate or
     * with an unsupported key is skipped.
     */
    suspend fun allSigningKeys(): List<KeyInfo> = ALL_SLOTS.mapNotNull { slot ->
        val cert = runCatching { readCertificate(slot) }.getOrNull() ?: return@mapNotNull null
        val type = runCatching { keyTypeOf(cert) }.getOrNull() ?: return@mapNotNull null
        KeyInfo(slot, type, cert, slotName(slot))
    }

    /** GET DATA for the X.509 certificate object of [slot]; decompresses it when the CertInfo byte says gzip. */
    private suspend fun readCertificate(slot: Int): ByteArray {
        val oid = CERT_OID[slot] ?: throw SigningException("不支援的 PIV 金鑰槽")
        val r = channel.transmit(0x00, 0xCB, 0x3F, 0xFF, byteArrayOf(0x5C, 0x03) + oid, 256)
        if (!r.ok) throw SigningException(if (r.sw == 0x6A82) "這個金鑰槽沒有憑證" else "讀取 PIV 憑證失敗（${hex4(r.sw)}）")
        val outer = Der.read(r.data, 0) ?: throw SigningException("PIV 憑證資料格式錯誤")
        if (outer.tag != 0x53) throw SigningException("PIV 憑證資料格式錯誤")
        var cert: ByteArray? = null
        var gzip = false
        for (t in Der.children(outer.value)) when (t.tag) {
            0x70 -> cert = t.value
            0x71 -> gzip = t.value.isNotEmpty() && (t.value[0].toInt() and 0x01) == 1
        }
        val der = cert ?: throw SigningException("PIV 憑證資料沒有憑證")
        if (der.isEmpty()) throw SigningException("這個金鑰槽沒有憑證")
        return if (gzip) runCatching { PlatformCrypto.gunzip(der, 64 * 1024) }.getOrElse { throw SigningException("PIV 憑證為壓縮格式且無法解壓", it) } else der
    }

    /**
     * Signs with the key in [slot]: for RSA the padded EMSA-PKCS1-v1_5 block of the SHA-256 DigestInfo, returning the
     * raw RSA signature; for EC P-256 the 32-byte hash, returning the DER ECDSA signature. The PIN is verified first
     * and is not kept; a wrong PIN stops with the remaining tries.
     */
    suspend fun sign(pin: String, key: KeyInfo, sha256: ByteArray): ByteArray {
        require(sha256.size == 32)
        verifyPin(pin)
        val (alg, payload) = when (key.keyType) {
            SignerKeyType.RSA -> 0x07 to GpkiCard.pkcs1Block(GpkiCard.SHA256_DIGEST_INFO + sha256)
            SignerKeyType.EC_P256 -> 0x11 to sha256
        }
        // Dynamic authentication template: 7C { 82 (empty response) 81 (data to sign) }.
        val inner = berTag(0x82, ByteArray(0)) + berTag(0x81, payload)
        val template = berTag(0x7C, inner)
        val resp = generalAuthenticate(alg, key.slot, template)
        val top = Der.read(resp, 0) ?: throw SigningException("PIV 簽章回應格式錯誤")
        if (top.tag != 0x7C) throw SigningException("PIV 簽章回應格式錯誤")
        val sig = Der.children(top.value).firstOrNull { it.tag == 0x82 }?.value
            ?: throw SigningException("PIV 簽章回應沒有簽章值")
        if (key.keyType == SignerKeyType.RSA && sig.size != RSA_LEN) throw SigningException("PIV 回傳的 RSA 簽章長度不正確")
        return sig
    }

    /** VERIFY the PIV application PIN (reference 0x80), padded to 8 bytes with 0xFF. */
    private suspend fun verifyPin(pin: String) {
        if (pin.length !in PIN_MIN..PIN_MAX || pin.any { it.code !in 0x20..0x7E }) {
            throw SigningException("PIN 碼格式不正確（應為 $PIN_MIN 至 $PIN_MAX 碼）")
        }
        val block = ByteArray(8) { 0xFF.toByte() }
        pin.encodeToByteArray().copyInto(block)
        val r = channel.transmit(0x00, 0x20, 0x00, 0x80, block, 0)
        when {
            r.ok -> {}
            r.sw == 0x6983 || r.sw == 0x6984 -> throw SigningException("PIN 碼已鎖定，請以 PUK 解鎖")
            r.sw and 0xFFF0 == 0x63C0 -> {
                val left = r.sw and 0x0F
                throw SigningException(if (left == 0) "PIN 碼錯誤，卡片已鎖定" else "PIN 碼錯誤，還可以再試 $left 次。為避免鎖卡，已停止簽署。")
            }
            else -> throw SigningException("PIV 卡拒絕 PIN 驗證（${hex4(r.sw)}）")
        }
    }

    /** GENERAL AUTHENTICATE, using command chaining (CLA 0x10) when the template is longer than one short APDU. */
    private suspend fun generalAuthenticate(alg: Int, slot: Int, template: ByteArray): ByteArray {
        if (template.size <= 255) {
            val r = channel.transmit(0x00, 0x87, alg, slot, template, 256)
            if (!r.ok) throw SigningException("PIV 卡拒絕簽章（${hex4(r.sw)}）")
            return r.data
        }
        var off = 0
        while (off < template.size) {
            val end = minOf(off + 255, template.size)
            val last = end == template.size
            val chunk = template.copyOfRange(off, end)
            val r = channel.transmit(if (last) 0x00 else 0x10, 0x87, alg, slot, chunk, if (last) 256 else 0)
            if (last) {
                if (!r.ok) throw SigningException("PIV 卡拒絕簽章（${hex4(r.sw)}）")
                return r.data
            }
            if (!r.ok && !r.warning) throw SigningException("PIV 卡拒絕簽章指令（${hex4(r.sw)}）")
            off = end
        }
        throw SigningException("PIV 簽章指令未完成")
    }

    companion object {
        const val PIN_MIN = 6
        const val PIN_MAX = 8
        const val SLOT_AUTH = 0x9A
        const val SLOT_SIGNATURE = 0x9C
        const val SLOT_KEY_MGMT = 0x9D
        const val SLOT_CARD_AUTH = 0x9E
        private const val RSA_LEN = 256

        val PIV_AID = DocCryptoUtil.unhex("A000000308000010000100")

        /** The retired Key Management slots (NIST SP 800-73-4 part 1): 0x82 through 0x95, twenty slots. */
        private val RETIRED_SLOTS = (0x82..0x95).toList()

        /** Every slot that can hold a signing certificate, in the order the wallet tries them. */
        val ALL_SLOTS = listOf(SLOT_SIGNATURE, SLOT_AUTH, SLOT_KEY_MGMT, SLOT_CARD_AUTH) + RETIRED_SLOTS

        /**
         * X.509 certificate object identifiers (NIST SP 800-73-4 part 1 table 3) for each key slot: the four primary
         * slots, then the retired Key Management slots 0x82..0x95 at 5FC10D..5FC120.
         */
        private val CERT_OID: Map<Int, ByteArray> = buildMap {
            put(SLOT_AUTH, DocCryptoUtil.unhex("5FC105"))
            put(SLOT_SIGNATURE, DocCryptoUtil.unhex("5FC10A"))
            put(SLOT_KEY_MGMT, DocCryptoUtil.unhex("5FC10B"))
            put(SLOT_CARD_AUTH, DocCryptoUtil.unhex("5FC101"))
            RETIRED_SLOTS.forEachIndexed { i, slot ->
                val last = (0x0D + i).toByte()
                put(slot, byteArrayOf(0x5F, 0xC1.toByte(), last))
            }
        }

        /** A human label for a slot, for the certificate chooser. */
        fun slotName(slot: Int): String = when (slot) {
            SLOT_AUTH -> "PIV 認證（9A）"
            SLOT_SIGNATURE -> "數位簽章（9C）"
            SLOT_KEY_MGMT -> "金鑰管理（9D）"
            SLOT_CARD_AUTH -> "卡片認證（9E）"
            in RETIRED_SLOTS -> "保留金鑰管理 ${slot - 0x81}（${hex2(slot)}）"
            else -> hex2(slot)
        }

        private fun hex2(v: Int) = v.toString(16).uppercase().padStart(2, '0')

        fun hex4(sw: Int) = sw.toString(16).uppercase().padStart(4, '0')

        /**
         * RSA-2048 or EC P-256 from the certificate; other keys are refused. The RSA modulus must be exactly 2048
         * bits: [sign] uses the RSA-2048 algorithm identifier, a 256-byte padded block and a 256-byte signature, so a
         * 1024/3072/4096-bit key would fail at signing. Refusing it here lets the slot be skipped and the next usable
         * certificate be found, instead of stopping on a key that cannot sign.
         */
        fun keyTypeOf(certificate: ByteArray): SignerKeyType {
            PlatformCrypto.rsaPublicKeyFromCertificate(certificate)?.let { rsa ->
                val bits = rsaModulusBits(rsa.modulus)
                if (bits != 2048) throw SigningException("PIV 憑證的 RSA 金鑰長度（$bits 位元）不支援，只支援 RSA-2048 與 EC P-256")
                return SignerKeyType.RSA
            }
            val ec = runCatching { org.multipaz.crypto.X509Cert(kotlinx.io.bytestring.ByteString(certificate)).ecPublicKey }.getOrNull()
                ?: throw SigningException("無法讀取 PIV 憑證的公開金鑰")
            if (ec.curve != org.multipaz.crypto.EcCurve.P256) throw SigningException("PIV 憑證的金鑰（${ec.curve.name}）不支援，只支援 RSA 與 EC P-256")
            return SignerKeyType.EC_P256
        }

        /** A BER-TLV element with a definite length (short or long form). */
        fun berTag(tag: Int, value: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + berLength(value.size) + value

        private fun berLength(n: Int): ByteArray = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }

        /** Bit length of an RSA modulus, ignoring any leading zero sign byte. */
        private fun rsaModulusBits(modulus: ByteArray): Int {
            var i = 0
            while (i < modulus.size && modulus[i] == 0.toByte()) i++
            if (i >= modulus.size) return 0
            val top = modulus[i].toInt() and 0xFF
            var highBit = 7
            while (highBit > 0 && (top shr highBit) == 0) highBit--
            return (modulus.size - i - 1) * 8 + highBit + 1
        }
    }
}

/**
 * A [DocumentSigner] backed by a PIV card read through any [NfcTagReader] (phone NFC, USB CCID, PC/SC). [load] reads
 * the signing certificate on a first tap; each [sign] is a further tap. The PIN is held only by this object for one
 * signing session, and every signature is checked against the certificate read at [load], so a different card is
 * refused. [slot] chooses which PIV slot to use; null lets the card's first usable slot answer.
 */
class PivTapSigner(
    private val reader: org.multipaz.nfc.NfcTagReader,
    private val pin: String,
    private val slot: Int? = null,
    private val intermediates: List<ByteArray> = emptyList(),
    private val tapMessage: String = "請將 PIV 卡（IC 晶片面）貼近 NFC 感應區，讀取期間請保持貼合、不要移動卡片。",
) : DocumentSigner {
    private var key: PivCard.KeyInfo? = null

    override val certificateChain: List<ByteArray>
        get() = listOf((key ?: throw SigningException("尚未讀取卡片憑證")).certificate) + intermediates
    override val keyType: SignerKeyType get() = (key ?: throw SigningException("尚未讀取卡片憑證")).keyType
    override val source = SignerSource.PIV

    /** Reads the chosen slot's signing certificate (no PIN needed). */
    suspend fun load(): ByteArray {
        val info = reader.scan(tapMessage, tagInteractionFunc = { tag ->
            val card = PivCard(NfcCardChannel(tag))
            card.connect()
            card.signingKey(slot)
        })
        key = info
        return info.certificate
    }

    override suspend fun sign(data: ByteArray): ByteArray {
        val k = key ?: throw SigningException("尚未讀取卡片憑證")
        val digest = DocCrypto.digest("SHA-256", data)
        val signature = reader.scan("請再次將 PIV 卡貼近 NFC 感應區完成簽署，簽署期間請保持不動，完成前請勿移開卡片。", tagInteractionFunc = { tag ->
            val card = PivCard(NfcCardChannel(tag))
            card.connect()
            card.sign(pin, k, digest)
        })
        verify(k, data, signature)
        return signature
    }

    /** Checks the signature against the certificate read at [load], so a swapped card is caught. */
    private fun verify(k: PivCard.KeyInfo, data: ByteArray, signature: ByteArray) {
        when (k.keyType) {
            SignerKeyType.RSA -> {
                val rsa = PlatformCrypto.rsaPublicKeyFromCertificate(k.certificate) ?: throw SigningException("卡片憑證不是 RSA 金鑰")
                if (!PlatformCrypto.verifyRsa("RS256", rsa, data, signature)) throw SigningException("簽章與先前讀取的憑證不符，請使用同一張卡片")
            }
            SignerKeyType.EC_P256 -> {
                val ec = org.multipaz.crypto.X509Cert(kotlinx.io.bytestring.ByteString(k.certificate)).ecPublicKey
                    as? org.multipaz.crypto.EcPublicKeyDoubleCoordinate ?: throw SigningException("PIV 憑證不是 EC 金鑰")
                val raw = ecdsaDerToRaw(signature) ?: throw SigningException("PIV 回傳的 ECDSA 簽章格式錯誤")
                if (!PlatformCrypto.verifyEcdsaRaw("secp256r1", ec.x, ec.y, data, raw)) {
                    throw SigningException("簽章與先前讀取的憑證不符，請使用同一張卡片")
                }
            }
        }
    }

    /** DER SEQUENCE{INTEGER r, INTEGER s} to a fixed 64-byte r||s for P-256. */
    private fun ecdsaDerToRaw(der: ByteArray): ByteArray? {
        val seq = Der.read(der, 0) ?: return null
        if (seq.tag != 0x30) return null
        val parts = Der.children(seq.value)
        if (parts.size < 2 || parts[0].tag != 0x02 || parts[1].tag != 0x02) return null
        fun fixed(v: ByteArray): ByteArray {
            var b = v
            while (b.isNotEmpty() && b[0] == 0.toByte()) b = b.copyOfRange(1, b.size)
            if (b.size > 32) return b.copyOfRange(b.size - 32, b.size)
            return ByteArray(32 - b.size) + b
        }
        return fixed(parts[0].value) + fixed(parts[1].value)
    }
}

package diw.wallet.core.document.pgp

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.card.GpkiCard
import diw.wallet.core.document.card.NfcCardChannel
import diw.wallet.core.document.card.OpenPgpAlgorithm
import diw.wallet.core.document.card.OpenPgpCard
import diw.wallet.core.document.card.OpenPgpCardInfo
import diw.wallet.core.document.card.OpenPgpCardKey
import diw.wallet.core.document.card.OpenPgpCurve
import diw.wallet.core.document.card.OpenPgpKeySlot
import diw.wallet.core.document.card.OpenPgpPublicMaterial
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.jose.PlatformCrypto
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.X509Cert
import org.multipaz.nfc.NfcTagReader
import kotlin.time.Clock

/** Card operations that run in one tap: reading the card and decrypting a message sent to it. */
object OpenPgpCards {
    /**
     * Reads the card on [reader] (no PIN) and matches each key to an OpenPGP v4 key packet, using [known] key packet
     * bodies from the keyring first.
     */
    suspend fun read(reader: NfcTagReader, message: String, known: List<ByteArray> = emptyList()): OpenPgpCardInfo =
        reader.scan(message, tagInteractionFunc = { tag ->
            val card = OpenPgpCard(NfcCardChannel(tag))
            card.connect()
            withPackets(card.readInfo(), known)
        })

    fun withPackets(info: OpenPgpCardInfo, known: List<ByteArray>): OpenPgpCardInfo =
        info.withKeys(info.keys.map { k -> if (k.present) k.withPacket(OpenPgpPackets.matchCardKey(k, known)) else k })

    /**
     * Recovers the session key of [message] with the card's decryption key: finds the PKESK addressed to the card,
     * has the card decipher it after VERIFY PW1 (82) and unwraps the result. Returns the card read and the session key.
     */
    suspend fun sessionKey(
        reader: NfcTagReader, message: String, pin: String, encrypted: ByteArray, known: List<ByteArray> = emptyList(),
    ): Pair<OpenPgpCardInfo, Pair<Int, ByteArray>> {
        val pkesks = OpenPgpPackets.pkesks(encrypted)
        if (pkesks.isEmpty()) throw SigningException("這份資料不是以公開金鑰加密的 OpenPGP 訊息")
        return reader.scan(message, tagInteractionFunc = { tag ->
            val card = OpenPgpCard(NfcCardChannel(tag))
            card.connect()
            val info = withPackets(card.readInfo(), known)
            val key = info.key(OpenPgpKeySlot.DECRYPTION) ?: throw SigningException("OpenPGP 卡上沒有解密金鑰")
            val body = key.packet ?: throw SigningException(
                "無法由卡片重建解密金鑰的公開金鑰（指紋不符），請先把這張卡的公開金鑰匯入 OpenPGP 公開金鑰清單",
            )
            val fpr = OpenPgpPackets.fingerprint(body)
            val pkesk = pkesks.firstOrNull { it.isFor(fpr) && !it.keyId.isNullOrAnonymous() }
                ?: pkesks.firstOrNull { it.isFor(fpr) }
                ?: throw SigningException(
                    "這份資料不是寄給這張卡片（卡片解密金鑰 " + OpenPgpPackets.fingerprintText(fpr) + "；收件人 " +
                        pkesks.joinToString("、") { it.keyIdText } + "）",
                )
            val out = card.decipher(pin, key, OpenPgpPackets.cardInput(pkesk, key))
            info to OpenPgpPackets.sessionKey(pkesk, body, out)
        })
    }

    private fun ByteArray?.isNullOrAnonymous(): Boolean = this == null || all { it == 0.toByte() }

    /** The X.509 SubjectPublicKeyInfo of an RSA or P-256 card key, for a self-issued certificate. */
    fun spki(key: OpenPgpCardKey): ByteArray = when (val m = key.publicKey) {
        is OpenPgpPublicMaterial.Rsa -> derSeq(
            derSeq(derOid("2A864886F70D010101") + byteArrayOf(0x05, 0x00)),
            derTag(0x03, byteArrayOf(0) + derSeq(derInt(m.modulus), derInt(m.exponent))),
        )
        is OpenPgpPublicMaterial.Ec -> derSeq(
            derSeq(derOid("2A8648CE3D0201"), derOid("2A8648CE3D030107")),
            derTag(0x03, byteArrayOf(0) + m.point),
        )
        null -> throw SigningException("OpenPGP 卡上沒有簽章金鑰")
    }

    /** r||s to a DER ECDSA signature. */
    fun ecdsaDer(raw: ByteArray): ByteArray {
        val half = raw.size / 2
        return derSeq(derInt(raw.copyOfRange(0, half)), derInt(raw.copyOfRange(half, raw.size)))
    }

    private fun derLen(n: Int): ByteArray = when {
        n < 0x80 -> byteArrayOf(n.toByte())
        n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
        else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
    }

    private fun derTag(tag: Int, v: ByteArray) = byteArrayOf(tag.toByte()) + derLen(v.size) + v

    private fun derSeq(vararg parts: ByteArray) = derTag(0x30, parts.fold(ByteArray(0)) { a, b -> a + b })

    private fun derOid(hex: String) = derTag(0x06, diw.wallet.core.document.DocCryptoUtil.unhex(hex))

    private fun derInt(v: ByteArray): ByteArray {
        var i = 0
        while (i < v.size - 1 && v[i] == 0.toByte()) i++
        var b = v.copyOfRange(i, v.size)
        if (b.isEmpty()) b = byteArrayOf(0)
        if (b[0].toInt() and 0x80 != 0) b = byteArrayOf(0) + b
        return derTag(0x02, b)
    }
}

/**
 * The signature key of an OpenPGP card on any [NfcTagReader] (phone NFC, USB CCID, PC/SC). [load] reads the card on a
 * first tap; each signature is a further tap. It signs both ways:
 * - [signDetached]: an OpenPGP v4 detached signature (ASCII armored), issued by the key whose fingerprint the card
 *   stores, so it verifies with the holder's published certificate.
 * - [sign] as a [DocumentSigner] for the X.509 formats, with the card's cardholder certificate for the signature key
 *   or, without one, a certificate the card signs itself (cached by the caller through [cachedCertificate]).
 * The PIN is verified right before each signature and only held by this object; every signature is checked against
 * the public key read at [load], so a different card is refused.
 */
class OpenPgpTapSigner(
    private val reader: NfcTagReader,
    private val pin: String,
    private val known: List<ByteArray> = emptyList(),
    private val cachedCertificate: (fingerprint: String) -> ByteArray? = { null },
    private val tapMessage: String = "請將 OpenPGP 卡（或 YubiKey 等安全金鑰）貼近 NFC 感應區，讀取期間請保持貼合、不要移動。",
    private val signMessage: String = "請再次將同一張 OpenPGP 卡貼近 NFC 感應區完成簽署，完成前請勿移開。",
) : DocumentSigner {
    var info: OpenPgpCardInfo? = null
        private set
    private var key: OpenPgpCardKey? = null
    private var certificate: ByteArray? = null

    /** A certificate the card signed for itself during [load]; the caller keeps it for later signings. */
    var selfIssued: ByteArray? = null
        private set

    override val certificateChain: List<ByteArray>
        get() = listOf(certificate ?: throw SigningException("尚未讀取 OpenPGP 卡的憑證"))
    override val keyType: SignerKeyType get() = keyTypeOf(key ?: throw SigningException("尚未讀取 OpenPGP 卡"))
    override val source = SignerSource.OPENPGP

    /** The signature key read at [load]. */
    val signatureKey: OpenPgpCardKey get() = key ?: throw SigningException("尚未讀取 OpenPGP 卡")

    /**
     * Reads the card and its signature key. With [x509] the key must be RSA or EC P-256 and gets a certificate: the
     * card's own for that key, the cached one, or a new self-issued one in [subject] (signed by the card in this tap).
     */
    suspend fun load(x509: Boolean, subject: String? = null): OpenPgpCardInfo {
        val result = reader.scan(tapMessage, tagInteractionFunc = { tag ->
            val card = OpenPgpCard(NfcCardChannel(tag))
            card.connect()
            val read = OpenPgpCards.withPackets(card.readInfo(), known)
            val k = read.key(OpenPgpKeySlot.SIGNATURE) ?: throw SigningException("這張 OpenPGP 卡沒有簽章金鑰")
            var made: ByteArray? = null
            val cert = if (!x509) null else {
                keyTypeOf(k)
                val fpr = k.fingerprint?.let { diw.wallet.core.document.DocCryptoUtil.hex(it).uppercase() }
                k.certificate?.takeIf { certificateMatches(it, k) }
                    ?: fpr?.let(cachedCertificate)?.takeIf { certificateMatches(it, k) }
                    ?: run {
                        val name = subject?.trim()?.ifEmpty { null } ?: read.cardholder ?: read.label
                        DocumentSigning.selfIssuedCertificate(OpenPgpCards.spki(k), name, { tbs -> x509Sign(card, k, tbs) }, keyTypeOf(k), 3650)
                            .also { made = it }
                    }
            }
            Triple(read, cert, made)
        })
        info = result.first
        key = result.first.key(OpenPgpKeySlot.SIGNATURE)
        certificate = result.second
        selfIssued = result.third
        return result.first
    }

    /** X.509 formats: RSASSA-PKCS1-v1_5 SHA-256, or ECDSA P-256 SHA-256 in DER. */
    override suspend fun sign(data: ByteArray): ByteArray {
        val k = signatureKey
        val signature = reader.scan(signMessage, tagInteractionFunc = { tag ->
            val card = OpenPgpCard(NfcCardChannel(tag))
            card.connect()
            sameCard(card, k)
            x509Sign(card, k, data)
        })
        val cert = certificateChain.first()
        val ok = when (keyTypeOf(k)) {
            SignerKeyType.RSA -> PlatformCrypto.rsaPublicKeyFromCertificate(cert)?.let { PlatformCrypto.verifyRsa("RS256", it, data, signature) } == true
            SignerKeyType.EC_P256 -> {
                val ec = X509Cert(ByteString(cert)).ecPublicKey as? EcPublicKeyDoubleCoordinate
                ec != null && PlatformCrypto.verifyEcdsaRaw("secp256r1", ec.x, ec.y, data, ecdsaRaw(signature, 32))
            }
        }
        if (!ok) throw SigningException("簽章與先前讀取的 OpenPGP 卡不符，請使用同一張卡片")
        return signature
    }

    /**
     * An OpenPGP v4 detached signature over [data] (binary document), ASCII armored. The key packet must match the
     * fingerprint the card stores, so the signature names the key the holder published.
     */
    suspend fun signDetached(data: ByteArray): ByteArray {
        val k = signatureKey
        val body = k.packet ?: throw SigningException(
            "無法由卡片重建簽章金鑰的 OpenPGP 公開金鑰（卡上指紋 ${k.fingerprintText ?: "無"} 不符），請先把你的公開金鑰匯入 OpenPGP 公開金鑰清單",
        )
        val hash = OpenPgpPackets.hashFor(k.algorithm)
        val pending = OpenPgpPackets.prepare(data, body, Clock.System.now().epochSeconds, hash)
        val input = if (k.algorithm is OpenPgpAlgorithm.Rsa) OpenPgpPackets.digestInfo(hash, pending.digest) else pending.digest
        val raw = reader.scan(signMessage, tagInteractionFunc = { tag ->
            val card = OpenPgpCard(NfcCardChannel(tag))
            card.connect()
            sameCard(card, k)
            card.sign(pin, input)
        })
        val packet = OpenPgpPackets.finish(pending, normalize(k, raw))
        if (!OpenPgp.verifyDetached(body, data, packet)) throw SigningException("簽章與先前讀取的 OpenPGP 卡不符，請使用同一張卡片")
        return OpenPgpPackets.armor("SIGNATURE", packet).encodeToByteArray()
    }

    /** Stops before the PIN is tried when the card now tapped holds another signature key than the one read at [load]. */
    private suspend fun sameCard(card: OpenPgpCard, k: OpenPgpCardKey) {
        val now = card.fingerprint(OpenPgpKeySlot.SIGNATURE)
        if (k.fingerprint != null && now != null && !now.contentEquals(k.fingerprint)) {
            throw SigningException("這不是先前讀取的 OpenPGP 卡（簽章金鑰指紋不同），請使用同一張卡片")
        }
    }

    /** RSA signatures are padded to the modulus length; EC r||s must be two equal halves. */
    private fun normalize(k: OpenPgpCardKey, raw: ByteArray): ByteArray = when (val a = k.algorithm) {
        is OpenPgpAlgorithm.Ec -> if (raw.size == 2 * a.curve.size) raw else throw SigningException("OpenPGP 卡回傳的簽章長度不正確")
        else -> raw
    }

    private suspend fun x509Sign(card: OpenPgpCard, k: OpenPgpCardKey, data: ByteArray): ByteArray {
        val digest = DocCrypto.digest("SHA-256", data)
        return when (keyTypeOf(k)) {
            SignerKeyType.RSA -> card.sign(pin, GpkiCard.SHA256_DIGEST_INFO + digest)
            SignerKeyType.EC_P256 -> OpenPgpCards.ecdsaDer(card.sign(pin, digest).also {
                if (it.size != 64) throw SigningException("OpenPGP 卡回傳的 ECDSA 簽章長度不正確")
            })
        }
    }

    companion object {
        /** The X.509 key type of a card key; only RSA and EC P-256 sign the X.509 document formats. */
        fun keyTypeOf(k: OpenPgpCardKey): SignerKeyType = when (val a = k.algorithm) {
            is OpenPgpAlgorithm.Rsa -> SignerKeyType.RSA
            is OpenPgpAlgorithm.Ec -> if (a.pgpId == 19 && a.curve == OpenPgpCurve.P256) SignerKeyType.EC_P256
                else throw SigningException("OpenPGP 卡的簽章金鑰是 $a，只能做 OpenPGP 簽章；PDF、CAdES、XAdES 等格式需要 RSA 或 ECDSA P-256 金鑰")
            is OpenPgpAlgorithm.Unsupported -> throw SigningException("OpenPGP 卡的簽章金鑰演算法不支援：$a")
        }

        fun x509Capable(k: OpenPgpCardKey): Boolean = runCatching { keyTypeOf(k) }.isSuccess

        /** Whether [cert] carries exactly the card key's public key. */
        fun certificateMatches(cert: ByteArray, k: OpenPgpCardKey): Boolean = runCatching {
            when (val m = k.publicKey) {
                is OpenPgpPublicMaterial.Rsa -> PlatformCrypto.rsaPublicKeyFromCertificate(cert)?.modulus?.let { strip(it).contentEquals(strip(m.modulus)) } == true
                is OpenPgpPublicMaterial.Ec -> (X509Cert(ByteString(cert)).ecPublicKey as? EcPublicKeyDoubleCoordinate)
                    ?.let { (byteArrayOf(4) + it.x + it.y).contentEquals(m.point) } == true
                null -> false
            }
        }.getOrDefault(false)

        private fun strip(b: ByteArray): ByteArray {
            var i = 0
            while (i < b.size - 1 && b[i] == 0.toByte()) i++
            return b.copyOfRange(i, b.size)
        }

        /** A DER ECDSA signature to fixed-length r||s. */
        fun ecdsaRaw(der: ByteArray, size: Int): ByteArray {
            fun fixed(v: ByteArray): ByteArray {
                val s = strip(v)
                return if (s.size >= size) s.copyOfRange(s.size - size, s.size) else ByteArray(size - s.size) + s
            }
            var p = 2
            if (der[1].toInt() and 0x80 != 0) p += der[1].toInt() and 0x7F
            val rLen = der[p + 1].toInt() and 0xFF
            val r = der.copyOfRange(p + 2, p + 2 + rLen)
            p += 2 + rLen
            val sLen = der[p + 1].toInt() and 0xFF
            val s = der.copyOfRange(p + 2, p + 2 + sLen)
            return fixed(r) + fixed(s)
        }
    }
}

package diw.wallet.core.document.card

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.jose.PlatformCrypto
import org.multipaz.nfc.NfcTagReader

/**
 * A citizen digital certificate card read through any [NfcTagReader] (phone NFC, USB CCID, PC/SC). [load] reads the
 * signing certificate on a first tap; each [sign] is a further tap, so a phone does not hold the card while the
 * document and time stamp are prepared (a reader with the card inserted answers at once). The PIN is held only by
 * this object, for one signing session, and every signature is checked against the certificate read at [load], so
 * a different card is refused.
 */
class GpkiTapSigner(
    private val reader: NfcTagReader,
    private val pin: String,
    private val intermediates: List<ByteArray> = emptyList(),
    private val tapMessage: String = "請將自然人憑證卡（IC 晶片面）貼近手機背面的 NFC 感應區，讀取期間請保持貼合、不要移動卡片。",
) : DocumentSigner {
    private var key: GpkiCard.KeyInfo? = null

    override val certificateChain: List<ByteArray>
        get() = listOf((key ?: throw SigningException("尚未讀取卡片憑證")).certificate) + intermediates
    override val keyType = SignerKeyType.RSA
    override val source = SignerSource.SMART_CARD

    /** Reads the card's signing certificate (no PIN needed). */
    suspend fun load(): ByteArray {
        val info = reader.scan(tapMessage, tagInteractionFunc = { tag ->
            val card = GpkiCard(NfcCardChannel(tag))
            card.connect()
            card.signingKey()
        })
        key = info
        return info.certificate
    }

    override suspend fun sign(data: ByteArray): ByteArray {
        val k = key ?: throw SigningException("尚未讀取卡片憑證")
        val digest = DocCrypto.digest("SHA-256", data)
        val signature = reader.scan("請再次將自然人憑證卡貼近 NFC 感應區完成簽署，簽署期間請保持不動，完成前請勿移開卡片。", tagInteractionFunc = { tag ->
            val card = GpkiCard(NfcCardChannel(tag))
            card.connect()
            card.signSha256(pin, k.keyRef, digest)
        })
        val rsa = PlatformCrypto.rsaPublicKeyFromCertificate(k.certificate) ?: throw SigningException("卡片憑證不是 RSA 金鑰")
        if (!PlatformCrypto.verifyRsa("RS256", rsa, data, signature)) {
            throw SigningException("簽章與先前讀取的憑證不符，請使用同一張卡片")
        }
        return signature
    }
}

package diw.wallet.core.document.card

import diw.wallet.core.i18n.ct
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
    private val tapMessage: String = ct("core_gpki_hold"),
) : DocumentSigner {
    private var key: GpkiCard.KeyInfo? = null

    override val certificateChain: List<ByteArray>
        get() = listOf((key ?: throw SigningException(ct("core_card_not_read"))).certificate) + intermediates
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
        val k = key ?: throw SigningException(ct("core_card_not_read"))
        val digest = DocCrypto.digest("SHA-256", data)
        val signature = reader.scan(ct("core_gpki_hold_again"), tagInteractionFunc = { tag ->
            val card = GpkiCard(NfcCardChannel(tag))
            card.connect()
            card.signSha256(pin, k.keyRef, digest)
        })
        val rsa = PlatformCrypto.rsaPublicKeyFromCertificate(k.certificate) ?: throw SigningException(ct("core_card_not_rsa"))
        if (!PlatformCrypto.verifyRsa("RS256", rsa, data, signature)) {
            throw SigningException(ct("core_card_sig_mismatch"))
        }
        return signature
    }
}

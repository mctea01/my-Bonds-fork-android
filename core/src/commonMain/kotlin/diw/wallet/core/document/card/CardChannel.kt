package diw.wallet.core.document.card

import diw.wallet.core.document.sign.SigningException
import kotlinx.io.bytestring.ByteString
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.NfcIsoTag
import org.multipaz.nfc.NfcTagLostException

/** A response APDU: status word and data. */
class CardResponse(val sw: Int, val data: ByteArray) {
    val ok: Boolean get() = sw == 0x9000
    val warning: Boolean get() = sw and 0xFF00 == 0x6200
}

/** Short APDUs to a smart card; [le] 0 means no Le, 256 means Le = 00. */
fun interface CardChannel {
    suspend fun transmit(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): CardResponse
}

/**
 * A [CardChannel] over a Multipaz [NfcIsoTag] (phone NFC, USB CCID, PC/SC). Handles 61XX with GET RESPONSE and 6CXX
 * by repeating with the right Le, since PC/SC readers here pass T=0 status words through.
 */
class NfcCardChannel(private val tag: NfcIsoTag) : CardChannel {
    override suspend fun transmit(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): CardResponse {
        var r = send(CommandApdu(cla, ins, p1, p2, ByteString(data), le))
        if (r.sw shr 8 == 0x6C) r = send(CommandApdu(cla, ins, p1, p2, ByteString(data), (r.sw and 0xFF).let { if (it == 0) 256 else it }))
        var out = r.data
        var guard = 0
        while (r.sw shr 8 == 0x61 && guard++ < 32) {
            r = send(CommandApdu(0x00, 0xC0, 0x00, 0x00, ByteString(), (r.sw and 0xFF).let { if (it == 0) 256 else it }))
            out += r.data
        }
        return CardResponse(r.sw, out)
    }

    private suspend fun send(c: CommandApdu): CardResponse = try {
        val r = tag.transceive(c)
        CardResponse(r.status, r.payload.toByteArray())
    } catch (e: NfcTagLostException) {
        throw SigningException("卡片已離開讀卡區域，請重新感應並保持不動", e)
    }
}

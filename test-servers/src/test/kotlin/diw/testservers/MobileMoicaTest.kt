package diw.testservers

import diw.wallet.core.document.sign.MobileMoicaException
import diw.wallet.core.document.sign.TwFidoClient
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.util.Base64

class MobileMoicaTest {
    @Test
    fun checksumAuthenticatesTheEntireResponse() = runBlocking<Unit> {
        val key = ByteArray(32) { it.toByte() }
        val iv = ByteArray(12) { (it + 32).toByte() }
        val checksum = TwFidoClient.spChecksum("transaction-result", key, iv)
        assertTrue(TwFidoClient.verifyChecksum(checksum, "transaction-result", key))
        assertFalse(TwFidoClient.verifyChecksum(checksum, "transaction-result-changed", key))
        assertFalse(TwFidoClient.verifyChecksum(checksum, "transaction-result", ByteArray(32)))
        assertFalse(TwFidoClient.verifyChecksum("00", "transaction-result", key))
        assertFalse(TwFidoClient.verifyChecksum(checksum.dropLast(1) + "z", "transaction-result", key))
    }

    @Test
    fun ticketParsingRejectsMissingIdentifiers() = runBlocking<Unit> {
        fun ticket(json: String): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray()) + ".signature"
        val valid = TwFidoClient.parseTicket(ticket("""{"transaction_id":"transaction-1","sp_ticket_id":"ticket-1"}"""))
        assertEquals("transaction-1", valid.transactionId)
        assertEquals("ticket-1", valid.spTicketId)
        assertFailsWith<MobileMoicaException> {
            TwFidoClient.parseTicket(ticket("""{"transaction_id":"transaction-1"}"""))
        }
        assertFailsWith<MobileMoicaException> { TwFidoClient.parseTicket("invalid-ticket") }
        assertTrue(TwFidoClient.isPending("20002:still processing"))
        assertFalse(TwFidoClient.isPending("90001:failure"))
    }
}

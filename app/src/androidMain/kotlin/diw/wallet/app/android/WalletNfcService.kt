package diw.wallet.app.android

import android.content.Context
import android.content.Intent
import android.os.VibrationEffect
import android.os.Vibrator
import kotlinx.coroutines.delay
import kotlinx.io.bytestring.ByteString
import org.multipaz.mdoc.nfc.MdocNfcDataTransferService
import org.multipaz.mdoc.nfc.MdocNfcEngagementHelper
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.Nfc
import org.multipaz.nfc.NfcApduRouter
import org.multipaz.nfc.NfcApduService
import org.multipaz.nfc.NfcDeactivationReason
import org.multipaz.nfc.ResponseApdu
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Host card emulation for ISO/IEC 18013-5 proximity presentation: the NDEF application carries the NFC engagement
 * and the mdoc data transfer application carries the data when the reader chose NFC over BLE. Both route to the
 * shared [diw.wallet.app.ProximityModel], which only engages while the wallet's 感應出示 screen is open.
 */
class WalletNfcService : NfcApduRouter() {
    override fun buildServices(): Map<ByteString, NfcApduService> = mapOf(
        Nfc.NDEF_APPLICATION_ID to NdefEngagementService(applicationContext),
        Nfc.ISO_MDOC_NFC_DATA_TRANSFER_APPLICATION_ID to DataTransferService(applicationContext),
    )
}

/**
 * NFC data transfer. Multipaz answers 6A82 at once while no NFC transport is open, but the wallet opens its transport
 * just after the handover, so a SELECT that comes first waits for it while the 感應出示 screen is open.
 */
private class DataTransferService(private val context: Context) : MdocNfcDataTransferService() {
    override suspend fun processCommandApdu(commandApdu: CommandApdu): ResponseApdu {
        var response = super.processCommandApdu(commandApdu)
        if (!commandApdu.isApplicationSelect) return response
        val proximity = (context as WalletApplication).model.proximity
        val deadline = TimeSource.Monotonic.markNow() + 2.seconds
        while (response.status == Nfc.RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND && proximity.listening.value && deadline.hasNotPassedNow()) {
            delay(100.milliseconds)
            response = super.processCommandApdu(commandApdu)
        }
        return response
    }
}

/**
 * NFC engagement over the NDEF Type 4 Tag application, after Multipaz's MdocNdefService (Apache-2.0) but handing the
 * transaction to the wallet's own consent screen, key unlock and history instead of Multipaz's presentment activity.
 * [NfcApduService] handles APDUs one at a time on a coroutine; SELECT is answered at once, since Android gives the
 * tap to another wallet when the first answer is slow, and replayed to the engagement helper.
 */
private class NdefEngagementService(private val context: Context) : NfcApduService() {
    private val app get() = context as WalletApplication

    @Volatile private var engagement: MdocNfcEngagementHelper? = null
    private var first: CommandApdu? = null
    private var received = 0

    override suspend fun processCommandApdu(commandApdu: CommandApdu): ResponseApdu = process(commandApdu)

    override suspend fun processDeactivated(reason: NfcDeactivationReason) {
        engagement?.processDeactivated(reason)
        reset()
    }

    private suspend fun process(apdu: CommandApdu): ResponseApdu {
        val proximity = app.model.proximity
        if (received == 0) {
            // Not listening: tell the reader there is no mdoc here, so it moves on.
            if (!proximity.listening.value) return ResponseApdu(Nfc.RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
            received = 1
            first = apdu
            return ResponseApdu(Nfc.RESPONSE_STATUS_SUCCESS)
        }
        val helper = engagement ?: proximity.nfcEngagement(onEngaged = { engaged() })?.also { engagement = it }
            ?: return ResponseApdu(Nfc.RESPONSE_STATUS_ERROR_FILE_OR_APPLICATION_NOT_FOUND)
        if (received++ == 1) first?.let { helper.processApdu(it) }
        return helper.processApdu(apdu)
    }

    private fun reset() {
        engagement = null
        first = null
        received = 0
    }

    /** The reader completed the handover: a short vibration, and the wallet comes to the front for the consent. */
    private fun engaged() {
        context.getSystemService(Vibrator::class.java)?.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 100, 50, 100), -1))
        // A service bound by the system for card emulation may start an activity from the background.
        context.startActivity(
            Intent(context, MainActivity::class.java)
                .setAction(MainActivity.ACTION_PROXIMITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
        )
    }
}

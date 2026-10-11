package diw.wallet.app.android

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.ByteString
import org.multipaz.compose.mdoc.CombinedNfcService
import org.multipaz.compose.mdoc.MdocNfcDataTransferService
import org.multipaz.compose.mdoc.NfcApduService
import org.multipaz.mdoc.nfc.MdocNfcEngagementHelper
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.Nfc
import org.multipaz.nfc.ResponseApdu
import org.multipaz.util.Logger

/**
 * Host card emulation for ISO/IEC 18013-5 proximity presentation: the NDEF application carries the NFC engagement
 * and the mdoc data transfer application carries the data when the reader chose NFC over BLE. Both route to the
 * shared [diw.wallet.app.ProximityModel], which only engages while the wallet's 感應出示 screen is open.
 */
class WalletNfcService : CombinedNfcService() {
    override fun buildServices(): Map<ByteString, NfcApduService> = mapOf(
        Nfc.NDEF_APPLICATION_ID to NdefEngagementService(this, ::sendResponseApdu),
        Nfc.ISO_MDOC_NFC_DATA_TRANSFER_APPLICATION_ID to MdocNfcDataTransferService(this, ::sendResponseApdu),
    )
}

/**
 * NFC engagement over the NDEF Type 4 Tag application, after Multipaz's MdocNdefService (Apache-2.0) but handing the
 * transaction to the wallet's own consent screen, key unlock and history instead of Multipaz's presentment activity.
 * APDUs are handled on one coroutine so suspend functions can be used; SELECT is answered at once, since Android
 * gives the tap to another wallet when the first answer is slow, and replayed to the engagement helper.
 */
private class NdefEngagementService(context: Context, sendResponse: (ByteArray) -> Unit) : NfcApduService(context, sendResponse) {
    private val app get() = applicationContext as WalletApplication
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val events = Channel<Event>(Channel.UNLIMITED)
    private var worker: Job? = null

    @Volatile private var engagement: MdocNfcEngagementHelper? = null
    private var first: CommandApdu? = null
    private var received = 0

    private sealed interface Event {
        data class Command(val apdu: CommandApdu) : Event
        data class Deactivated(val reason: Int) : Event
    }

    override fun onCreate() {
        worker = scope.launch {
            for (e in events) {
                try {
                    when (e) {
                        is Event.Command -> process(e.apdu)?.let { sendResponseApdu(it.encode()) }
                        is Event.Deactivated -> reset()
                    }
                } catch (ex: CancellationException) {
                    if (!isActive) throw ex
                } catch (ex: Exception) {
                    Logger.w(TAG, "APDU handling failed", ex)
                }
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        events.close()
    }

    override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        val apdu = runCatching { CommandApdu.decode(commandApdu) }.getOrNull() ?: return null
        events.trySend(Event.Command(apdu))
        return null
    }

    override fun onDeactivated(reason: Int) {
        // Unblocks the helper if it waits for the reader inside processApdu.
        engagement?.processDeactivated(reason)
        events.trySend(Event.Deactivated(reason))
    }

    private suspend fun process(apdu: CommandApdu): ResponseApdu? {
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
        applicationContext.getSystemService(Vibrator::class.java)?.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 100, 50, 100), -1))
        // A service bound by the system for card emulation may start an activity from the background.
        applicationContext.startActivity(
            Intent(applicationContext, MainActivity::class.java)
                .setAction(MainActivity.ACTION_PROXIMITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)
        )
    }

    private companion object {
        const val TAG = "WalletNfcService"
    }
}

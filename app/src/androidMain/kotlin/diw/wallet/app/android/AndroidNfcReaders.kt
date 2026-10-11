package diw.wallet.app.android

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build
import androidx.core.content.ContextCompat
import diw.wallet.app.NfcReaderList
import diw.wallet.app.NfcReaderOption
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.multipaz.nfc.NfcIsoTag
import org.multipaz.nfc.NfcIsoTagAndroid
import org.multipaz.nfc.NfcScanOptions
import org.multipaz.nfc.NfcTagLostException
import org.multipaz.nfc.NfcTagReader
import org.multipaz.nfc.ExternalNfcReaderUsb
import java.io.IOException
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume

/**
 * NFC readers on Android: the phone's own NFC in reader mode, and USB CCID readers attached by OTG, the USB class
 * that PC/SC readers use on a computer (ACR122U, ACR1252U and similar).
 */
internal object AndroidNfcReaders {
    fun list(context: Context, platform: AndroidPlatform): NfcReaderList {
        val readers = mutableListOf<NfcReaderOption>()
        val problems = mutableListOf<String>()
        val adapter = NfcAdapter.getDefaultAdapter(context)
        when {
            adapter == null -> problems += "這支手機沒有 NFC。"
            !adapter.isEnabled -> problems += "NFC 未開啟，請到系統設定開啟後再重新尋找。"
            else -> readers += NfcReaderOption("這支手機的 NFC", external = false, reader = ReaderModeTagReader(context, platform), bluetooth = true)
        }
        val usb = context.getSystemService(UsbManager::class.java)
        usb?.deviceList?.values?.forEach { device ->
            val index = (0 until device.interfaceCount).firstOrNull { device.getInterface(it).interfaceClass == UsbConstants.USB_CLASS_CSCID }
                ?: return@forEach
            val name = device.productName?.takeIf { it.isNotBlank() } ?: "USB 讀卡機"
            readers += NfcReaderOption("$name（USB）", external = true, reader = UsbCcidTagReader(context, usb, device, index))
        }
        if (readers.isEmpty()) problems += "也可以用 OTG 接上 USB 非接觸式讀卡機（CCID）。"
        return NfcReaderList(readers, problems.joinToString("").ifEmpty { null })
    }
}

/**
 * The phone's NFC in reader mode, after Multipaz's scan dialog (Apache-2.0) but drawn by the wallet's own screen:
 * NFC-A and NFC-B, no NDEF check, no platform sound. The tag is handled inside the reader callback, as Multipaz
 * does, with a 20 second transceive timeout. Reader mode only lasts while the activity is in front, so the wallet
 * turns it on again when it comes back.
 */
private class ReaderModeTagReader(private val context: Context, private val platform: AndroidPlatform) : NfcTagReader {
    override val external = false
    override val dialogAlwaysShown = false
    override val dialogNeverShown = true

    override suspend fun <T : Any> scan(
        message: String?,
        tagInteractionFunc: suspend (tag: NfcIsoTag) -> T?,
        options: NfcScanOptions,
        context: CoroutineContext,
    ): T {
        val adapter = NfcAdapter.getDefaultAdapter(this.context) ?: throw IllegalStateException("這支手機沒有 NFC")
        if (!adapter.isEnabled) throw IllegalStateException("NFC 未開啟，請到系統設定開啟")
        val outcome = CompletableDeferred<T>()
        // A failure inside one tap ends the scan through [outcome], not by failing the caller's job.
        val guard = SupervisorJob(currentCoroutineContext()[Job])
        val callback = NfcAdapter.ReaderCallback { tag ->
            if (outcome.isCompleted) return@ReaderCallback
            val isoDep = IsoDep.get(tag) ?: return@ReaderCallback
            try {
                isoDep.connect()
                isoDep.timeout = TRANSCEIVE_TIMEOUT_MS
                val result = runBlocking(guard) { tagInteractionFunc(NfcIsoTagAndroid(isoDep, context) {}) }
                if (result != null) outcome.complete(result) else runCatching { isoDep.close() }
            } catch (e: NfcTagLostException) {
                runCatching { isoDep.close() }
            } catch (e: IOException) {
                runCatching { isoDep.close() }
            } catch (e: CancellationException) {
                runCatching { isoDep.close() }
            } catch (e: Throwable) {
                runCatching { isoDep.close() }
                outcome.completeExceptionally(e)
            }
        }
        val enable: (Activity) -> Unit = { a -> adapter.enableReaderMode(a, callback, FLAGS, null) }
        val host = platform.activity ?: throw IllegalStateException("請先開啟錢包畫面")
        platform.readerMode = enable
        withContext(Dispatchers.Main) { enable(host) }
        try {
            return outcome.await()
        } finally {
            guard.cancel()
            if (platform.readerMode === enable) platform.readerMode = null
            withContext(NonCancellable + Dispatchers.Main) {
                (platform.activity ?: host).let { a -> runCatching { adapter.disableReaderMode(a) } }
            }
        }
    }

    private companion object {
        const val FLAGS = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or
            NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS
        const val TRANSCEIVE_TIMEOUT_MS = 20_000
    }
}

/** A USB CCID reader through Multipaz's CCID driver, after asking the user for access to the device. */
private class UsbCcidTagReader(
    private val context: Context,
    private val usb: UsbManager,
    private val device: UsbDevice,
    private val interfaceIndex: Int,
) : NfcTagReader {
    override val external = true
    override val dialogAlwaysShown = false
    override val dialogNeverShown = true

    override suspend fun <T : Any> scan(
        message: String?,
        tagInteractionFunc: suspend (tag: NfcIsoTag) -> T?,
        options: NfcScanOptions,
        context: CoroutineContext,
    ): T {
        if (!usb.hasPermission(device) && !requestPermission()) throw IllegalStateException("沒有取得 USB 讀卡機的使用權限")
        val name = device.productName ?: device.deviceName
        val reader = ExternalNfcReaderUsb(device.deviceName, kotlin.time.Clock.System.now(), name, name, device.vendorId, device.productId, interfaceIndex)
        return reader.getNfcTagReader().scan(message, tagInteractionFunc, options, context)
    }

    private suspend fun requestPermission(): Boolean = suspendCancellableCoroutine { cont ->
        val action = context.packageName + ".USB_PERMISSION"
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, intent: Intent) {
                if (intent.action != action) return
                runCatching { context.unregisterReceiver(this) }
                if (cont.isActive) cont.resume(intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false))
            }
        }
        ContextCompat.registerReceiver(context, receiver, IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED)
        cont.invokeOnCancellation { runCatching { context.unregisterReceiver(receiver) } }
        // The system fills in the device and the answer, so the intent must be mutable.
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        usb.requestPermission(device, PendingIntent.getBroadcast(context, 0, Intent(action).setPackage(context.packageName), flags))
    }
}

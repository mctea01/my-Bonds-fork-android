package diw.wallet.app.android

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
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
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.NfcIsoTag
import org.multipaz.nfc.NfcIsoTagAndroid
import org.multipaz.nfc.NfcScanOptions
import org.multipaz.nfc.NfcTagLostException
import org.multipaz.nfc.NfcTagReader
import org.multipaz.nfc.ResponseApdu
import kotlinx.io.bytestring.ByteString
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume

/**
 * NFC readers on Android: the phone's own NFC in reader mode, and USB CCID readers attached by OTG, the USB class
 * that PC/SC readers use on a computer (ACR122U, ACR1252U and similar). A security key plugged in directly (YubiKey,
 * Nitrokey, Gnuk) is a CCID device with its card always inserted, so PIV and OpenPGP work through the same path; a
 * YubiKey over NFC is an ISO-DEP tag in reader mode.
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
            if (index == null) {
                // A security key with only FIDO or OTP turned on has no smart card interface for PIV or OpenPGP.
                tokenName(device)?.let { problems += "$it 已接上，但沒有開啟智慧卡（CCID）介面，無法使用 PIV 或 OpenPGP。請以 Yubico Authenticator 等工具在 USB 介面設定開啟 CCID；只支援 FIDO 的 Security Key 系列沒有這兩種功能。" }
                return@forEach
            }
            val name = tokenName(device) ?: device.productName?.takeIf { it.isNotBlank() } ?: "USB 讀卡機"
            readers += NfcReaderOption("$name（USB）", external = true, reader = UsbCcidTagReader(context, usb, device, index))
        }
        if (readers.isEmpty()) problems += "也可以用 OTG 接上 USB 非接觸式讀卡機（CCID），或直接插上 YubiKey 等 USB 安全金鑰。"
        return NfcReaderList(readers, problems.joinToString("").ifEmpty { null })
    }

    /**
     * A clear name for a USB security key that holds the cards itself (no card to insert): its product name, or the
     * maker's name when the device reports none. Null for anything else, which keeps its own product name.
     */
    private fun tokenName(device: UsbDevice): String? {
        val maker = TOKEN_VENDORS[device.vendorId] ?: return null
        val product = device.productName?.trim()?.takeIf { it.isNotEmpty() }
        return when {
            product == null -> maker
            product.contains(maker, ignoreCase = true) -> product
            else -> "$maker $product"
        }
    }

    /** USB vendor IDs of security keys with PIV or OpenPGP applets on a CCID interface. */
    private val TOKEN_VENDORS = mapOf(
        0x1050 to "YubiKey",
        0x20A0 to "Nitrokey",
        0x234B to "Gnuk",
    )
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
        // Show the scan sheet only while reader mode is actually waiting for a tap, so the user taps at the right
        // moment and a tap outside this window is not left for the system to report as an unhandled tag.
        platform.nfcScanPromptState.value = message ?: "請將卡片貼近手機背面的 NFC 感應區"
        withContext(Dispatchers.Main) { enable(host) }
        try {
            return outcome.await()
        } finally {
            guard.cancel()
            platform.nfcScanPromptState.value = null
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
        // Talk to the CCID interface directly rather than through the SDK's USB driver, which failed to read the
        // bulk-in endpoint on these security keys. The wallet's own CCID framing waits long enough for PIV and OpenPGP
        // card operations and handles the reader's time-extension replies.
        val iface = device.getInterface(interfaceIndex)
        var bulkIn: UsbEndpoint? = null
        var bulkOut: UsbEndpoint? = null
        for (i in 0 until iface.endpointCount) {
            val ep = iface.getEndpoint(i)
            if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
            if (ep.direction == UsbConstants.USB_DIR_IN) bulkIn = ep else bulkOut = ep
        }
        if (bulkIn == null || bulkOut == null) throw IllegalStateException("這張 CCID 介面沒有可用的傳輸端點")
        val connection = usb.openDevice(device) ?: throw IllegalStateException("無法開啟 USB 讀卡機")
        try {
            if (!connection.claimInterface(iface, true)) throw IllegalStateException("無法取得 USB 智慧卡介面（可能被其他程式占用）")
            val tag = UsbCcidTag(connection, bulkOut, bulkIn)
            tag.powerOn()
            return withContext(context) { tagInteractionFunc(tag) } ?: throw IllegalStateException("讀卡沒有取得結果")
        } finally {
            withContext(NonCancellable) {
                runCatching { connection.releaseInterface(iface) }
                runCatching { connection.close() }
            }
        }
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

/**
 * A smart card reached over the USB CCID protocol (USB Device Class: Smart Card CCID, rev 1.1). The wallet frames the
 * APDUs itself rather than relying on the SDK: it powers the slot on (PC_to_RDR_IccPowerOn), sends each APDU in a
 * PC_to_RDR_XfrBlock and reads the RDR_to_PC_DataBlock reply, reassembling a reply that spans several USB packets and
 * waiting through the reader's time-extension replies (bmCommandStatus = 2), so a slow PIV or OpenPGP operation does
 * not fail the bulk-in read. APDU-level 61xx/6Cxx chaining is handled a layer up by NfcCardChannel.
 */
private class UsbCcidTag(
    private val connection: UsbDeviceConnection,
    private val bulkOut: UsbEndpoint,
    private val bulkIn: UsbEndpoint,
) : NfcIsoTag() {
    private var seq = 0

    override val maxTransceiveLength = 65536

    suspend fun powerOn() {
        // PC_to_RDR_IccPowerOn with bPowerSelect = 0 (automatic voltage); the reply carries the ATR, which we ignore.
        exchange(0x62, ByteArray(0))
    }

    override suspend fun transceive(command: CommandApdu): ResponseApdu {
        val resp = exchange(0x6F, command.encode())
        if (resp.size < 2) throw NfcTagLostException("CCID 回應過短，缺少狀態位元組")
        val sw = ((resp[resp.size - 2].toInt() and 0xFF) shl 8) or (resp[resp.size - 1].toInt() and 0xFF)
        return ResponseApdu(sw, ByteString(resp.copyOfRange(0, resp.size - 2)))
    }

    override suspend fun close() {
        // PC_to_RDR_IccPowerOff, best effort; the connection itself is released by the reader.
        runCatching { exchange(0x63, ByteArray(0)) }
    }

    override suspend fun updateDialogMessage(message: String) {}

    /** Sends one CCID command and returns the response message's abData (bmCommandStatus 0), on [Dispatchers.IO]. */
    private suspend fun exchange(messageType: Int, data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        writeMessage(messageType, data)
        var result: ByteArray? = null
        while (result == null) {
            val msg = readMessage()
            if (msg.size < 10) throw NfcTagLostException("CCID 回應標頭不完整")
            when ((msg[7].toInt() shr 6) and 0x03) {
                2 -> {} // time extension requested: the reader is still working, wait for the next block
                1 -> throw NfcTagLostException("CCID 指令失敗（bError 0x" + (msg[8].toInt() and 0xFF).toString(16) + "）")
                else -> result = msg.copyOfRange(10, msg.size)
            }
        }
        result
    }

    private fun writeMessage(messageType: Int, data: ByteArray) {
        val msg = ByteArray(10 + data.size)
        msg[0] = messageType.toByte()
        val len = data.size
        msg[1] = len.toByte(); msg[2] = (len shr 8).toByte(); msg[3] = (len shr 16).toByte(); msg[4] = (len shr 24).toByte()
        msg[5] = 0                      // bSlot
        msg[6] = (seq++ and 0xFF).toByte() // bSeq
        msg[7] = 0                      // XfrBlock: bBWI = 0; IccPowerOn: bPowerSelect = 0 (automatic)
        msg[8] = 0; msg[9] = 0          // wLevelParameter / abRFU
        data.copyInto(msg, 10)
        var off = 0
        while (off < msg.size) {
            val n = connection.bulkTransfer(bulkOut, msg.copyOfRange(off, msg.size), msg.size - off, WRITE_TIMEOUT_MS)
            if (n < 0) throw NfcTagLostException("送出 CCID 指令失敗（bulk-out）")
            off += n
        }
    }

    /** Reads one complete CCID message, reassembling the 10-byte header plus the abData its dwLength announces. */
    private fun readMessage(): ByteArray {
        val chunk = ByteArray(bulkIn.maxPacketSize.coerceAtLeast(64))
        val out = ByteArrayOutputStream()
        var need = 10
        while (true) {
            val n = connection.bulkTransfer(bulkIn, chunk, chunk.size, READ_TIMEOUT_MS)
            if (n < 0) throw NfcTagLostException("讀取 CCID 回應失敗（bulk-in）")
            if (n == 0) continue
            out.write(chunk, 0, n)
            if (out.size() >= 10 && need == 10) {
                val h = out.toByteArray()
                val dw = (h[1].toInt() and 0xFF) or ((h[2].toInt() and 0xFF) shl 8) or
                    ((h[3].toInt() and 0xFF) shl 16) or ((h[4].toInt() and 0xFF) shl 24)
                need = 10 + dw
            }
            if (out.size() >= need) return out.toByteArray().copyOfRange(0, need)
        }
    }

    private companion object {
        const val WRITE_TIMEOUT_MS = 3_000
        const val READ_TIMEOUT_MS = 15_000
    }
}

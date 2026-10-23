package diw.wallet.app.android

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import diw.wallet.app.BondsLinkCentral
import diw.wallet.core.profile.bonds.BondsLinkCollector
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.profile.bonds.BondsTransportException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The verifier side of the Bonds BLE link on Android: scans for the holder advertising the request's one-time service,
 * connects, subscribes to the frames, writes "received" and then the framed reply. Up to [ATTEMPTS] connections are
 * tried, since a phone that is still proving or a dropped link is common in person.
 */
class AndroidBondsLinkCentral(private val context: Context, private val activity: () -> Activity?) : BondsLinkCentral {
    private val manager get() = context.getSystemService(BluetoothManager::class.java)

    private val permissions: Array<String>
        get() = if (Build.VERSION.SDK_INT >= 31) arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

    override suspend fun unavailableReason(): String? {
        val adapter = manager?.adapter ?: return "此裝置沒有藍牙"
        val missing = permissions.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) {
            activity()?.let { a -> a.runOnUiThread { a.requestPermissions(missing.toTypedArray(), PERMISSION_REQUEST) } }
            return "請允許「附近的裝置」權限後再試一次"
        }
        if (!adapter.isEnabled) return "藍牙未開啟"
        if (adapter.bluetoothLeScanner == null) return "此裝置不支援藍牙掃描"
        return null
    }

    private sealed interface Event {
        class Found(val device: BluetoothDevice) : Event
        data class ScanFailed(val code: Int) : Event
        data class Connection(val connected: Boolean, val status: Int) : Event
        data class Mtu(val mtu: Int) : Event
        data class Discovered(val status: Int) : Event
        data class DescriptorWritten(val status: Int) : Event
        data class Written(val status: Int) : Event
        class Frame(val value: ByteArray) : Event
    }

    /** The link dropped or a step failed; another connection may still succeed. */
    private class Dropped(message: String) : Exception(message)

    @SuppressLint("MissingPermission")
    override suspend fun receive(
        serviceUuid: String,
        maxPayload: Int,
        onProgress: (String) -> Unit,
        answer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        val adapter = manager?.adapter ?: throw BondsTransportException("此裝置沒有藍牙")
        val scanner = adapter.bluetoothLeScanner ?: throw BondsTransportException("此裝置不支援藍牙掃描")
        val service = UUID.fromString(serviceUuid)
        var last: String? = null
        repeat(ATTEMPTS) {
            val events = Channel<Event>(Channel.UNLIMITED)
            val scan = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    events.trySend(Event.Found(result.device))
                }

                override fun onScanFailed(errorCode: Int) {
                    events.trySend(Event.ScanFailed(errorCode))
                }
            }
            var gatt: BluetoothGatt? = null
            try {
                onProgress(if (last == null) "等待出示者的手機出現（對方產生證明需要數秒到數十秒）" else "重新尋找出示者：$last")
                scanner.startScan(
                    listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(service)).build()),
                    ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                    scan,
                )
                val device = await(events, null) {
                    when (it) {
                        is Event.Found -> it.device
                        is Event.ScanFailed -> throw BondsTransportException("無法開始藍牙掃描（${it.code}）")
                        else -> null
                    }
                }
                runCatching { scanner.stopScan(scan) }
                onProgress("已找到出示者，正在連線")
                gatt = device.connectGatt(context, false, callback(events), BluetoothDevice.TRANSPORT_LE)
                    ?: throw Dropped("無法連線")
                return exchange(gatt, events, service, maxPayload, onProgress, answer)
            } catch (e: Dropped) {
                last = e.message
            } finally {
                runCatching { scanner.stopScan(scan) }
                gatt?.let { g -> runCatching { g.disconnect() }; runCatching { g.close() } }
                events.close()
            }
        }
        throw BondsTransportException("藍牙連線一再中斷：$last")
    }

    private fun callback(events: Channel<Event>) = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            events.trySend(Event.Connection(newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS, status))
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            events.trySend(Event.Mtu(if (status == BluetoothGatt.GATT_SUCCESS) mtu else DEFAULT_MTU))
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            events.trySend(Event.Discovered(status))
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            events.trySend(Event.DescriptorWritten(status))
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            events.trySend(Event.Written(status))
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            events.trySend(Event.Frame(value.copyOf()))
        }

        // Before Android 13 only this form is called; from 13 on both are, so it is ignored there.
        @Deprecated("Deprecated in Android 13")
        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            if (Build.VERSION.SDK_INT < 33) characteristic.value?.let { events.trySend(Event.Frame(it.copyOf())) }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun exchange(
        gatt: BluetoothGatt,
        events: Channel<Event>,
        service: UUID,
        maxPayload: Int,
        onProgress: (String) -> Unit,
        answer: suspend (ByteArray) -> ByteArray,
    ): ByteArray {
        await(events, STEP_TIMEOUT) { (it as? Event.Connection)?.let { c -> if (c.connected) true else throw Dropped("連線失敗（${c.status}）") } }
        gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
        if (Build.VERSION.SDK_INT >= 26) gatt.setPreferredPhy(BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_OPTION_NO_PREFERRED)
        val mtu = if (!gatt.requestMtu(MAX_MTU)) DEFAULT_MTU
        else withTimeoutOrNull(STEP_TIMEOUT) { await(events, null) { (it as? Event.Mtu)?.mtu } } ?: DEFAULT_MTU
        if (!gatt.discoverServices()) throw Dropped("無法讀取對方的藍牙服務")
        await(events, STEP_TIMEOUT) { (it as? Event.Discovered)?.let { d -> if (d.status == BluetoothGatt.GATT_SUCCESS) true else throw Dropped("讀取藍牙服務失敗（${d.status}）") } }
        val s = gatt.getService(service) ?: throw Dropped("對方沒有這次查驗的藍牙服務")
        val frames = s.getCharacteristic(UUID.fromString(BondsLinkTransport.FRAMES_CHARACTERISTIC))
        val state = s.getCharacteristic(UUID.fromString(BondsLinkTransport.STATE_CHARACTERISTIC))
        val reply = s.getCharacteristic(UUID.fromString(BondsLinkTransport.REPLY_CHARACTERISTIC))
        if (frames == null || state == null || reply == null) throw BondsTransportException("對方的藍牙服務不支援年齡證明")
        val cccd = frames.getDescriptor(CCCD) ?: throw BondsTransportException("對方的藍牙服務不支援通知")
        if (!gatt.setCharacteristicNotification(frames, true) || !writeDescriptor(gatt, cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
            throw Dropped("無法訂閱對方的資料")
        }
        await(events, STEP_TIMEOUT) { (it as? Event.DescriptorWritten)?.let { d -> if (d.status == BluetoothGatt.GATT_SUCCESS) true else throw Dropped("訂閱失敗（${d.status}）") } }

        val collector = BondsLinkCollector(maxPayload, BondsLinkTransport.AGE_MAX_CHUNKS)
        val payload = await(events, FRAME_TIMEOUT) {
            (it as? Event.Frame)?.let { f ->
                when (val r = collector.accept(f.value)) {
                    is BondsReception.Completed -> r.payload
                    is BondsReception.Accepted -> { onProgress("藍牙接收中 ${r.received} / ${r.total}"); null }
                    is BondsReception.Duplicate -> null
                }
            }
        }
        write(gatt, events, state, byteArrayOf(BondsLinkTransport.RECEIVED))
        onProgress("已收到證明，正在驗證")
        val verdict = answer(payload)
        for (frame in BondsLinkTransport.frames(verdict, mtu - 3, BondsLinkTransport.REPLY_MAX_PAYLOAD)) write(gatt, events, reply, frame)
        // Let the last write response reach the holder before the link goes down.
        delay(300.milliseconds)
        return payload
    }

    /** Receives events until [pick] returns a value; a disconnect is [Dropped], silence for [timeout] (when given) as well. */
    private suspend fun <T : Any> await(events: Channel<Event>, timeout: Duration?, pick: (Event) -> T?): T {
        while (true) {
            val e = if (timeout == null) events.receive() else withTimeoutOrNull(timeout) { events.receive() } ?: throw Dropped("對方沒有回應")
            if (e is Event.Connection && !e.connected) throw Dropped("連線中斷（${e.status}）")
            pick(e)?.let { return it }
        }
    }

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    private suspend fun write(gatt: BluetoothGatt, events: Channel<Event>, c: BluetoothGattCharacteristic, value: ByteArray) {
        val started = if (Build.VERSION.SDK_INT >= 33) {
            gatt.writeCharacteristic(c, value, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT) == BluetoothGatt.GATT_SUCCESS
        } else {
            c.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
            c.value = value
            gatt.writeCharacteristic(c)
        }
        if (!started) throw Dropped("無法寫入藍牙資料")
        await(events, STEP_TIMEOUT) { (it as? Event.Written)?.let { w -> if (w.status == BluetoothGatt.GATT_SUCCESS) true else throw Dropped("寫入失敗（${w.status}）") } }
    }

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    private fun writeDescriptor(gatt: BluetoothGatt, d: BluetoothGattDescriptor, value: ByteArray): Boolean =
        if (Build.VERSION.SDK_INT >= 33) gatt.writeDescriptor(d, value) == BluetoothGatt.GATT_SUCCESS
        else {
            d.value = value
            gatt.writeDescriptor(d)
        }

    companion object {
        private val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        private const val DEFAULT_MTU = 23
        private const val MAX_MTU = 517
        private const val ATTEMPTS = 3
        private val STEP_TIMEOUT = 10.seconds
        private val FRAME_TIMEOUT = 20.seconds
        const val PERMISSION_REQUEST = 4103
    }
}

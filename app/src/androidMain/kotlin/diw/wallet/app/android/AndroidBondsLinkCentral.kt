package diw.wallet.app.android

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.tr
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
 * connects, subscribes to the frames, writes "received" and then, to a holder that can take it (not Bonds), the framed
 * reply. The holder may be this wallet or the Bonds App. Up to [ATTEMPTS] connections are
 * tried, since a phone that is still proving or a dropped link is common in person.
 */
class AndroidBondsLinkCentral(private val context: Context, private val activity: () -> Activity?) : BondsLinkCentral {
    private val manager get() = context.getSystemService(BluetoothManager::class.java)

    private val permissions: Array<String>
        get() = if (Build.VERSION.SDK_INT >= 31) arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

    override suspend fun unavailableReason(): String? {
        val adapter = manager?.adapter ?: return tr(Res.string.ble_none)
        val missing = permissions.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) {
            activity()?.let { a -> a.runOnUiThread { a.requestPermissions(missing.toTypedArray(), PERMISSION_REQUEST) } }
            return tr(Res.string.ble_permission_retry)
        }
        if (!adapter.isEnabled) return tr(Res.string.ble_off)
        if (adapter.bluetoothLeScanner == null) return tr(Res.string.ble_no_scan)
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
        answer: (suspend (ByteArray) -> ByteArray)?,
    ): ByteArray {
        val adapter = manager?.adapter ?: throw BondsTransportException(tr(Res.string.ble_none))
        val scanner = adapter.bluetoothLeScanner ?: throw BondsTransportException(tr(Res.string.ble_no_scan))
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
                onProgress(if (last == null) tr(Res.string.blec_waiting) else tr(Res.string.blec_searching_again, last))
                scanner.startScan(
                    listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(service)).build()),
                    ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                    scan,
                )
                val device = await(events, null) {
                    when (it) {
                        is Event.Found -> it.device
                        is Event.ScanFailed -> throw BondsTransportException(tr(Res.string.blec_scan_failed, it.code))
                        else -> null
                    }
                }
                runCatching { scanner.stopScan(scan) }
                onProgress(tr(Res.string.blec_found))
                gatt = device.connectGatt(context, false, callback(events), BluetoothDevice.TRANSPORT_LE)
                    ?: throw Dropped(tr(Res.string.blec_cannot_connect))
                return exchange(gatt, events, service, maxPayload, onProgress, answer)
            } catch (e: Dropped) {
                last = e.message
            } finally {
                runCatching { scanner.stopScan(scan) }
                gatt?.let { g -> runCatching { g.disconnect() }; runCatching { g.close() } }
                events.close()
            }
        }
        throw BondsTransportException(tr(Res.string.blec_keeps_dropping, last))
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
        answer: (suspend (ByteArray) -> ByteArray)?,
    ): ByteArray {
        await(events, STEP_TIMEOUT) { (it as? Event.Connection)?.let { c -> if (c.connected) true else throw Dropped(tr(Res.string.blec_connect_failed, c.status)) } }
        gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
        if (Build.VERSION.SDK_INT >= 26) gatt.setPreferredPhy(BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_LE_2M_MASK, BluetoothDevice.PHY_OPTION_NO_PREFERRED)
        val mtu = if (!gatt.requestMtu(MAX_MTU)) DEFAULT_MTU
        else withTimeoutOrNull(STEP_TIMEOUT) { await(events, null) { (it as? Event.Mtu)?.mtu } } ?: DEFAULT_MTU
        if (!gatt.discoverServices()) throw Dropped(tr(Res.string.blec_no_services))
        await(events, STEP_TIMEOUT) { (it as? Event.Discovered)?.let { d -> if (d.status == BluetoothGatt.GATT_SUCCESS) true else throw Dropped(tr(Res.string.blec_services_failed, d.status)) } }
        val s = gatt.getService(service) ?: throw Dropped(tr(Res.string.blec_no_service))
        val frames = s.getCharacteristic(UUID.fromString(BondsLinkTransport.FRAMES_CHARACTERISTIC))
        val state = s.getCharacteristic(UUID.fromString(BondsLinkTransport.STATE_CHARACTERISTIC))
        val reply = answer?.let { s.getCharacteristic(UUID.fromString(BondsLinkTransport.REPLY_CHARACTERISTIC)) }
        if (frames == null || state == null) throw BondsTransportException(tr(Res.string.blec_not_bonds))
        val cccd = frames.getDescriptor(CCCD) ?: throw BondsTransportException(tr(Res.string.blec_no_notify))
        // A holder with the reply characteristic (this wallet) is told a verdict follows; Bonds has none and only waits for "received".
        reply?.let { write(gatt, events, it, byteArrayOf(BondsLinkTransport.REPLY_HELLO)) }
        if (!gatt.setCharacteristicNotification(frames, true) || !writeDescriptor(gatt, cccd, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
            throw Dropped(tr(Res.string.blec_no_subscribe))
        }
        await(events, STEP_TIMEOUT) { (it as? Event.DescriptorWritten)?.let { d -> if (d.status == BluetoothGatt.GATT_SUCCESS) true else throw Dropped(tr(Res.string.blec_subscribe_failed, d.status)) } }

        val collector = BondsLinkCollector(maxPayload, BondsLinkTransport.AGE_MAX_CHUNKS)
        val payload = await(events, FRAME_TIMEOUT) {
            (it as? Event.Frame)?.let { f ->
                when (val r = collector.accept(f.value)) {
                    is BondsReception.Completed -> r.payload
                    is BondsReception.Accepted -> { onProgress(tr(Res.string.blec_receiving, r.received, r.total)); null }
                    is BondsReception.Duplicate -> null
                }
            }
        }
        write(gatt, events, state, byteArrayOf(BondsLinkTransport.RECEIVED))
        if (answer == null) return payload
        onProgress(tr(Res.string.blec_received))
        val verdict = answer(payload)
        if (reply != null) {
            // The verdict is a courtesy to the holder: this device already has the result, so a lost link is not a failure.
            try {
                for (frame in BondsLinkTransport.frames(verdict, mtu - 3, BondsLinkTransport.REPLY_MAX_PAYLOAD)) write(gatt, events, reply, frame)
                delay(300.milliseconds)
            } catch (_: Dropped) {
            } catch (_: BondsTransportException) {
            }
        }
        return payload
    }

    /** Receives events until [pick] returns a value; a disconnect is [Dropped], silence for [timeout] (when given) as well. */
    private suspend fun <T : Any> await(events: Channel<Event>, timeout: Duration?, pick: (Event) -> T?): T {
        while (true) {
            val e = if (timeout == null) events.receive() else withTimeoutOrNull(timeout) { events.receive() } ?: throw Dropped(tr(Res.string.blec_no_answer))
            if (e is Event.Connection && !e.connected) throw Dropped(tr(Res.string.blec_dropped, e.status))
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
        if (!started) throw Dropped(tr(Res.string.blec_write_failed))
        await(events, STEP_TIMEOUT) { (it as? Event.Written)?.let { w -> if (w.status == BluetoothGatt.GATT_SUCCESS) true else throw Dropped(tr(Res.string.blec_write_status, w.status)) } }
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

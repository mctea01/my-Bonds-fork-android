package diw.wallet.app.android

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import diw.wallet.app.BondsLinkPeripheral
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * Bonds BLE link on Android: a GATT server with the verifier's one-time service, advertised as connectable.
 * When the verifier subscribes to the frames characteristic, the frames (sized to the negotiated MTU) are
 * notified one after another; the verifier writes 0x01 to the state characteristic when it has the payload.
 */
class AndroidBondsLink(private val context: Context, private val activity: () -> Activity?) : BondsLinkPeripheral {
    private val manager get() = context.getSystemService(BluetoothManager::class.java)

    private val permissions: Array<String>
        get() = if (Build.VERSION.SDK_INT >= 31) arrayOf(Manifest.permission.BLUETOOTH_ADVERTISE, Manifest.permission.BLUETOOTH_CONNECT)
        else emptyArray()

    override suspend fun unavailableReason(): String? {
        val adapter = manager?.adapter ?: return "此裝置沒有藍牙"
        val missing = permissions.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (missing.isNotEmpty()) {
            activity()?.requestPermissions(missing.toTypedArray(), PERMISSION_REQUEST)
            return "請允許「附近的裝置」權限後再試一次"
        }
        if (!adapter.isEnabled) return "藍牙未開啟"
        if (adapter.bluetoothLeAdvertiser == null || !adapter.isMultipleAdvertisementSupported) return "此裝置不支援藍牙周邊模式"
        return null
    }

    private sealed interface Event {
        data class Subscribed(val device: BluetoothDevice) : Event
        data class Mtu(val mtu: Int) : Event
        data object Sent : Event
        data object Received : Event
        data class Disconnected(val device: BluetoothDevice) : Event
        data class Failed(val reason: String) : Event
    }

    @SuppressLint("MissingPermission")
    override suspend fun send(serviceUuid: String, presentationJws: String, onProgress: (String) -> Unit): Boolean {
        val m = manager ?: return false
        val adapter = m.adapter ?: return false
        val advertiser = adapter.bluetoothLeAdvertiser ?: return false
        val events = Channel<Event>(Channel.UNLIMITED)
        val serviceId = UUID.fromString(serviceUuid)
        val frames = BluetoothGattCharacteristic(
            UUID.fromString(BondsLinkTransport.FRAMES_CHARACTERISTIC),
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ).apply {
            addDescriptor(BluetoothGattDescriptor(CCCD, BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE))
        }
        val stateChar = BluetoothGattCharacteristic(
            UUID.fromString(BondsLinkTransport.STATE_CHARACTERISTIC),
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        var server: BluetoothGattServer? = null
        val callback = object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_DISCONNECTED) events.trySend(Event.Disconnected(device))
            }

            override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
                events.trySend(Event.Mtu(mtu))
            }

            override fun onDescriptorWriteRequest(
                device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
                preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
            ) {
                if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                if (descriptor.uuid == CCCD && value != null && value.isNotEmpty() && value[0].toInt() and 0x01 == 0x01) {
                    events.trySend(Event.Subscribed(device))
                }
            }

            override fun onDescriptorReadRequest(device: BluetoothDevice, requestId: Int, offset: Int, descriptor: BluetoothGattDescriptor) {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
            }

            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
            ) {
                if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                if (characteristic.uuid == stateChar.uuid && value != null && value.isNotEmpty() && value[0] == BondsLinkTransport.RECEIVED) {
                    events.trySend(Event.Received)
                }
            }

            override fun onNotificationSent(device: BluetoothDevice, status: Int) {
                events.trySend(if (status == BluetoothGatt.GATT_SUCCESS) Event.Sent else Event.Failed("通知傳送失敗（$status）"))
            }
        }
        val advertising = object : AdvertiseCallback() {
            override fun onStartFailure(errorCode: Int) {
                events.trySend(Event.Failed("無法開始廣播（$errorCode）"))
            }
        }
        try {
            server = m.openGattServer(context, callback) ?: return false
            val service = BluetoothGattService(serviceId, BluetoothGattService.SERVICE_TYPE_PRIMARY).apply {
                addCharacteristic(frames)
                addCharacteristic(stateChar)
            }
            server.addService(service)
            advertiser.startAdvertising(
                AdvertiseSettings.Builder()
                    .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                    .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                    .setConnectable(true)
                    .build(),
                AdvertiseData.Builder().addServiceUuid(ParcelUuid(serviceId)).setIncludeDeviceName(false).build(),
                advertising,
            )
            return withTimeoutOrNull(2.minutes) { drive(server, frames, events, presentationJws, onProgress) } ?: false
        } finally {
            runCatching { advertiser.stopAdvertising(advertising) }
            runCatching { server?.close() }
            events.close()
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun drive(
        server: BluetoothGattServer,
        frames: BluetoothGattCharacteristic,
        events: Channel<Event>,
        jws: String,
        onProgress: (String) -> Unit,
    ): Boolean {
        var mtu = DEFAULT_MTU
        var device: BluetoothDevice? = null
        while (device == null) {
            when (val e = events.receive()) {
                is Event.Mtu -> mtu = e.mtu
                is Event.Subscribed -> device = e.device
                is Event.Failed -> { onProgress(e.reason); return false }
                else -> {}
            }
        }
        // A central often negotiates the MTU right after subscribing; give it a moment before sizing frames.
        withTimeoutOrNull(MTU_GRACE) {
            while (true) {
                val e = events.receive()
                if (e is Event.Mtu) { mtu = e.mtu; break }
            }
        }
        val chunks = BondsOfflinePresentation.linkFrames(jws, (mtu - 3).coerceAtMost(MAX_NOTIFICATION))
        chunks.forEachIndexed { i, chunk ->
            onProgress("藍牙傳送中 ${i + 1} / ${chunks.size}")
            if (!notify(server, device, frames, chunk)) { onProgress("藍牙傳送失敗"); return false }
            while (true) {
                when (val e = events.receive()) {
                    Event.Sent -> break
                    Event.Received -> return true
                    is Event.Failed -> { onProgress(e.reason); return false }
                    is Event.Disconnected -> if (e.device == device) { onProgress("查驗方已中斷連線"); return false }
                    else -> {}
                }
            }
        }
        onProgress("等待查驗方確認")
        while (true) {
            when (val e = events.receive()) {
                Event.Received -> return true
                is Event.Disconnected -> if (e.device == device) return false
                is Event.Failed -> return false
                else -> {}
            }
        }
    }

    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    private fun notify(server: BluetoothGattServer, device: BluetoothDevice, c: BluetoothGattCharacteristic, value: ByteArray): Boolean =
        if (Build.VERSION.SDK_INT >= 33) {
            server.notifyCharacteristicChanged(device, c, false, value) == BluetoothGatt.GATT_SUCCESS
        } else {
            c.value = value
            server.notifyCharacteristicChanged(device, c, false)
        }

    companion object {
        private val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
        private const val DEFAULT_MTU = 23
        private const val MAX_NOTIFICATION = 512
        private val MTU_GRACE = 1.seconds
        const val PERMISSION_REQUEST = 4102
    }
}

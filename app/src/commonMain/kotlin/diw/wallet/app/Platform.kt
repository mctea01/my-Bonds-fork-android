package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import io.ktor.client.HttpClient
import kotlinx.io.bytestring.ByteString
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.storage.Storage

/** Decodes PNG, JPEG or WebP bytes with the platform image codec. */
expect fun decodeImageBytes(bytes: ByteArray): ImageBitmap?

/** Where credential keys live; listed from strongest to weakest. */
enum class KeyProtection(val wire: String, val displayName: String, val hardware: Boolean) {
    STRONGBOX("strongbox", "StrongBox 安全晶片", true),
    TEE("tee", "TEE 可信執行環境", true),
    SOFTWARE("software", "軟體金鑰（App PIN 保護）", false),
}

/** A secure area and how to create keys in it. */
class KeyBackend(
    val secureArea: SecureArea,
    val protection: KeyProtection,
    /** challenge is the issuer nonce (Android attestation challenge); userAuth requests biometric or PIN per use. */
    val settings: suspend (challenge: ByteString, userAuth: Boolean) -> CreateKeySettings,
)

/**
 * Bonds BLE link: the holder is the GATT peripheral advertising the verifier's one-time service UUID, notifies
 * the frames and finishes when the verifier writes "received". [send] returns true when the verifier confirmed.
 */
interface BondsLinkPeripheral {
    /** Null when the link can be used now, otherwise why not (Bluetooth off, permission missing, no peripheral mode). */
    suspend fun unavailableReason(): String?

    suspend fun send(serviceUuid: String, presentationJws: String, onProgress: (String) -> Unit): Boolean
}

/** Everything platform specific the shared wallet model needs. */
interface PlatformServices {
    val platformName: String

    /** Encrypted storage for documents, keys metadata and trust anchors. */
    suspend fun openStorage(): Storage

    /** Secure areas in preference order; the first one is used for new credentials. [pinPrompt] supplies the App PIN for software keys. */
    suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?): List<KeyBackend>

    /** Unlock provider that delegates platform keys to the OS prompt and software keys to the App PIN. */
    fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider

    fun httpClient(): HttpClient

    /** Opens an authorization page (OpenID4VCI authorization code flow) in the system browser. */
    fun openBrowser(url: String)

    /** Opens a link the Verifier returned after a presentation. */
    fun openRedirect(url: String) = openBrowser(url)

    /** Redirect URI registered for this platform (custom scheme on Android, loopback on desktop). */
    val oid4vciRedirectUri: String

    /** Registers stored credentials with the platform Digital Credentials API (no-op where unavailable). */
    suspend fun registerDigitalCredentials(model: WalletModel) {}

    /** Decodes a PNG (or another platform image format) for display; null when it is not an image. */
    fun decodeImage(bytes: ByteArray): ImageBitmap? = decodeImageBytes(bytes)

    /** Bonds BLE link, where the platform can act as a GATT peripheral. */
    val bondsLink: BondsLinkPeripheral? get() = null

    /** Keeps the screen on and bright while a code is shown at a counter or to a verifier. */
    fun keepScreenOn(on: Boolean) {}

    /** Why an NFC tap cannot start a proximity presentation now (no NFC, NFC off, no card emulation); null when it can. */
    fun nfcPresentationUnavailableReason(): String? = "此裝置不支援 NFC 感應出示"

    /**
     * Why Bluetooth cannot carry a proximity presentation now (no Bluetooth, turned off, permission missing, which is
     * then asked for); null when it can.
     */
    suspend fun proximityTransportUnavailableReason(): String? = "此平台不支援藍牙近距離傳輸"

    /** While true, NFC taps go to the wallet rather than another wallet app (Android card emulation preference). */
    fun setNfcPresentationActive(active: Boolean) {}
}

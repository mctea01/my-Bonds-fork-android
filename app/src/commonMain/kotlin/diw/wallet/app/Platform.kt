package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import io.ktor.client.HttpClient
import kotlinx.io.bytestring.ByteString
import org.multipaz.nfc.NfcTagReader
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.storage.Storage
import kotlin.time.Instant

/** Decodes PNG, JPEG or WebP bytes with the platform image codec. */
expect fun decodeImageBytes(bytes: ByteArray): ImageBitmap?

/** PNG encoding of an image (card art for the Digital Credentials picker); null when it fails. */
expect fun encodePng(image: ImageBitmap): ByteArray?

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

/**
 * An NFC reader the wallet can read another wallet with: the phone's own NFC, or an external reader (PC/SC on a
 * computer, USB CCID on a phone).
 */
class NfcReaderOption(
    val name: String,
    /** Attached to the device rather than its own antenna. */
    val external: Boolean,
    val reader: NfcTagReader,
    /** After the tap the data may also go over Bluetooth (a phone); a computer's reader is NFC only. */
    val bluetooth: Boolean = false,
)

/** The NFC readers found now; [problem] says why there are none, or why some may be missing. */
data class NfcReaderList(val readers: List<NfcReaderOption>, val problem: String? = null)

/** A file the user picked or another app handed over. */
class PickedFile(val name: String, val bytes: ByteArray, val mediaType: String? = null)

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

    /**
     * Registers stored credentials with the platform Digital Credentials API and records the outcome in
     * [WalletModel.dcApiRegistration] (no-op where unavailable). [force] registers even when nothing changed.
     */
    suspend fun registerDigitalCredentials(model: WalletModel, force: Boolean = false) {}

    /** Decodes a PNG (or another platform image format) for display; null when it is not an image. */
    fun decodeImage(bytes: ByteArray): ImageBitmap? = decodeImageBytes(bytes)

    /**
     * The first [maxPages] pages of an unencrypted PDF as images [widthPx] wide (encrypted files are handed over
     * decrypted, see PdfPlain); empty when the platform has no renderer or the file cannot be drawn.
     */
    suspend fun renderPdf(bytes: ByteArray, maxPages: Int, widthPx: Int): List<ImageBitmap> = emptyList()

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

    /** NFC readers for reading another wallet in person (ISO/IEC 18013-5 mdoc reader) or a citizen certificate card. */
    suspend fun nfcReaders(): NfcReaderList = NfcReaderList(emptyList(), "此平台不支援 NFC 讀取")

    /** Lets the user pick a file to store; null when cancelled or not possible. */
    suspend fun pickFile(): PickedFile? = null

    /** Lets the user save [bytes] under a name they choose; false when cancelled or not possible. */
    suspend fun saveFile(name: String, mediaType: String, bytes: ByteArray): Boolean = false

    /** Document source pages open inside the app (downloads go straight to the vault) rather than in a browser. */
    val embeddedBrowser: Boolean get() = false

    /** Hands a link of another app (such as mobilemoica: for the mobile citizen certificate) to the system; false when no app takes it. */
    fun openExternal(url: String): Boolean = false
}

/** Outcome of the last registration with the platform Digital Credentials API, shown in settings. */
data class DcApiRegistration(
    /** Credentials the system picker can offer (mdoc and SD-JWT VC). */
    val registered: Int,
    /** Documents only held as W3C VCs (TWDIW cards and others), which the platform matcher cannot offer. */
    val notListable: Int,
    val protocols: Set<String>,
    /** Why the system refused the registration; null when it was accepted. */
    val error: String?,
    val at: Instant,
)

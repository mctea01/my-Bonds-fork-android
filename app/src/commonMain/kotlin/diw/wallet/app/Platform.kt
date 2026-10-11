package diw.wallet.app

import io.ktor.client.HttpClient
import kotlinx.io.bytestring.ByteString
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.storage.Storage

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
}

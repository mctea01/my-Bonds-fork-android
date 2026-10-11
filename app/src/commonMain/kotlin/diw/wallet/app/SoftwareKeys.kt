package diw.wallet.app

import org.multipaz.crypto.Algorithm
import org.multipaz.prompt.Reason
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.PassphraseConstraints
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareKeyUnlockData
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.Storage

/**
 * Pure software fallback for platforms without hardware key storage (emulator, AOSP without TEE access,
 * Linux phones, PC). Keys that need user authentication are sealed with the App PIN.
 */
suspend fun softwareBackend(storage: Storage, pinPrompt: suspend (String) -> String?): KeyBackend =
    KeyBackend(SoftwareSecureArea.create(storage), KeyProtection.SOFTWARE) { _, userAuth ->
        val b = SoftwareCreateKeySettings.Builder()
        if (userAuth) {
            val pin = pinPrompt("設定此憑證金鑰的 App PIN（至少 6 位數字），之後每次使用都需輸入")
                ?: throw KeyLockedException("使用者取消輸入 App PIN")
            b.setPassphraseRequired(true, pin, PassphraseConstraints.PIN_SIX_DIGITS_OR_LONGER)
        }
        b.build()
    }

/** Unlocks software keys with the App PIN and hands every other secure area to [platform]. */
class PinOrPlatformUnlock(
    private val pinPrompt: suspend () -> String?,
    private val platform: KeyUnlockDataProvider?,
) : KeyUnlockDataProvider {
    override suspend fun getKeyUnlockData(secureArea: SecureArea, alias: String, algorithm: Algorithm, unlockReason: Reason): KeyUnlockData {
        if (secureArea is SoftwareSecureArea) {
            val pin = pinPrompt() ?: throw KeyLockedException("使用者取消輸入 App PIN")
            return SoftwareKeyUnlockData(secureArea, alias, pin)
        }
        return platform?.getKeyUnlockData(secureArea, alias, algorithm, unlockReason)
            ?: throw KeyLockedException("此平台無法解鎖 ${secureArea.displayName} 的金鑰")
    }
}

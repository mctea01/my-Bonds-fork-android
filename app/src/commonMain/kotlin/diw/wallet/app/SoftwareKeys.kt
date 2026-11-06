package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
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
            val pin = pinPrompt(tr(Res.string.sk_set_pin))
                ?: throw KeyLockedException(tr(Res.string.sk_pin_cancelled))
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
            val pin = pinPrompt() ?: throw KeyLockedException(tr(Res.string.sk_pin_cancelled))
            return SoftwareKeyUnlockData(secureArea, alias, pin)
        }
        return platform?.getKeyUnlockData(secureArea, alias, algorithm, unlockReason)
            ?: throw KeyLockedException(tr(Res.string.sk_cannot_unlock, secureArea.displayName))
    }
}

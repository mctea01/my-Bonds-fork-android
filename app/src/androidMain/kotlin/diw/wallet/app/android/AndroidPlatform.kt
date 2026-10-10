package diw.wallet.app.android

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.browser.customtabs.CustomTabsIntent
import diw.wallet.app.KeyBackend
import diw.wallet.app.KeyProtection
import diw.wallet.app.PinOrPlatformUnlock
import diw.wallet.app.PlatformServices
import diw.wallet.app.WalletModel
import diw.wallet.app.softwareBackend
import diw.wallet.core.storage.EncryptedStorage
import diw.wallet.core.storage.ValueCipher
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.multipaz.crypto.Algorithm
import org.multipaz.digitalcredentials.DigitalCredentials
import org.multipaz.digitalcredentials.getDefault
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.Reason
import org.multipaz.securearea.AndroidKeystoreCreateKeySettings
import org.multipaz.securearea.AndroidKeystoreDefaultKeyUnlockDataProvider
import org.multipaz.securearea.AndroidKeystoreSecureArea
import org.multipaz.securearea.KeyLockedException
import org.multipaz.securearea.KeyUnlockData
import org.multipaz.securearea.KeyUnlockDataProvider
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.UserAuthenticationType
import org.multipaz.storage.Storage
import org.multipaz.storage.android.AndroidStorage
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.time.Duration

/** AES-256-GCM with a non-exportable Android Keystore key; output is iv(12) || ciphertext || tag. */
class KeystoreValueCipher(private val alias: String = "diw-storage-v1") : ValueCipher {
    private val key: SecretKey by lazy {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            generateKey()
        }
    }

    override suspend fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        c.updateAAD(aad)
        return c.iv + c.doFinal(plaintext)
    }

    override suspend fun decrypt(ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, ciphertext, 0, 12))
        c.updateAAD(aad)
        return c.doFinal(ciphertext, 12, ciphertext.size - 12)
    }
}

class AndroidPlatform(private val context: Context) : PlatformServices {
    override val platformName = "Android ${android.os.Build.VERSION.RELEASE} (API ${android.os.Build.VERSION.SDK_INT})"
    override val oid4vciRedirectUri = "diw-wallet://oid4vci/callback"

    /** Prompt model of the activity in the foreground; biometric prompts need one. */
    @Volatile var promptModel: AndroidPromptModel? = null

    private val deviceSecure: Boolean
        get() = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true

    override suspend fun openStorage(): Storage = withContext(Dispatchers.IO) {
        val file = File(context.noBackupFilesDir, "diw-wallet-v1.db")
        EncryptedStorage(AndroidStorage(file.absolutePath), KeystoreValueCipher())
    }

    override suspend fun keyBackends(storage: Storage, pinPrompt: suspend (String) -> String?): List<KeyBackend> {
        val keystore = AndroidKeystoreSecureArea.create(storage)
        val software = softwareBackend(storage, pinPrompt)
        val secure = deviceSecure
        fun hw(strongBox: Boolean) = KeyBackend(keystore, if (strongBox) KeyProtection.STRONGBOX else KeyProtection.TEE) { challenge, userAuth ->
            AndroidKeystoreCreateKeySettings.Builder(challenge)
                .setUseStrongBox(strongBox)
                .apply {
                    // Without a screen lock Android cannot bind keys to the user; such keys are not created (software takes over).
                    if (userAuth) setUserAuthenticationRequired(true, Duration.ZERO, setOf(UserAuthenticationType.LSKF, UserAuthenticationType.BIOMETRIC))
                }
                .build()
        }
        val hardware = buildList {
            if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) add(hw(true))
            add(hw(false))
        }
        // No screen lock: user-bound hardware keys are impossible, so new credentials use App PIN software keys first.
        return if (secure) hardware + software else listOf(software) + hardware
    }

    override fun keyUnlockProvider(pinPrompt: suspend () -> String?): KeyUnlockDataProvider =
        PinOrPlatformUnlock(pinPrompt, object : KeyUnlockDataProvider {
            override suspend fun getKeyUnlockData(secureArea: SecureArea, alias: String, algorithm: Algorithm, unlockReason: Reason): KeyUnlockData {
                val pm = promptModel ?: throw KeyLockedException("請先開啟錢包畫面再進行驗證")
                return withContext(pm) { AndroidKeystoreDefaultKeyUnlockDataProvider.getKeyUnlockData(secureArea, alias, algorithm, unlockReason) }
            }
        })

    override fun httpClient(): HttpClient = HttpClient(OkHttp) { followRedirects = false }

    override fun openBrowser(url: String) {
        val tab = CustomTabsIntent.Builder().setShowTitle(true).build()
        tab.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        tab.launchUrl(context, Uri.parse(url))
    }

    override fun openRedirect(url: String) {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    override suspend fun registerDigitalCredentials(model: WalletModel) {
        runCatching {
            val dc = DigitalCredentials.getDefault()
            if (!dc.registerAvailable) return
            // Only OpenID4VP goes through the DIW request validation layer, so only those protocols are offered.
            val protocols = dc.supportedProtocols.filter { it.startsWith("openid4vp") }.toSet()
            dc.register(model.documentStore, model.documentTypes, protocols, false)
        }
    }
}

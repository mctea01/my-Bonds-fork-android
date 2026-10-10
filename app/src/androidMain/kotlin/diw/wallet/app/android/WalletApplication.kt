package diw.wallet.app.android

import android.app.Application
import diw.wallet.app.WalletModel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.multipaz.context.initializeApplication
import java.security.Security

class WalletApplication : Application() {
    lateinit var platform: AndroidPlatform
        private set
    lateinit var model: WalletModel
        private set

    override fun onCreate() {
        super.onCreate()
        initializeApplication(applicationContext)
        // Android ships a stripped BouncyCastle under the same name; replace it with the full provider.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.addProvider(BouncyCastleProvider())
        platform = AndroidPlatform(applicationContext)
        model = WalletModel(platform)
        model.scope.launch {
            try {
                model.init()
                platform.registerDigitalCredentials(model)
            } catch (e: Exception) {
                model.message.value = "錢包初始化失敗：${e.message}"
            }
        }
    }

    /** Waits until storage and keys are ready; activities started by the system may arrive first. */
    suspend fun awaitReady() {
        model.ready.first { it }
    }
}

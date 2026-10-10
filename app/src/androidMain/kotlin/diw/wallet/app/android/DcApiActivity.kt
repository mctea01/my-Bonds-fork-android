package diw.wallet.app.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.registry.provider.selectedEntryId
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import diw.wallet.app.Screen
import diw.wallet.app.ui.WalletApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.compose.prompt.PromptDialogs
import org.multipaz.digitalcredentials.getAppOrigin
import org.multipaz.prompt.AndroidPromptModel

/**
 * Credential Manager (Digital Credentials API) entry point. Unlike Multipaz's stock activity, every request goes
 * through the DIW validation layer (client_id, expected_origins, trust tier) and the shared consent screen.
 */
class DcApiActivity : FragmentActivity() {
    private val app get() = application as WalletApplication
    private val promptModel = AndroidPromptModel.Builder().apply { addCommonDialogs() }.build()
    private var finished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PromptDialogs(promptModel)
            WalletApp(app.model)
        }
        lifecycleScope.launch { run() }
    }

    override fun onResume() {
        super.onResume()
        app.platform.promptModel = promptModel
    }

    override fun onPause() {
        if (app.platform.promptModel === promptModel) app.platform.promptModel = null
        super.onPause()
    }

    override fun onDestroy() {
        if (!finished) app.model.cancelDcApi()
        promptModel.cancel()
        super.onDestroy()
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    private suspend fun run() {
        try {
            val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                ?: throw IllegalStateException("沒有 Credential Manager 請求")
            val caller = request.callingAppInfo
            // Browsers are trusted to report the web origin only when on the privileged allow list; otherwise the app signature is the origin.
            val origin = runCatching { caller.getOrigin(PRIVILEGED_BROWSERS) }.getOrNull()
                ?: getAppOrigin(caller.signingInfoCompat.signingCertificateHistory[0].toByteArray())
            val option = request.credentialOptions.filterIsInstance<GetDigitalCredentialOption>().firstOrNull()
                ?: throw IllegalStateException("不是數位憑證請求")
            val json = Json.parseToJsonElement(option.requestJson).jsonObject
            val protocol = selectedProtocol(request)
            val entry = json["requests"]?.jsonArray?.map { it.jsonObject }
                ?.firstOrNull { protocol == null || it["protocol"]?.jsonPrimitive?.content == protocol }
                ?: throw IllegalStateException("請求中沒有可處理的協定")
            val p = entry["protocol"]!!.jsonPrimitive.content
            if (!p.startsWith("openid4vp")) throw IllegalStateException("不支援的協定：$p")

            app.awaitReady()
            val data = app.model.presentDcApi(p, entry["data"]!!.jsonObject, origin)
            if (data == null) {
                fail(GetCredentialCancellationException("使用者拒絕或請求驗證失敗"))
                return
            }
            val response = buildJsonObject {
                put("protocol", JsonPrimitive(p))
                put("data", data)
            }
            succeed(response)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            fail(GetCredentialUnknownException(e.message))
        }
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    private fun succeed(response: JsonObject) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(DigitalCredential(Json.encodeToString(JsonObject.serializer(), response))))
        done(result)
    }

    private fun fail(e: GetCredentialException) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, e)
        done(result)
    }

    private fun done(result: Intent) {
        finished = true
        setResult(RESULT_OK, result)
        app.model.screen.value = Screen.Home
        finish()
    }

    /** Protocol part of the entry the user picked in the system selector ("<type> <protocol> <docId>" or a credential set). */
    private fun selectedProtocol(request: ProviderGetCredentialRequest): String? {
        val setId = request.sourceBundle?.getString("androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ID")
        if (setId != null) return setId.split(" ").getOrNull(1)
        return runCatching { request.selectedEntryId }.getOrNull()?.split(" ")?.getOrNull(1)
    }

    companion object {
        /** Minimal allow list (Chrome stable); a privileged browser reports the calling web origin. */
        private val PRIVILEGED_BROWSERS = """
            {"apps":[{"type":"android","info":{"package_name":"com.android.chrome","signatures":[
            {"build":"release","cert_fingerprint_sha256":"F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83"}]}}]}
        """.trimIndent()
    }
}

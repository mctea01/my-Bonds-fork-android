package diw.wallet.app.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
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
 *
 * Credential Manager reports every provider error to the web page as a cancelled request, so failures stay on screen
 * until the user leaves them; validation failures are then returned as an OpenID4VP error the Verifier can show.
 */
class DcApiActivity : FragmentActivity() {
    private val app get() = application as WalletApplication
    private val promptModel = AndroidPromptModel.Builder().apply { addCommonDialogs() }.build()
    private var finished = false

    /**
     * Browsers (and Google Play services, which relays their requests) trusted to report the web origin: the list Google
     * Password Manager uses, https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json. Any other caller is
     * identified by its signing key.
     */
    private val privilegedUserAgents by lazy { assets.open("privileged_user_agents.json").use { it.readBytes().decodeToString() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val screen by app.model.screen.collectAsState()
            BackHandler(enabled = screen != Screen.Home) { app.model.back() }
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
        if (!finished) app.model.leaveDcApi()
        promptModel.cancel()
        super.onDestroy()
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    private suspend fun run() {
        app.awaitReady()
        var protocol: String? = null
        val data = try {
            val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                ?: throw IllegalStateException("沒有 Credential Manager 請求")
            val caller = request.callingAppInfo
            val origin = runCatching { caller.getOrigin(privilegedUserAgents) }.getOrNull()
                ?: getAppOrigin(caller.signingInfoCompat.signingCertificateHistory[0].toByteArray())
            val option = request.credentialOptions.filterIsInstance<GetDigitalCredentialOption>().firstOrNull()
                ?: throw IllegalStateException("不是數位憑證請求")
            val json = Json.parseToJsonElement(option.requestJson).jsonObject
            val selected = selectedProtocol(request)
            val entry = json["requests"]?.jsonArray?.map { it.jsonObject }
                ?.firstOrNull { selected == null || it["protocol"]?.jsonPrimitive?.content == selected }
                ?: throw IllegalStateException("請求中沒有可處理的協定")
            val p = entry["protocol"]!!.jsonPrimitive.content
            if (!p.startsWith("openid4vp")) throw IllegalStateException("不支援的協定：$p")
            protocol = p
            app.model.presentDcApi(p, entry["data"]!!.jsonObject, origin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            app.model.failDcApi(app.model.describe(e))
        }
        if (data == null || protocol == null) {
            fail()
        } else {
            succeed(buildJsonObject {
                put("protocol", JsonPrimitive(protocol))
                put("data", data)
            })
        }
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    private fun succeed(response: JsonObject) {
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(DigitalCredential(Json.encodeToString(JsonObject.serializer(), response))))
        done(result)
    }

    private fun fail() {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException("使用者取消或無法處理請求"))
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
}

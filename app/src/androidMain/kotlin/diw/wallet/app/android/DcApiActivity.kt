package diw.wallet.app.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.credentials.CreateDigitalCredentialRequest
import androidx.credentials.CreateDigitalCredentialResponse
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.CreateCredentialCancellationException
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
        if (intent.action == ACTION_CREATE) return create()
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
            val selected = selectedEntry(request)
            val entry = json["requests"]?.jsonArray?.map { it.jsonObject }
                ?.firstOrNull { selected == null || it["protocol"]?.jsonPrimitive?.content == selected.protocol }
                ?: throw IllegalStateException("請求中沒有可處理的協定")
            val p = entry["protocol"]!!.jsonPrimitive.content
            protocol = p
            // The documents the holder picked in the system selector (one entry, or every element of a credential set).
            val documentIds = selected?.documentIds.orEmpty()
            when {
                p.startsWith("openid4vp") -> app.model.presentDcApi(p, entry["data"]!!.jsonObject, origin, documentIds)
                // ISO/IEC 18013-7 Annex C: the mdoc DeviceRequest, answered on the same consent screen as in person.
                p == "org-iso-mdoc" || p == "org.iso.mdoc" -> {
                    val appId = if (origin.startsWith("android:")) caller.packageName else null
                    app.model.proximity.presentDcApi(p, entry["data"]!!.jsonObject, origin, appId, documentIds)?.get("data")?.jsonObject
                }
                else -> throw IllegalStateException("不支援的協定：$p")
            }
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

    /**
     * A web page or app saves a credential (navigator.credentials.create): the request names OpenID4VCI and carries the
     * credential offer, which runs through the wallet's issuance screens. The answer is the bare acknowledgement the
     * protocol defines; the credential itself comes from the issuer.
     */
    @OptIn(ExperimentalDigitalCredentialApi::class)
    private suspend fun create() {
        val result = Intent()
        val protocol = try {
            val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                ?: throw IllegalStateException("沒有 Credential Manager 請求")
            val caller = request.callingAppInfo
            val origin = runCatching { caller.getOrigin(privilegedUserAgents) }.getOrNull()
                ?: getAppOrigin(caller.signingInfoCompat.signingCertificateHistory[0].toByteArray())
            val requestJson = (request.callingRequest as? CreateDigitalCredentialRequest)?.requestJson
                ?: request.callingRequest.credentialData.getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON")
                ?: throw IllegalStateException("不是數位憑證請求")
            val entry = Json.parseToJsonElement(requestJson).jsonObject["requests"]?.jsonArray?.map { it.jsonObject }
                ?.firstOrNull { it["protocol"]?.jsonPrimitive?.content in ISSUANCE_PROTOCOLS }
                ?: throw IllegalStateException("請求中沒有 OpenID4VCI 發卡協定")
            val p = entry["protocol"]!!.jsonPrimitive.content
            if (app.model.receiveDcApi(entry["data"]!!.jsonObject, origin)) p else null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            app.model.failDcApi(app.model.describe(e))
            null
        }
        if (protocol == null) {
            PendingIntentHandler.setCreateCredentialException(result, CreateCredentialCancellationException("使用者取消或沒有存入證件"))
        } else {
            val ack = buildJsonObject { put("protocol", JsonPrimitive(protocol)); put("data", JsonObject(emptyMap())) }
            PendingIntentHandler.setCreateCredentialResponse(result, CreateDigitalCredentialResponse(Json.encodeToString(JsonObject.serializer(), ack)))
        }
        done(result)
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

    /** The protocol and document ids of the entry the user picked in the system selector. */
    private data class SelectedEntry(val protocol: String, val documentIds: List<String>)

    /**
     * What the user picked in the system selector: a single entry ("<type> <protocol> <docId>"), or a credential set
     * (CREDENTIAL_SET_ID "<type> <protocol>" with CREDENTIAL_SET_ELEMENT_ID_n entries, one per document the set needs).
     * The docId is the document's Credential Manager id, which is its [org.multipaz.document.Document.identifier]; it is
     * carried through so the picked credential, not merely the first match, answers the request.
     */
    private fun selectedEntry(request: ProviderGetCredentialRequest): SelectedEntry? {
        val bundle = request.sourceBundle
        val setId = bundle?.getString("androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ID")
        if (setId != null) {
            val protocol = setId.split(" ").getOrNull(1) ?: return null
            val length = bundle.getInt("androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_LENGTH", 0)
            val ids = (0 until length).mapNotNull { n ->
                bundle.getString("androidx.credentials.registry.provider.extra.CREDENTIAL_SET_ELEMENT_ID_$n")
                    ?.split(" ")?.getOrNull(2)
            }
            return SelectedEntry(protocol, ids)
        }
        val entryId = runCatching { request.selectedEntryId }.getOrNull()?.split(" ") ?: return null
        val protocol = entryId.getOrNull(1) ?: return null
        return SelectedEntry(protocol, listOfNotNull(entryId.getOrNull(2)))
    }

    private companion object {
        const val ACTION_CREATE = "androidx.credentials.registry.provider.action.CREATE_CREDENTIAL"
        /** OpenID4VCI over the Digital Credentials API: the final name and the earlier draft name. */
        val ISSUANCE_PROTOCOLS = setOf("openid4vci-v1", "openid4vci1.0", "openid4vci")
    }
}

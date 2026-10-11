package diw.wallet.app

import diw.wallet.core.profile.msvid.MsIssuanceRequest
import diw.wallet.core.profile.msvid.MsPresentationRequirement
import diw.wallet.core.profile.msvid.MsTokenRequirement
import diw.wallet.core.profile.msvid.MsVerifiedIdIssuance
import diw.wallet.core.w3c.W3cInspector
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.multipaz.document.Document

sealed class MsIssuanceUi {
    data object Loading : MsIssuanceUi()

    /** [revision] changes whenever the request gains a token, so the screen recomposes. */
    data class Review(val request: MsIssuanceRequest, val revision: Int) : MsIssuanceUi()
    data class WaitingForLogin(val request: MsIssuanceRequest, val requirement: MsTokenRequirement) : MsIssuanceUi()
    data class Working(val message: String) : MsIssuanceUi()
    data class Done(val document: Document) : MsIssuanceUi()
    data class Failed(val message: String) : MsIssuanceUi()
}

/** Microsoft Entra Verified ID issuance (openid-vc request with prompt=create, contract flow). */
class MsIssuanceModel(private val model: WalletModel) {
    val state = MutableStateFlow<MsIssuanceUi>(MsIssuanceUi.Loading)
    private var current: MsIssuanceRequest? = null
    private var revision = 0

    private fun issuance(): MsVerifiedIdIssuance {
        val loopback = model.environmentPolicy.insecureLoopbackAllowed
        return MsVerifiedIdIssuance(
            model.http,
            model.didResolver(),
            model.linkedDomains,
            W3cInspector(model.http, model.trust, loopback, model.didTrust),
            model.holderIdentities,
            model.documentStore,
            loopback,
        )
    }

    /** Resolves [uri]; true when it was an issuance request (now shown), false for a presentation request. */
    suspend fun start(uri: String): Boolean {
        val request = issuance().resolve(uri) ?: return false
        current = request
        state.value = MsIssuanceUi.Review(request, ++revision)
        model.screen.value = Screen.MsIssuance
        return true
    }

    /** The contract's identity provider redirect while a sign-in is pending. */
    fun isLoginRedirect(uri: String): Boolean {
        val waiting = state.value as? MsIssuanceUi.WaitingForLogin ?: return false
        val target = waiting.requirement.redirectUri
        return target.isNotEmpty() && uri.startsWith(target)
    }

    fun login(request: MsIssuanceRequest, requirement: MsTokenRequirement) = model.scope.launch {
        try {
            val url = issuance().beginLogin(request, requirement)
            state.value = MsIssuanceUi.WaitingForLogin(request, requirement)
            model.platform.openBrowser(url)
        } catch (e: Exception) {
            state.value = MsIssuanceUi.Failed(model.describe(e))
        }
    }

    fun completeLogin(redirect: String) {
        val request = current ?: return
        model.screen.value = Screen.MsIssuance
        model.scope.launch {
            try {
                state.value = MsIssuanceUi.Working("完成登入")
                issuance().completeLogin(request, redirect)
                state.value = MsIssuanceUi.Review(request, ++revision)
            } catch (e: Exception) {
                state.value = MsIssuanceUi.Failed(model.describe(e))
            }
        }
    }

    /** Stored Verified ID and W3C cards that satisfy a presentation the contract asks for (type and listed issuers). */
    suspend fun candidates(requirement: MsPresentationRequirement): List<Pair<Document, W3cVcCredential>> =
        model.documents.value.mapNotNull { doc ->
            val c = doc.getCertifiedCredentials().filterIsInstance<W3cVcCredential>()
                .firstOrNull { requirement.accepts(it) } ?: return@mapNotNull null
            doc to c
        }

    fun complete(
        request: MsIssuanceRequest,
        selfIssued: Map<String, String>,
        pin: String?,
        presentations: Map<String, W3cVcCredential>,
    ) = model.scope.launch {
        state.value = MsIssuanceUi.Working("向發行端領取憑證")
        try {
            request.selfIssued.putAll(selfIssued.filterValues { it.isNotEmpty() })
            request.pin = pin?.ifEmpty { null }
            request.presentations.putAll(presentations)
            val doc = try {
                withContext(model.unlockProvider) { issuance().complete(request, model.keyRequest()) }
            } finally {
                model.endOperation()
            }
            current = null
            model.refreshDocuments()
            state.value = MsIssuanceUi.Done(doc)
        } catch (e: Exception) {
            current = null
            state.value = MsIssuanceUi.Failed(model.describe(e))
        }
    }

    /** Declines a pending request and tells the issuer. */
    fun cancel() {
        val request = current ?: return
        current = null
        model.scope.launch { runCatching { issuance().cancel(request) } }
        state.value = MsIssuanceUi.Failed("已取消")
    }
}

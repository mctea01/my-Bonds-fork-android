package diw.wallet.app

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.x509.displaySubject
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.crypto.X509Cert

/**
 * The production server (diw-wallet-server) set in [WalletSettings.zkVerifierUrl], which serves the relay, the
 * zkTLS verifier host and the age host. Its `/info` names the root that signs its zkTLS requests and web-proof
 * receipts; the user compares the root's SHA-256 with what the operator published and then trusts it as their own
 * anchor (T2) for verifiers and issuers. A changed root is never accepted silently.
 */
class ServerModel(private val model: WalletModel) {
    /** What `/info` says about the server's signing root. */
    data class Info(val url: String, val subject: String, val sha256: String, val root: X509Cert, val features: List<String>)

    data class State(
        val checking: Boolean = false,
        /** Read from the server and waiting for the user to compare and confirm. */
        val pending: Info? = null,
        /** The root the server names now differs from the one the user trusted. */
        val changed: Boolean = false,
        val error: String? = null,
    )

    val state = MutableStateFlow(State())

    private fun base(): String? = model.settings.zkVerifierUrl.trim().trimEnd('/').takeIf { it.isNotEmpty() }

    /** The token for [base] when it is the configured server; never sent to the test server or another host. */
    fun tokenFor(base: String): String? = model.settings.serverToken.takeIf { it.isNotEmpty() && base() == base.trimEnd('/') }

    private fun source(url: String) = SOURCE_PREFIX + Url(url).host

    /** Reads the server's signing root. With [confirm] the result waits for the user; otherwise it only notes a change. */
    fun check(confirm: Boolean) {
        val url = base() ?: return
        state.value = state.value.copy(checking = true, error = null)
        model.scope.launch {
            state.value = try {
                val info = read(url)
                val trusted = model.settings.serverRootSha256
                State(pending = info.takeIf { confirm }, changed = trusted.isNotEmpty() && trusted != info.sha256)
            } catch (e: Exception) {
                State(error = model.describe(e))
            }
        }
    }

    private suspend fun read(url: String): Info {
        val response = model.http.get("$url/info")
        if (!response.status.isSuccess()) throw ProtocolException("server_error", "HTTP ${response.status.value}")
        val o = DiwJson.parseToJsonElement(response.bodyAsText()) as? JsonObject ?: throw ProtocolException("server_error", "不是服務端的 /info")
        val features = (o["features"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.content }
        val signing = o["signing"] as? JsonObject
            ?: throw ProtocolException("unavailable", "這台服務端沒有簽章金鑰（未啟用 zkTLS 查驗主機），不需要加入信任")
        val root = X509Cert.fromPem(signing.str("root") ?: throw ProtocolException("server_error", "No signing root"))
        if (!TrustRegistry.isRoot(root)) throw ProtocolException("server_error", "服務端提供的不是根憑證")
        val sha = PlatformCrypto.sha256(root.encoded.toByteArray()).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
        // The fingerprint shown is computed here; the server's own claim must agree with it.
        if (signing.str("rootSha256")?.lowercase() != sha) throw ProtocolException("server_error", "服務端回報的指紋與憑證不符")
        return Info(url, root.displaySubject(), sha, root, features)
    }

    fun dismiss() {
        state.value = state.value.copy(pending = null)
    }

    /** Trusts [info]'s root for verifiers and issuers (receipts), replacing an earlier root of the same server. */
    fun confirm(info: Info) {
        state.value = state.value.copy(pending = null)
        model.scope.launch {
            try {
                val src = source(info.url)
                for (old in model.trust.allAnchors()) {
                    if (old.source == src && old.certificate != info.root) model.trust.removeAnchor(old)
                }
                var added = 0
                for (role in ROLES) {
                    if (model.trust.addAnchor(role, TrustEnvironment.USER, info.root, "正式服務端 ${Url(info.url).host}", official = false, source = src)) added++
                }
                model.updateSettings { it.copy(serverRootSha256 = info.sha256) }
                state.value = State()
                model.message.value = if (added == 0) "已經信任這台服務端" else "已信任服務端 ${Url(info.url).host}（使用者匯入，信任等級 T2）"
                model.loadAnchors()
                model.status.reevaluateIssuers("信任正式服務端", affected = { it.anchorName == null }, accept = { it.environment != null })
            } catch (e: Exception) {
                model.message.value = "無法加入信任：" + model.describe(e)
            }
        }
    }

    companion object {
        const val SOURCE_PREFIX = "server:"
        /** Requests the server signs (verifier) and the web-proof receipts it issues (issuer). */
        val ROLES = listOf(TrustRole.VERIFIER, TrustRole.ISSUER)
    }
}

package diw.wallet.app

import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.sign.MobileMoicaEnvironment
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
import kotlin.time.Clock

/**
 * The production server (diw-wallet-server) set in [WalletSettings.zkVerifierUrl], which serves the relay, the
 * zkTLS verifier host and the age host. Its `/info` names the root that signs its zkTLS requests and web-proof
 * receipts; the user compares the root's SHA-256 with what the operator published and then trusts it as their own
 * anchor (T2) for verifiers and issuers. The same confirmation trusts the DID of its web verifier (`verifierDid`,
 * a did:key the national platform does not list) as the user's own verifier DID. The DID is bound to the server
 * only by TLS and the address the user entered. A changed root or DID is never accepted silently.
 */
class ServerModel(private val model: WalletModel) {
    /** What `/info` says about the server's signing root. */
    data class Info(
        val url: String,
        /** The signing root, absent when the server runs no zkTLS host. */
        val subject: String?,
        val sha256: String?,
        val root: X509Cert?,
        val features: List<String>,
        /** The web verifier's DID, absent when the server runs no web verifier. */
        val verifierDid: String?,
    )

    data class State(
        val checking: Boolean = false,
        /** Read from the server and waiting for the user to compare and confirm. */
        val pending: Info? = null,
        /** The root the server names now differs from the one the user trusted. */
        val changed: Boolean = false,
        val error: String? = null,
    )

    val state = MutableStateFlow(State())

    /** The configured server's address without a trailing slash, or null when none is set. */
    fun base(): String? = model.settings.zkVerifierUrl.trim().trimEnd('/').takeIf { it.isNotEmpty() }

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
                val s = model.settings
                val rootChanged = s.serverRootSha256.isNotEmpty() && s.serverRootSha256 != info.sha256
                val didChanged = s.serverVerifierDid.isNotEmpty() && s.serverVerifierDid != info.verifierDid
                State(pending = info.takeIf { confirm }, changed = rootChanged || didChanged)
            } catch (e: Exception) {
                State(error = model.describe(e))
            }
        }
    }

    private suspend fun info(url: String): JsonObject {
        val response = model.http.get("$url/info")
        if (!response.status.isSuccess()) throw ProtocolException("server_error", "HTTP ${response.status.value}")
        return DiwJson.parseToJsonElement(response.bodyAsText()) as? JsonObject ?: throw ProtocolException("server_error", "不是服務端的 /info")
    }

    private fun features(o: JsonObject) = (o["features"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonPrimitive)?.content }

    /**
     * The TW FidO service [url]'s SP account signs with, read fresh from `/info`: the server must list the `twfido`
     * feature and name a known environment. Null when it offers no mobile citizen certificate signing. This is the
     * server's own claim; the certificate that comes back is checked against MOICA as well (FilesModel).
     */
    suspend fun mobileMoica(url: String): MobileMoicaEnvironment? {
        val o = info(url)
        if (FEATURE_TWFIDO !in features(o)) return null
        val name = (o["twfido"] as? JsonObject)?.str("environment")
        return MobileMoicaEnvironment.entries.firstOrNull { it.name == name }
            ?: throw ProtocolException("server_error", "服務端沒有說明它的行動自然人憑證 SP 屬於哪個環境")
    }

    private suspend fun read(url: String): Info {
        val o = info(url)
        val features = features(o)
        val verifierDid = o.str("verifierDid")?.trim()?.takeIf { it.startsWith("did:") }
        val signing = o["signing"] as? JsonObject
        if (signing == null && verifierDid == null) {
            throw ProtocolException("unavailable", "這台服務端沒有簽章金鑰或網頁查驗端（未啟用 zktls 或 verifier），不需要加入信任")
        }
        if (verifierDid != null) {
            // Only a DID this wallet can resolve to a key is offered; the presentation checks its signature with it.
            runCatching { DidResolver(model.http).resolveKey(verifierDid, null) }
                .getOrElse { throw ProtocolException("server_error", "服務端的網頁查驗端 DID 無法解析") }
        }
        val signed = signing?.let { sig ->
            val root = X509Cert.fromPem(sig.str("root") ?: throw ProtocolException("server_error", "No signing root"))
            if (!TrustRegistry.isRoot(root)) throw ProtocolException("server_error", "服務端提供的不是根憑證")
            val sha = PlatformCrypto.sha256(root.encoded.toByteArray()).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
            // The fingerprint shown is computed here; the server's own claim must agree with it.
            if (sig.str("rootSha256")?.lowercase() != sha) throw ProtocolException("server_error", "服務端回報的指紋與憑證不符")
            root to sha
        }
        return Info(url, signed?.first?.displaySubject(), signed?.second, signed?.first, features, verifierDid)
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
                val host = Url(info.url).host
                for (old in model.trust.allAnchors()) {
                    if (old.source == src && old.certificate != info.root) model.trust.removeAnchor(old)
                }
                var added = 0
                info.root?.let { root ->
                    for (role in ROLES) {
                        if (model.trust.addAnchor(role, TrustEnvironment.USER, root, "正式服務端 $host", official = false, source = src)) added++
                    }
                }
                val previousDid = model.settings.serverVerifierDid
                if (previousDid.isNotEmpty() && previousDid != info.verifierDid) model.userDids.remove(previousDid)
                info.verifierDid?.let { did ->
                    if (model.userDids.all().none { it.did == did && TrustRole.VERIFIER.id in it.roles }) added++
                    model.userDids.put(did, "正式服務端 $host 網頁查驗", setOf(TrustRole.VERIFIER), Clock.System.now().toEpochMilliseconds())
                }
                model.updateSettings { it.copy(serverRootSha256 = info.sha256.orEmpty(), serverVerifierDid = info.verifierDid.orEmpty()) }
                state.value = State()
                model.message.value = if (added == 0) "已經信任這台服務端" else "已信任服務端 $host（使用者匯入，信任等級 T2）"
                model.loadAnchors()
                if (info.root != null) {
                    model.status.reevaluateIssuers("信任正式服務端", affected = { it.anchorName == null }, accept = { it.environment != null })
                }
            } catch (e: Exception) {
                model.message.value = "無法加入信任：" + model.describe(e)
            }
        }
    }

    companion object {
        const val SOURCE_PREFIX = "server:"
        const val FEATURE_TWFIDO = "twfido"
        /** Requests the server signs (verifier) and the web-proof receipts it issues (issuer). */
        val ROLES = listOf(TrustRole.VERIFIER, TrustRole.ISSUER)
    }
}

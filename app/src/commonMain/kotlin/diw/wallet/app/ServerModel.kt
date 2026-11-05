package diw.wallet.app

import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.sign.MobileMoicaEnvironment
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.federation.FederationResolver
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.server.ServerShare
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.x509.displaySubject
import diw.wallet.core.zktls.ZkTlsTransport
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlinx.coroutines.Job
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
 *
 * Two more ways vouch for the fingerprint: a share link ([ServerShare]) from someone the user trusts carries it, and
 * a server in an OpenID Federation whose Trust Anchor the user added states it in its `diw_wallet_server` metadata.
 * Either way the root must match exactly, and the user still confirms.
 *
 * Between two wallets only one needs a server: the other party's server, shared for one check ([peer]), is used as a
 * relay without being trusted, and [ServerPolicy] decides which of two servers a check runs through.
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
        /** The address the server sends wallets to (its public_url), absent from older servers. */
        val publicUrl: String? = null,
        /** The Trust Anchor that vouches for [sha256] and [verifierDid], when the server is in a federation the user trusts. */
        val federation: String? = null,
        /** The fingerprint a share link carried, already checked to match [sha256]. */
        val sharedFingerprint: Boolean = false,
        /** The server's settings digest, to compare deployments. */
        val settingsSha256: String? = null,
        /** The server's OpenID Federation Entity Identifier. */
        val entityId: String? = null,
    ) {
        /**
         * A warning when the server sends wallets to another host than the one entered here: sessions, relay links and
         * the web verifier then point at an address that may not be reachable.
         */
        val addressWarning: String?
            get() {
                val announced = publicUrl?.let { runCatching { Url(it).host }.getOrNull() } ?: return null
                val entered = runCatching { Url(url).host }.getOrNull() ?: return null
                if (announced.equals(entered, ignoreCase = true)) return null
                return "服務端設定的對外網址是 $announced，和你填的 $entered 不同。查驗連結、中繼與網頁查驗都會用 $announced；" +
                    "如果它連不到，網站查驗會顯示「無法連到查驗方」。請業者把 public_url 改成 https://$entered，或讓 $announced 可以連線。"
            }
    }

    data class State(
        val checking: Boolean = false,
        /** Read from the server and waiting for the user to compare and confirm. */
        val pending: Info? = null,
        /** The root the server names now differs from the one the user trusted. */
        val changed: Boolean = false,
        val error: String? = null,
        /** [Info.addressWarning] from the last read. */
        val addressWarning: String? = null,
        /** The last read, for sharing the features and federation it names. */
        val last: Info? = null,
    )

    val state = MutableStateFlow(State())

    /** The other party's server for the check on screen; used as a relay or age host only, never trusted or saved. */
    val peer = MutableStateFlow<ServerShare?>(null)

    /** A scanned or pasted share waiting for the user to choose what to do with it. */
    val pendingShare = MutableStateFlow<ServerShare?>(null)

    /** The share being adopted: its fingerprint must match what the server reports. */
    private var expected: ServerShare? = null

    /** The configured server's address without a trailing slash, or null when none is set. */
    fun base(): String? = model.settings.zkVerifierUrl.trim().trimEnd('/').takeIf { it.isNotEmpty() }

    /** The token for [base] when it is the configured server; never sent to the test server or another host. */
    fun tokenFor(base: String): String? = model.settings.serverToken.takeIf { it.isNotEmpty() && base() == base.trimEnd('/') }

    val policy: ServerPolicy get() = ServerPolicy.of(model.settings.serverPolicy)

    private fun source(url: String) = SOURCE_PREFIX + Url(url).host

    private fun hostOf(url: String) = runCatching { Url(url).host }.getOrNull()

    /** Reads the server's signing root. With [confirm] the result waits for the user; otherwise it only notes a change. */
    fun check(confirm: Boolean) {
        val url = base() ?: return
        state.value = state.value.copy(checking = true, error = null)
        model.scope.launch {
            state.value = try {
                val info = read(url, expected?.takeIf { it.url == url })
                expected = null
                val s = model.settings
                val rootChanged = s.serverRootSha256.isNotEmpty() && s.serverRootSha256 != info.sha256
                val didChanged = s.serverVerifierDid.isNotEmpty() && s.serverVerifierDid != info.verifierDid
                State(pending = info.takeIf { confirm }, changed = rootChanged || didChanged, addressWarning = info.addressWarning, last = info)
            } catch (e: Exception) {
                expected = null
                State(error = model.describe(e), last = state.value.last)
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

    private suspend fun read(url: String, shared: ServerShare?): Info {
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
        // A share carries the fingerprint someone else compared: anything else is refused outright.
        if (shared != null) {
            if (shared.rootSha256 != null && shared.rootSha256 != signed?.second) throw ProtocolException("server_error", ServerStrings.shareFingerprintMismatch(Url(url).host))
            if (shared.verifierDid != null && shared.verifierDid != verifierDid) throw ProtocolException("server_error", ServerStrings.shareFingerprintMismatch(Url(url).host))
        }
        val federationObject = o["federation"] as? JsonObject
        val entityId = federationObject?.str("entityId")
        val federation = entityId?.let { federationAnchor(it, signed?.second, verifierDid) }
        return Info(
            url, signed?.first?.displaySubject(), signed?.second, signed?.first, features, verifierDid, o.str("publicUrl")?.trim(),
            federation = federation, sharedFingerprint = shared?.rootSha256 != null || shared?.verifierDid != null,
            settingsSha256 = o.str("settingsSha256"), entityId = entityId,
        )
    }

    /**
     * The Trust Anchor (its name) that vouches for this server: a trust chain from [entityId] to an anchor the user
     * added, whose `diw_wallet_server` metadata names exactly [sha256] and [did]. Null when no anchor is configured or
     * no chain resolves; a chain that names other values is an error, since the federation then contradicts the server.
     */
    private suspend fun federationAnchor(entityId: String, sha256: String?, did: String?): String? {
        val anchors = model.federationAnchors.all().filter { it.trustEnvironment != TrustEnvironment.TEST || model.settings.testEnvironment }
        if (anchors.isEmpty()) return null
        val resolved = runCatching {
            FederationResolver(model.http, { anchors }, model.environmentPolicy.insecureLoopbackAllowed).resolve(entityId, SERVER_TYPE)
        }.getOrNull() ?: return null
        val root = resolved.metadata.str("signing_root_sha256")?.lowercase()
        val verifier = resolved.metadata.str("verifier_did")
        if (root != sha256 || verifier != did) throw ProtocolException("server_error", ServerStrings.federationMismatch(resolved.anchor.name))
        return resolved.anchor.name
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
                state.value = State(addressWarning = info.addressWarning, last = info)
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

    /**
     * This wallet's server as a share: its address and the fingerprint and DID the user trusted, the features and
     * federation of the last read, and the token only with [includeToken]. Null when no server is set.
     */
    fun share(includeToken: Boolean): ServerShare? {
        val url = base() ?: return null
        val s = model.settings
        val last = state.value.last?.takeIf { it.url == url }
        return ServerShare(
            url = url,
            rootSha256 = s.serverRootSha256.takeIf { it.isNotEmpty() },
            verifierDid = s.serverVerifierDid.takeIf { it.isNotEmpty() },
            federation = last?.entityId,
            features = last?.features.orEmpty(),
            token = s.serverToken.takeIf { includeToken && it.isNotEmpty() },
        )
    }

    /**
     * A scanned or pasted share link. While a check is waiting on the verifier screen it is the other party's server
     * for that check; otherwise the user chooses whether to make it this wallet's server.
     */
    fun receive(link: String) {
        val share = try {
            ServerShare.parse(link, allowHttp = model.settings.testEnvironment)
        } catch (e: ProtocolException) {
            model.message.value = e.message
            return
        }
        if (verifierWaiting()) usePeer(share) else pendingShare.value = share
    }

    /** A code scanned from the verifier screen's "use the other party's server": always for this check only. */
    fun scanPeer(link: String) {
        val share = try {
            ServerShare.parse(link, allowHttp = model.settings.testEnvironment)
        } catch (e: ProtocolException) {
            model.message.value = e.message
            return
        }
        usePeer(share)
    }

    /** A verifier screen that can open its request again through another server is showing. */
    private fun verifierWaiting(): Boolean = when (val s = model.taiwan.offline.value) {
        is OfflineUi.ZkTlsVerifierWaiting -> s.local
        is OfflineUi.AgeVerifierWaiting -> s.peerable
        else -> false
    }

    /** Makes [share] this wallet's server, then reads it; trust is offered only when its root matches the shared fingerprint. */
    fun adopt(share: ServerShare): Job {
        pendingShare.value = null
        val sameServer = base() == share.url
        val saved = model.updateSettings {
            it.copy(
                zkVerifierUrl = share.url,
                serverToken = share.token ?: if (sameServer) it.serverToken else "",
                serverRootSha256 = if (sameServer) it.serverRootSha256 else "",
                serverVerifierDid = if (sameServer) it.serverVerifierDid else "",
            )
        }
        model.scope.launch {
            saved.join()
            expected = share
            check(confirm = share.rootSha256 != null || share.verifierDid != null)
        }
        return saved
    }

    /**
     * Uses [share] as the other party's server for the check on screen: the verifier screen starts again with a room
     * on it too, so the holder can reach this device through the server it has.
     */
    fun usePeer(share: ServerShare) {
        pendingShare.value = null
        peer.value = share.withoutToken()
        val waiting = verifierWaiting()
        model.message.value = if (waiting) ServerStrings.peerForSession(share.host) else ServerStrings.peerInUse(share.host)
        when (model.taiwan.offline.value) {
            is OfflineUi.ZkTlsVerifierWaiting -> if (waiting) model.taiwan.zkTls.restartVerifier()
            is OfflineUi.AgeVerifierWaiting -> if (waiting) model.taiwan.ageVerifier.restart()
            else -> Unit
        }
    }

    /**
     * The age host a verifier on this device sends its request through: this wallet's server and the other party's
     * shared one in the order [policy] prefers, else the test server in the test environment. The holder only posts
     * its proof to the address in the request, so one server is enough.
     */
    fun ageHost(own: String? = base()): String? {
        val other = peer.value?.url
        val test = model.settings.takeIf { it.testEnvironment }?.testServerUrl?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }
        val ordered = if (policy == ServerPolicy.PREFER_PEER) listOf(other, own) else listOf(own, other)
        return ordered.firstOrNull { it != null } ?: test
    }

    /** Forgets the other party's server when a check ends. */
    fun clearPeer() {
        peer.value = null
    }

    /**
     * The relays a verifier on this device opens rooms on, in the order [policy] prefers: this wallet's server and the
     * other party's shared one. The peer is only ever set by an explicit scan, so it is included under every policy.
     */
    fun relaysForVerifier(own: String? = base()): List<String> {
        val other = peer.value?.url
        val ordered = if (policy == ServerPolicy.PREFER_PEER) listOf(other, own) else listOf(own, other)
        return ordered.filterNotNull().distinct()
    }

    /**
     * The holder's side of the choice: the verifier lists rooms on one or more relays; local addresses stay first,
     * then the relays in the order [policy] prefers. Under [ServerPolicy.OWN_ONLY] relays on other servers are left
     * out. A verifier host (wss) is the verifier itself, not an intermediary, and stays.
     */
    fun orderForHolder(transports: List<ZkTlsTransport>): List<ZkTlsTransport> {
        val ownHost = base()?.let { hostOf(it) }
        val lan = transports.filterIsInstance<ZkTlsTransport.Lan>()
        val relays = transports.filterIsInstance<ZkTlsTransport.Relay>()
        val (mine, others) = relays.partition { ownHost != null && hostOf(it.url).equals(ownHost, ignoreCase = true) }
        val chosen = when (policy) {
            ServerPolicy.PREFER_OWN -> mine + others
            ServerPolicy.PREFER_PEER -> others + mine
            ServerPolicy.OWN_ONLY -> mine
        }
        return lan + chosen + transports.filterIsInstance<ZkTlsTransport.Wss>()
    }

    /**
     * Why the holder may not reach the verifier and what to do, shown before proving: no relay this wallet would use
     * while it has a server the verifier could join. Null when there is nothing to suggest.
     */
    fun holderRouteHint(transports: List<ZkTlsTransport>): String? {
        val usable = orderForHolder(transports)
        if (usable.any { it !is ZkTlsTransport.Lan }) return null
        val own = base()?.let { hostOf(it) }
        return when {
            policy == ServerPolicy.OWN_ONLY && transports.any { it is ZkTlsTransport.Relay } -> ServerStrings.ownOnlyNoRoute(own)
            else -> ServerStrings.noPeerRelay(own)
        }
    }

    companion object {
        const val SOURCE_PREFIX = "server:"
        const val FEATURE_TWFIDO = "twfido"
        /** The OpenID Federation entity type diw-wallet-server publishes its signing root and verifier DID under. */
        const val SERVER_TYPE = "diw_wallet_server"
        /** Requests the server signs (verifier) and the web-proof receipts it issues (issuer). */
        val ROLES = listOf(TrustRole.VERIFIER, TrustRole.ISSUER)
    }
}

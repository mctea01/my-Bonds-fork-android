package diw.wallet.app

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.trust.BuiltInAnchors
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.x509.displaySubject
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zktls.WebProofCredentials
import diw.wallet.core.zktls.ZkTlsCheck
import diw.wallet.core.zktls.ZkTlsEngine
import diw.wallet.core.zktls.ZkTlsOutcome
import diw.wallet.core.zktls.ZkTlsPlanner
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsProfiles
import diw.wallet.core.zktls.ZkTlsReceipts
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import diw.wallet.core.zktls.ZkTlsVerifierSession
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.X509Cert
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * zkTLS between two wallets (p4-zkp.md section 5.2). As holder the wallet answers a `diw-zktls://` request: the user
 * types the page's inputs, this device queries the official site through the verifier's TLSNotary session and
 * reveals only the status and the requested fields; the inputs and the rest of the page stay here. As verifier it
 * shows a signed request and checks the proof on this device, over the local network or a relay that only forwards
 * ciphertext; a device without the engine lets the verifier host (the test server) check it and shows that host's
 * verdict, labelled as such.
 */
class ZkTlsFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var job: Job? = null
    private var session: ZkTlsVerifierSession? = null
    private val client by lazy { model.http.config { followRedirects = false } }
    private val keeper = ZkTlsKeep(model)

    /** This device's zkTLS engine, or why there is none; replaced in tests. */
    internal var engines: suspend () -> ZkResult<ZkTlsEngine> = { model.zk.tls() }

    /** Whether this device signs receipts as verifier; turned off in tests to reach the holder's own record. */
    internal var receiptsEnabled = true

    /** The verifier host: the age host setting, else the test server in the test environment. */
    fun host(): String? = model.taiwan.ageVerifier.host()

    private fun insecureHosts(): Set<String> = model.taiwan.ageVerifier.insecureHosts()

    /**
     * Server roots TLSNotary accepts besides the public web roots: the GPKI anchors (Taiwan government sites), the
     * issuer roots the user imported, and in the test environment the test anchors and the CA of the test server's
     * record page, read from the server each time since the server makes a new one at every start.
     */
    private suspend fun extraRoots(): List<ByteArray> {
        val test = model.settings.testEnvironment
        val envs = if (test) listOf(TrustEnvironment.USER, TrustEnvironment.TEST) else listOf(TrustEnvironment.USER)
        val stored = envs.flatMap { env -> runCatching { model.trust.anchors(TrustRole.ISSUER, env) }.getOrDefault(emptyList()).map { it.first } }
        val recordPage = model.settings.testServerUrl.trim().trimEnd('/').takeIf { test && it.isNotEmpty() }?.let { base ->
            runCatching {
                val response = client.get("$base/pki/zktls-ca.pem")
                if (response.status.isSuccess()) X509Cert.fromPem(response.bodyAsText()) else null
            }.getOrNull()
        }
        return (BuiltInAnchors.all.map { it.certificate } + stored + listOfNotNull(recordPage)).distinct().map { it.encoded.toByteArray() }
    }

    /** How far the site's certificate chain is trusted beyond the TLS check itself. */
    private suspend fun serverTrust(chain: List<ByteArray>): TrustDecision? = runCatching {
        model.trust.decide(TrustRole.ISSUER, chain.map { X509Cert(ByteString(it)) })
    }.getOrNull()

    // ---------------------------------------------------------------- holder

    /** A scanned request: checks its signature and page, then asks for consent and the inputs. */
    fun start(link: String) {
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("讀取網站查驗請求")
        job = model.scope.launch {
            ui.value = try {
                val verified = ZkTlsSessionRequest.verify(ZkTlsSessionRequest.jwsOf(link), model.didResolver(), insecureHosts = insecureHosts())
                val profile = ZkTlsProfiles.resolve(verified.request, allowInline = model.settings.testEnvironment)
                val unknown = verified.request.fields.filter { profile.field(it) == null }
                if (unknown.isNotEmpty()) throw ProtocolException("invalid_request", "查驗頁沒有欄位 ${unknown.joinToString("、")}")
                val chain = verified.chain
                val (name, trust) = if (chain != null) {
                    chain.first().displaySubject() to model.trust.decide(TrustRole.VERIFIER, chain)
                } else {
                    val did = verified.did!!
                    TaiwanModel.shortDid(did) to model.didTrust.decideOrDefault(did, TrustRole.VERIFIER, "The verifier's DID is in no trust source")
                }
                OfflineUi.ZkTlsConsent(verified, profile, name, trust, inline = ZkTlsProfiles.find(profile.id) == null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                OfflineUi.Failed("無法讀取網站查驗請求：" + model.describe(e))
            }
        }
    }

    /**
     * Queries the page with [inputs] through the verifier and reveals the planned parts. The inputs live only in the
     * request bytes handed to the engine; they are never stored, logged or shown again. With [keep] a passed result
     * is also kept in the documents list (ZkTlsKeep): the verifier's receipt when it gives one, else this wallet's
     * own record.
     */
    fun prove(consent: OfflineUi.ZkTlsConsent, inputs: Map<String, String>, keep: Boolean = false) {
        val request = consent.session.request
        if (!request.isFresh(Clock.System.now())) {
            ui.value = OfflineUi.ZkTlsHolderResult(consent, null, null, EXPIRED, retry = false)
            return
        }
        val bytes = try {
            ZkTlsPlanner.request(consent.profile, inputs)
        } catch (e: ProtocolException) {
            ui.value = consent.copy(error = e.message)
            return
        }
        val id = jobId(request)
        model.zk.clear(id)
        ui.value = OfflineUi.ZkTlsProving(consent, id)
        job?.cancel()
        job = model.scope.launch {
            var pending: ZkTlsKeep.Pending? = null
            val failure = try {
                when (val engine = engines()) {
                    is ZkResult.Failed -> {
                        ui.value = OfflineUi.ZkTlsHolderResult(consent, null, null, engine.reason, retry = false)
                        engine.reason
                    }
                    ZkResult.Cancelled -> return@launch
                    is ZkResult.Ok -> {
                        val roots = extraRoots()
                        pending = if (keep) keeper.prepare() else null
                        val binding = pending?.jwk
                        val result = model.zk.prove(id, ZkProofKind.TLS) { step ->
                            engine.value.prove(consent.session, consent.profile, bytes, roots, binding, step)
                        }.await()
                        when (result) {
                            is ZkResult.Ok -> {
                                val proved = result.value
                                val trust = serverTrust(proved.certChainDer)
                                var shown = OfflineUi.ZkTlsHolderResult(consent, proved, trust, null, retry = false)
                                val p = pending
                                if (p != null && proved.outcome.passed) {
                                    pending = null
                                    shown = try {
                                        shown.copy(kept = keeper.keep(p, consent.session, proved, consent.verifier, consent.trust))
                                    } catch (e: CancellationException) {
                                        throw e
                                    } catch (e: Exception) {
                                        shown.copy(keepError = "無法保存查詢結果：" + model.describe(e))
                                    }
                                }
                                ui.value = shown
                                if (proved.outcome.passed) null else proved.outcome.problems.firstOrNull() ?: "查驗頁沒有找到資料"
                            }
                            is ZkResult.Failed -> {
                                val fresh = request.isFresh(Clock.System.now())
                                ui.value = OfflineUi.ZkTlsHolderResult(consent, null, null, result.reason, retry = result.retryable && fresh)
                                result.reason
                            }
                            ZkResult.Cancelled -> {
                                ui.value = consent
                                return@launch
                            }
                        }
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val reason = model.describe(e)
                ui.value = OfflineUi.ZkTlsHolderResult(consent, null, null, reason, retry = request.isFresh(Clock.System.now()))
                reason
            } finally {
                // Nothing to keep: a failed or cancelled proof leaves no pending document behind.
                pending?.let { p -> withContext(NonCancellable) { keeper.discard(p) } }
            }
            model.record(
                HistoryKind.PRESENTED, consent.verifier, consent.trust, listOf(consent.profile.title),
                request.fields.mapNotNull { consent.profile.field(it)?.label },
                "網站查驗證明（zkTLS，${consent.profile.host}），用途：${request.purpose.ifEmpty { "未說明" }}", failure,
            )
        }
    }

    /** Stops the running proof and returns to the consent screen. */
    fun cancel(state: OfflineUi.ZkTlsProving) {
        stop()
        ui.value = state.consent
    }

    private fun jobId(request: ZkTlsSessionRequest) = "zktls-" + request.sessionId

    // ---------------------------------------------------------------- verifier

    /** The pages this device can ask for: the installed template pack, and in the test environment the test server's. */
    fun openSetup() {
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("讀取可查驗的網站")
        job = model.scope.launch {
            val installed = ZkTlsProfiles.installed
            val test = model.settings.testEnvironment
            var note: String? = null
            // Pages imported for testing come first among the test pages; the test server's follow.
            val imported = if (test) model.zkTemplates.state.value.testPages else emptyList()
            val served = if (!test) emptyList() else host()?.let { base ->
                try {
                    hostPages(base)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    note = "無法從 ${Url(base).host} 取得測試查驗頁：" + model.describe(e)
                    emptyList()
                }
            }.orEmpty()
            val offered = imported + served.filter { p -> imported.none { it.id == p.id } }
            val pages = installed + offered.filter { p -> installed.none { it.id == p.id } }
            if (pages.isEmpty()) {
                val why = if (model.zkTemplates.state.value.version == null) "尚未安裝查驗頁版型，請到設定的「零知識證明」頁更新或匯入版型。" else "已安裝的版型沒有查驗頁。"
                note = listOfNotNull(note, why, if (test) null else "測試用的查驗頁只在測試環境提供。").joinToString("\n")
            }
            ui.value = OfflineUi.ZkTlsVerifierSetup(pages, offered.map { it.id }.toSet() - installed.map { it.id }.toSet(), note)
        }
    }

    private suspend fun hostPages(base: String): List<ZkTlsProfile> {
        val response = client.get("$base/zktls/profiles") { accept(ContentType.Application.Json) }
        if (!response.status.isSuccess()) throw ProtocolException("server_error", "HTTP ${response.status.value}")
        val list = (DiwJson.parseToJsonElement(response.bodyAsText()) as? JsonObject)?.get("profiles") as? JsonArray
            ?: throw ProtocolException("server_error", "No pages")
        return list.mapNotNull { (it as? JsonObject)?.let { o -> runCatching { ZkTlsProfile.parse(o) }.getOrNull() } }
    }

    /**
     * Shows a request for [fields] of [profile]. With the engine on this device the proof is checked here, the holder
     * reaching this device over the local network or through the host's relay; without it the host checks it.
     */
    fun startVerifier(profile: ZkTlsProfile, fields: List<String>, purpose: String) {
        stop()
        ui.value = OfflineUi.Working("建立網站查驗請求")
        job = model.scope.launch {
            try {
                model.platform.keepScreenOn(true)
                when (val local = engines()) {
                    is ZkResult.Ok -> verifyHere(local.value, profile, fields, purpose)
                    is ZkResult.Failed -> verifyOnHost(profile, fields, purpose, "這台裝置無法驗證（${local.reason}），改由查驗主機驗證。")
                    ZkResult.Cancelled -> Unit
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed("無法建立網站查驗：" + model.describe(e))
            } finally {
                session?.close()
                session = null
                model.platform.keepScreenOn(false)
            }
        }
    }

    private suspend fun verifyHere(engine: ZkTlsEngine, profile: ZkTlsProfile, fields: List<String>, purpose: String) {
        val relay = host()
        val opened = engine.open(lan = model.platform.bondsLan != null, relayUrl = relay)
        session = opened
        val request = ZkTlsSessionRequest.create(opened.transports, opened.publicKey, profile, fields, purpose,
            inlineProfile = ZkTlsProfiles.find(profile.id) == null)
        val key = verifierKey()
        val jws = try {
            withContext(model.unlockProvider) { ZkTlsSessionRequest.sign(request, key.signingKey("ES256"), did = key.did) }
        } finally {
            model.endOperation()
        }
        val where = opened.transports.joinToString("、") { routeName(it) }
        val details = transportDetails(request) + listOf("查驗方 DID：${key.did}", "請求 id：${request.sessionId}")
        ui.value = OfflineUi.ZkTlsVerifierWaiting(request, ZkTlsSessionRequest.link(jws), profile, where, local = true, details = details)
        // A holder that keeps the result gets a receipt signed with the key that signed the request.
        val signer = WebProofCredentials.receipts(request, profile, key.did!!, key.signingKey("ES256"))
        var issued = false
        val receipts = ZkTlsReceipts { seen, jwk ->
            try {
                withContext(model.unlockProvider) { signer.issue(seen, jwk) }?.also { issued = true }
            } finally {
                model.endOperation()
            }
        }
        val result = opened.verify(jws, request, profile, extraRoots(), receipts.takeIf { receiptsEnabled }) { step ->
            (ui.value as? OfflineUi.ZkTlsVerifierWaiting)?.takeIf { it.request == request }?.let { ui.value = it.copy(step = step) }
        }
        val shown = when (result) {
            is ZkResult.Ok -> {
                val seen = result.value
                OfflineUi.ZkTlsVerifierResult(profile, request, ZkTlsCheck.check(request, profile, seen), serverTrust(seen.certChainDer),
                    local = true, where = where, error = null, receipt = issued)
            }
            is ZkResult.Failed -> OfflineUi.ZkTlsVerifierResult(profile, request, null, null, local = true, where = where, error = result.reason)
            ZkResult.Cancelled -> return
        }
        ui.value = shown
        record(shown)
    }

    private suspend fun verifyOnHost(profile: ZkTlsProfile, fields: List<String>, purpose: String, note: String) {
        val base = host() ?: throw ProtocolException("unavailable", "$note 但尚未設定查驗主機（設定的「零知識證明」頁，測試環境會使用測試伺服器）。")
        val body = buildJsonObject {
            put("profile", profile.id)
            putJsonArray("fields") { fields.forEach { add(it) } }
            put("purpose", purpose)
        }
        val response = client.post("$base/zktls/sessions") {
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            setBody(body.toString())
        }
        val created = DiwJson.parseToJsonElement(response.bodyAsText()) as? JsonObject
            ?: throw ProtocolException("server_error", "HTTP ${response.status.value}")
        if (!response.status.isSuccess()) throw ProtocolException("server_error", created.str("error_description") ?: "HTTP ${response.status.value}")
        val link = created.str("request") ?: throw ProtocolException("server_error", "No request")
        val sid = created.str("sessionId") ?: throw ProtocolException("server_error", "No session")
        val token = created.str("token") ?: throw ProtocolException("server_error", "No token")
        val request = ZkTlsSessionRequest.read(ZkTlsSessionRequest.verify(ZkTlsSessionRequest.jwsOf(link), model.didResolver(),
            insecureHosts = insecureHosts()).request.payload(), insecureHosts())
        val where = Url(base).host
        ui.value = OfflineUi.ZkTlsVerifierWaiting(request, link, profile, where, local = false, note = note,
            details = transportDetails(request) + listOf("查驗主機：$base", "請求 id：$sid"))
        var verdict: JsonObject? = null
        while (Clock.System.now() < request.expiresAt + GRACE) {
            delay(POLL)
            val state = runCatching {
                DiwJson.parseToJsonElement(client.get("$base/zktls/sessions/$sid?token=${token.encodeURLParameter()}").bodyAsText()) as? JsonObject
            }.getOrNull() ?: continue
            when (state.str("status")) {
                "verifying" -> (ui.value as? OfflineUi.ZkTlsVerifierWaiting)?.takeIf { it.request == request && it.step == null }
                    ?.let { ui.value = it.copy(step = "出示者已連線，查驗主機正在查驗") }
                "done", "failed" -> {
                    verdict = state
                    break
                }
            }
        }
        val v = verdict
        val shown = when {
            v == null -> OfflineUi.ZkTlsVerifierResult(profile, request, null, null, local = false, where = where, error = EXPIRED_VERIFIER)
            v.str("status") == "done" -> OfflineUi.ZkTlsVerifierResult(profile, request,
                (v["outcome"] as? JsonObject)?.let { ZkTlsOutcome.fromJson(it, profile) }, null, local = false, where = where, error = null,
                receipt = (v["receipt"] as? kotlinx.serialization.json.JsonPrimitive)?.content == "true")
            else -> OfflineUi.ZkTlsVerifierResult(profile, request, null, null, local = false, where = where, error = v.str("reason") ?: "查驗失敗")
        }
        ui.value = shown
        record(shown)
    }

    /** The key that signs this device's requests: a did:key of its own, used without unlocking. */
    private suspend fun verifierKey(): HolderKey {
        val backend = model.backends.first()
        return model.holderIdentities.getOrCreate(VERIFIER_PROFILE, "did:key", backend.secureArea,
            backend.settings(ByteString(PlatformCrypto.randomBytes(16)), false))
    }

    private fun routeName(t: ZkTlsTransport): String = when (t) {
        is ZkTlsTransport.Lan -> "區網"
        is ZkTlsTransport.Relay -> "中繼 " + runCatching { Url(t.url).host }.getOrDefault(t.url)
        is ZkTlsTransport.Wss -> "查驗主機 " + runCatching { Url(t.url).host }.getOrDefault(t.url)
    }

    private fun transportDetails(request: ZkTlsSessionRequest): List<String> = request.transports.map { t ->
        when (t) {
            is ZkTlsTransport.Lan -> "區網監聽：${t.host}:${t.port}（TCP）"
            is ZkTlsTransport.Relay -> "中繼：${t.url}（房間 ${t.room.take(6)}…）"
            is ZkTlsTransport.Wss -> "查驗主機連線：${t.url}"
        }
    } + "通道：Noise（綁定這個請求的簽章，傳輸路線只看到密文）"

    private fun record(r: OfflineUi.ZkTlsVerifierResult) {
        val failure = when {
            r.error != null -> r.error
            r.outcome == null -> "查驗主機沒有回傳結果"
            !r.outcome.passed -> r.outcome.problems.firstOrNull() ?: "查驗頁沒有找到資料"
            else -> null
        }
        model.record(
            HistoryKind.VERIFIED, "網站查驗出示者", null, listOf(r.profile.title),
            r.request.fields.mapNotNull { r.profile.field(it)?.label },
            "網站查驗證明（zkTLS，${r.profile.host}，${if (r.local) "在這台裝置驗證" else "由 ${r.where} 驗證"}），用途：${r.request.purpose.ifEmpty { "未說明" }}",
            failure,
        )
    }

    /** Stops whatever runs, when the screen is left. */
    fun stop() {
        (ui.value as? OfflineUi.ZkTlsProving)?.let { model.zk.cancel(it.jobId) }
        job?.cancel()
        job = null
        session?.close()
        session = null
    }

    companion object {
        const val VERIFIER_PROFILE = "zktls-verifier"
        const val EXPIRED = "這個請求已過期（10 分鐘內有效），請對方重新產生 QR Code。"
        const val EXPIRED_VERIFIER = "請求已過期，沒有收到出示。"
        private val POLL = 2.seconds
        private val GRACE = 30.seconds
    }
}

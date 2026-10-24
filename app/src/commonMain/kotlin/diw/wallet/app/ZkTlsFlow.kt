package diw.wallet.app

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.profile.bonds.networks
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
import diw.wallet.core.zktls.ZkTlsDirect
import diw.wallet.core.zktls.ZkTlsDirectRead
import diw.wallet.core.zktls.ZkTlsPlanner
import diw.wallet.core.zktls.ZkTlsPrepare
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
import diw.wallet.core.document.DocumentFormat
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
    private var prepareJob: Job? = null
    private var documentJob: Job? = null

    /** A value a stored file prints for an input of the page on screen (a transcript's check number). */
    data class DocumentValue(val fileId: String, val fileName: String, val input: String, val value: String)

    /** Values the holder's stored files offer for the page on screen; kept in memory while the query is open. */
    val documentValues = MutableStateFlow<List<DocumentValue>>(emptyList())

    /**
     * Reads the values [profile]'s inputs can take from the holder's files ([ZkTlsProfile.Input.document]): the file
     * [fileId] the query was started from first, then the others. Nothing is read when no input names a rule.
     */
    private fun findDocumentValues(profile: ZkTlsProfile, fileId: String?) {
        documentJob?.cancel()
        documentValues.value = emptyList()
        val inputs = profile.request.inputs.filter { it.document != null }
        if (inputs.isEmpty()) return
        documentJob = model.scope.launch {
            val files = model.files.files.value.filter { it.report?.format in DOCUMENT_FORMATS }.sortedByDescending { it.id == fileId }
            for (f in files) {
                val text = runCatching { model.files.documentText(f) }.getOrNull() ?: continue
                val found = inputs.mapNotNull { i -> i.fromDocument(text)?.let { DocumentValue(f.id, f.name, i.name, it) } }
                    .filter { v -> documentValues.value.none { it.input == v.input && it.value == v.value } }
                if (found.isNotEmpty()) documentValues.value = documentValues.value + found
            }
        }
    }
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
                consentFor(link, null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                OfflineUi.Failed("無法讀取網站查驗請求：" + model.describe(e))
            }
            (ui.value as? OfflineUi.ZkTlsConsent)?.let { if (ZkTlsPrepare.needed(it.profile)) refreshCaptcha(it) }
        }
    }

    /** Checks a request link's signature and page, and who signed it, for the consent screen. */
    private suspend fun consentFor(link: String, forFile: String?): OfflineUi.ZkTlsConsent {
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
        findDocumentValues(profile, forFile)
        return OfflineUi.ZkTlsConsent(verified, profile, name, trust, inline = ZkTlsProfiles.find(profile.id) == null, forFile = forFile)
    }

    /**
     * Fetches a new picture code for [consent]: in the same site session when it has one (the site may expect the
     * session that served the form), else in a new one. Each query uses up its picture, so this also runs on retry.
     */
    fun refreshCaptcha(consent: OfflineUi.ZkTlsConsent) {
        if (!ZkTlsPrepare.needed(consent.profile)) return
        prepareJob?.cancel()
        ui.value = consent.copy(preparing = true, error = null)
        prepareJob = model.scope.launch {
            val next = try {
                consent.copy(captcha = ZkTlsPrepare.start(model.http, consent.profile, consent.captcha), preparing = false, error = null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                consent.copy(captcha = null, preparing = false, error = "無法取得驗證碼：" + model.describe(e))
            }
            val now = ui.value
            if (now is OfflineUi.ZkTlsConsent && now.session.jws == consent.session.jws) ui.value = next
        }
    }

    /** Back to [consent] after a failed or cancelled query, with a new picture code where the page uses one. */
    fun retry(consent: OfflineUi.ZkTlsConsent) {
        ui.value = consent.copy(error = null)
        refreshCaptcha(consent)
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
        if (ZkTlsPrepare.needed(consent.profile) && consent.captcha == null) {
            ui.value = consent.copy(error = "請先取得驗證碼")
            return
        }
        val bytes = try {
            ZkTlsPlanner.request(consent.profile, inputs, consent.captcha?.cookies.orEmpty(), consent.captcha?.values.orEmpty())
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
                                        val kept = keeper.keep(p, consent.session, proved, consent.verifier, consent.trust)
                                        consent.forFile?.let { model.files.attachWebProof(it, kept.documentId) }
                                        shown.copy(kept = kept)
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
                                retry(consent)
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
        val found = documentValues.value
        stop()
        documentValues.value = found
        retry(state.consent)
    }

    private fun jobId(request: ZkTlsSessionRequest) = "zktls-" + request.sessionId

    // ---------------------------------------------------------------- verifier

    /** The pages this device can ask for: the installed template pack, and in the test environment the test server's. */
    fun openSetup() {
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("讀取可查驗的網站")
        job = model.scope.launch {
            val (pages, testPages, note) = availablePages()
            ui.value = OfflineUi.ZkTlsVerifierSetup(pages, testPages, note)
        }
    }

    /**
     * The pages this device can query or ask for: the installed template pack, and in the test environment imported
     * test pages and the test server's. Returns them, the ids of the test pages, and a note when something is missing.
     */
    private suspend fun availablePages(): Triple<List<ZkTlsProfile>, Set<String>, String?> {
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
        return Triple(pages, offered.map { it.id }.toSet() - installed.map { it.id }.toSet(), note)
    }

    // ---------------------------------------------------------------- holder-initiated

    /** The holder's own web query, as evidence of the file [fileId] when given: first which page and how. */
    fun openSelf(fileId: String?) {
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("讀取可查詢的網站")
        job = model.scope.launch {
            val (pages, testPages, note) = availablePages()
            ui.value = OfflineUi.ZkTlsSelfPick(fileId, pages, testPages, host(), note)
        }
    }

    /**
     * A zkTLS proof of [profile] through the verifier host: the host opens a session for every field, and this device
     * proves to it as to any verifier. The host's receipt is kept (a web-proof) and linked to the file.
     */
    fun selfThroughHost(pick: OfflineUi.ZkTlsSelfPick, profile: ZkTlsProfile) {
        stop()
        ui.value = OfflineUi.Working("向查驗主機建立網站查驗")
        job = model.scope.launch {
            ui.value = try {
                val base = host() ?: throw ProtocolException("unavailable", "尚未設定查驗主機（設定的「零知識證明」頁）")
                val body = buildJsonObject {
                    put("profile", profile.id)
                    putJsonArray("fields") { profile.fields.forEach { add(it.name) } }
                    put("purpose", SELF_PURPOSE)
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
                consentFor(link, pick.fileId)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                OfflineUi.Failed("無法透過查驗主機查詢：" + model.describe(e))
            }
            (ui.value as? OfflineUi.ZkTlsConsent)?.let { if (ZkTlsPrepare.needed(it.profile)) refreshCaptcha(it) }
        }
    }

    /** [profile] queried by this device alone; the result can only be kept as a device record. */
    fun selfDirect(pick: OfflineUi.ZkTlsSelfPick, profile: ZkTlsProfile) {
        stop()
        val state = OfflineUi.ZkTlsSelf(profile, pick.fileId)
        ui.value = state
        findDocumentValues(profile, pick.fileId)
        refreshSelfCaptcha(state)
    }

    /** A new picture code for a query on this device, in the same site session when there is one. */
    fun refreshSelfCaptcha(state: OfflineUi.ZkTlsSelf) {
        if (!ZkTlsPrepare.needed(state.profile)) return
        prepareJob?.cancel()
        ui.value = state.copy(preparing = true, error = null)
        prepareJob = model.scope.launch {
            val next = try {
                state.copy(captcha = ZkTlsPrepare.start(model.http, state.profile, state.captcha), preparing = false, error = null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                state.copy(captcha = null, preparing = false, error = "無法取得驗證碼：" + model.describe(e))
            }
            val now = ui.value
            if (now is OfflineUi.ZkTlsSelf && now.profile.id == state.profile.id) ui.value = next
        }
    }

    /**
     * Queries the page of [state] with [inputs] over this device's own TLS connection and reads it with the profile's
     * rules. A found record is kept as this wallet's statement (a web-record, not a zero-knowledge proof) and linked
     * to the file. The inputs live only in the request bytes.
     */
    fun queryDirect(state: OfflineUi.ZkTlsSelf, inputs: Map<String, String>) {
        if (ZkTlsPrepare.needed(state.profile) && state.captcha == null) {
            ui.value = state.copy(error = "請先取得驗證碼")
            return
        }
        val bytes = try {
            ZkTlsPlanner.request(state.profile, inputs, state.captcha?.cookies.orEmpty(), state.captcha?.values.orEmpty())
        } catch (e: ProtocolException) {
            ui.value = state.copy(error = e.message)
            return
        }
        job?.cancel()
        ui.value = state.copy(working = true, error = null)
        job = model.scope.launch {
            var pending: ZkTlsKeep.Pending? = null
            val result = try {
                val fetched = ZkTlsDirect.fetch(state.profile, bytes, extraRoots())
                val outcome = ZkTlsDirectRead.outcome(state.profile, bytes, fetched, SELF_PURPOSE)
                val trust = serverTrust(fetched.certChainDer)
                if (!outcome.passed) {
                    OfflineUi.ZkTlsSelfResult(state, outcome, trust, fetched, null, null)
                } else {
                    val p = keeper.prepare().also { pending = it }
                    val kept = keeper.record(p, outcome, fetched.time, fetched.certChainDer, fetched.cipherSuite)
                    pending = null
                    state.fileId?.let { model.files.attachWebProof(it, kept.documentId) }
                    OfflineUi.ZkTlsSelfResult(state, outcome, trust, fetched, kept, null)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                OfflineUi.ZkTlsSelfResult(state, null, null, null, null, model.describe(e))
            } finally {
                pending?.let { p -> withContext(NonCancellable) { keeper.discard(p) } }
            }
            ui.value = result
        }
    }

    /** The file the holder query on screen was started from, which leaving it returns to. */
    val queryFile: String?
        get() = when (val s = ui.value) {
            is OfflineUi.ZkTlsSelfPick -> s.fileId
            is OfflineUi.ZkTlsSelf -> s.fileId
            is OfflineUi.ZkTlsSelfResult -> s.state.fileId
            is OfflineUi.ZkTlsConsent -> s.forFile
            is OfflineUi.ZkTlsProving -> s.consent.forFile
            is OfflineUi.ZkTlsHolderResult -> s.consent.forFile
            else -> null
        }

    /** Leaves a holder query: back to the file [fileId] it was started from, else as the back key does. */
    fun leave(fileId: String?) {
        if (fileId == null) {
            model.back()
            return
        }
        model.taiwan.closeOffline()
        model.screen.value = Screen.FileDetail(fileId)
    }

    /** Back to the query of [result] with a new picture code where the page uses one. */
    fun retrySelf(result: OfflineUi.ZkTlsSelfResult) {
        val state = result.state.copy(working = false, error = null)
        ui.value = state
        refreshSelfCaptcha(state)
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
        val opened = try {
            engine.open(lan = model.platform.bondsLan != null, relayUrl = relay)
        } catch (e: ProtocolException) {
            if (e.code != "unavailable") throw e
            throw IllegalStateException(noRoute(relay))
        }
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
    /**
     * Why no holder could reach this verifier, and what to change: a phone on mobile data alone has no address another
     * phone can reach (the carrier's addresses are left out on purpose), so it needs a shared Wi-Fi or hotspot, or a
     * verifier host whose relay both phones reach.
     */
    private fun noRoute(relay: String?): String {
        val lan = model.platform.bondsLan?.localInterfaces().orEmpty()
        val network = if (lan.isEmpty()) "這支手機沒有連上 Wi-Fi 或開啟熱點（只用行動數據時，對方的手機連不到這支手機）" else "無法在 ${lan.networks()} 上開啟連線"
        val host = if (relay == null) "也沒有設定查驗主機，所以沒有中繼可用" else "也連不到查驗主機 $relay 的中繼（/zktls/relay）"
        return "$network，$host。請讓兩支手機連同一個 Wi-Fi，或由其中一支開熱點讓另一支連上；" +
            "兩支手機不在同一個網路時，請在設定「零知識證明」頁填入有提供中繼的查驗主機。"
    }

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
        prepareJob?.cancel()
        prepareJob = null
        documentJob?.cancel()
        documentJob = null
        documentValues.value = emptyList()
        session?.close()
        session = null
    }

    companion object {
        /** The purpose of a query the holder starts to keep the result. */
        const val SELF_PURPOSE = "保存網站查驗結果"
        private val DOCUMENT_FORMATS = setOf(DocumentFormat.PDF, DocumentFormat.TEXT, DocumentFormat.XML)

        const val VERIFIER_PROFILE = "zktls-verifier"
        const val EXPIRED = "這個請求已過期（10 分鐘內有效），請對方重新產生 QR Code。"
        const val EXPIRED_VERIFIER = "請求已過期，沒有收到出示。"
        private val POLL = 2.seconds
        private val GRACE = 30.seconds
    }
}

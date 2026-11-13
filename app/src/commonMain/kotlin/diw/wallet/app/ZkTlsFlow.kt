package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
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
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
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

    /** The last request this device showed as verifier, to open again with the other party's server. */
    private var lastVerifier: Triple<ZkTlsProfile, List<String>, String>? = null
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
        ui.value = OfflineUi.Working(tr(Res.string.zktls_reading_request))
        job = model.scope.launch {
            ui.value = try {
                consentFor(link, null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                OfflineUi.Failed(tr(Res.string.zktls_request_unreadable) + model.describe(e))
            }
            (ui.value as? OfflineUi.ZkTlsConsent)?.let { if (ZkTlsPrepare.needed(it.profile)) refreshCaptcha(it) }
        }
    }

    /** Checks a request link's signature and page, and who signed it, for the consent screen. */
    private suspend fun consentFor(link: String, forFile: String?): OfflineUi.ZkTlsConsent {
        val verified = ZkTlsSessionRequest.verify(ZkTlsSessionRequest.jwsOf(link), model.didResolver(), insecureHosts = insecureHosts())
        val profile = ZkTlsProfiles.resolve(verified.request, allowInline = model.settings.testEnvironment)
        val unknown = verified.request.fields.filter { profile.field(it) == null }
        if (unknown.isNotEmpty()) throw ProtocolException("invalid_request", tr(Res.string.zktls_unknown_fields, unknown.joinToString(tr(Res.string.sep_list))))
        val chain = verified.chain
        val (name, trust) = if (chain != null) {
            chain.first().displaySubject() to model.trust.decide(TrustRole.VERIFIER, chain)
        } else {
            val did = verified.did!!
            TaiwanModel.shortDid(did) to model.didTrust.decideOrDefault(did, TrustRole.VERIFIER, "The verifier's DID is in no trust source")
        }
        findDocumentValues(profile, forFile)
        return OfflineUi.ZkTlsConsent(verified, profile, name, trust, inline = ZkTlsProfiles.find(profile.id) == null, forFile = forFile,
            routeHint = model.server.holderRouteHint(verified.request.transports))
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
                consent.copy(captcha = null, preparing = false, error = tr(Res.string.zktls_captcha_failed) + model.describe(e))
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
            ui.value = consent.copy(error = tr(Res.string.zktls_captcha_first))
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
                        // The routes in the order this wallet's server policy prefers; the signed request is unchanged.
                        val routed = ZkTlsSessionRequest.Verified(
                            request.copy(transports = model.server.orderForHolder(request.transports)),
                            consent.session.jws, consent.session.chain, consent.session.did,
                        )
                        val result = model.zk.prove(id, ZkProofKind.TLS) { step ->
                            engine.value.prove(routed, consent.profile, bytes, roots, binding, step)
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
                                        shown.copy(keepError = tr(Res.string.zktls_keep_failed) + model.describe(e))
                                    }
                                }
                                ui.value = shown
                                if (proved.outcome.passed) null else proved.outcome.problems.firstOrNull() ?: tr(Res.string.zktls_page_no_data)
                            }
                            is ZkResult.Failed -> {
                                val fresh = request.isFresh(Clock.System.now())
                                val reason = hostReason(consent)?.let { tr(Res.string.zktls_host_reported, it) } ?: result.reason
                                ui.value = OfflineUi.ZkTlsHolderResult(consent, null, null, reason, retry = result.retryable && fresh)
                                reason
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
                tr(Res.string.zktls_history_presented, consent.profile.host, request.purpose.ifEmpty { tr(Res.string.age_unstated) }), failure,
            )
        }
    }

    /**
     * The verifier host's own reason for a failed proof, when this device opened the session there: the host ends
     * the connection without saying why, so its status is read for a few seconds while it records the failure.
     */
    private suspend fun hostReason(consent: OfflineUi.ZkTlsConsent): String? {
        val url = consent.hostState ?: return null
        repeat(HOST_REASON_TRIES) { attempt ->
            val state = runCatching { DiwJson.parseToJsonElement(client.get(url).bodyAsText()) as? JsonObject }.getOrNull()
            when (state?.str("status")) {
                "failed" -> return state.str("reason")
                "done", null -> return null
            }
            if (attempt < HOST_REASON_TRIES - 1) delay(POLL)
        }
        return null
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
        ui.value = OfflineUi.Working(tr(Res.string.zktls_reading_pages))
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
                note = tr(Res.string.zktls_test_pages_failed, Url(base).host) + model.describe(e)
                emptyList()
            }
        }.orEmpty()
        val offered = imported + served.filter { p -> imported.none { it.id == p.id } }
        val pages = installed + offered.filter { p -> installed.none { it.id == p.id } }
        if (pages.isEmpty()) {
            val why = if (model.zkTemplates.state.value.version == null) tr(Res.string.zktls_no_templates) else tr(Res.string.zktls_templates_no_pages)
            note = listOfNotNull(note, why, if (test) null else tr(Res.string.zktls_test_pages_only)).joinToString("\n")
        }
        return Triple(pages, offered.map { it.id }.toSet() - installed.map { it.id }.toSet(), note)
    }

    // ---------------------------------------------------------------- holder-initiated

    /** The holder's own web query, as evidence of the file [fileId] when given: first which page and how. */
    fun openSelf(fileId: String?) {
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working(tr(Res.string.zktls_reading_query_pages))
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
        ui.value = OfflineUi.Working(tr(Res.string.zktls_creating_on_host))
        job = model.scope.launch {
            ui.value = try {
                val base = host() ?: throw ProtocolException("unavailable", tr(Res.string.zktls_host_unset))
                val body = buildJsonObject {
                    put("profile", profile.id)
                    putJsonArray("fields") { profile.fields.forEach { add(it.name) } }
                    put("purpose", SELF_PURPOSE)
                }
                val created = createOnHost(base, body)
                val link = created.str("request") ?: throw ProtocolException("server_error", "No request")
                val state = created.str("sessionId")?.let { sid -> created.str("token")?.let { "$base/zktls/sessions/$sid?token=${it.encodeURLParameter()}" } }
                consentFor(link, pick.fileId).copy(hostState = state)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                OfflineUi.Failed(tr(Res.string.zktls_host_query_failed) + model.describe(e))
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
                state.copy(captcha = null, preparing = false, error = tr(Res.string.zktls_captcha_failed) + model.describe(e))
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
            ui.value = state.copy(error = tr(Res.string.zktls_captcha_first))
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
        lastVerifier = Triple(profile, fields, purpose)
        ui.value = OfflineUi.Working(tr(Res.string.zktls_creating_request))
        job = model.scope.launch {
            try {
                model.platform.keepScreenOn(true)
                when (val local = engines()) {
                    is ZkResult.Ok -> verifyHere(local.value, profile, fields, purpose)
                    is ZkResult.Failed -> verifyOnHost(profile, fields, purpose, tr(Res.string.zktls_local_fallback, local.reason))
                    ZkResult.Cancelled -> Unit
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed(tr(Res.string.zktls_create_failed) + model.describe(e))
            } finally {
                // A request opened again (the other party's server) has its own session by now: leave that one alone.
                if (job == null || job === currentCoroutineContext()[Job]) {
                    session?.close()
                    session = null
                    model.platform.keepScreenOn(false)
                }
            }
        }
    }

    /**
     * Opens the same request again, after the other party's server was scanned ([ServerModel.usePeer]): the new QR
     * lists a room on that server's relay as well.
     */
    fun restartVerifier() {
        val (profile, fields, purpose) = lastVerifier ?: return
        startVerifier(profile, fields, purpose)
    }

    private suspend fun verifyHere(engine: ZkTlsEngine, profile: ZkTlsProfile, fields: List<String>, purpose: String) {
        val relays = model.server.relaysForVerifier(host())
        val relay = relays.firstOrNull()
        val opened = try {
            engine.open(lan = model.platform.bondsLan != null, relayUrls = relays)
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
        // The relay is optional when a local address opened; say so, since a holder elsewhere then cannot reach this side.
        val relayMissing = relay != null && opened.transports.none { it is ZkTlsTransport.Relay }
        val peerMissing = model.server.peer.value?.let { p -> opened.transports.none { it is ZkTlsTransport.Relay && hostOf(it.url) == p.host } } == true
        val where = opened.transports.joinToString(tr(Res.string.sep_list)) { routeName(it) } + if (relayMissing) tr(Res.string.zktls_relay_down_note, hostOf(relay!!)) else ""
        val details = transportDetails(request) + listOfNotNull(
            tr(Res.string.zktls_relay_down_detail, relay).takeIf { relayMissing },
            tr(Res.string.zktls_peer_relay_down, model.server.peer.value?.host).takeIf { peerMissing && !relayMissing },
            tr(Res.string.zktls_verifier_did, key.did), tr(Res.string.zktls_request_id, request.sessionId),
        )
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

    /**
     * Opens a session on the verifier host. The production server's access token goes only to that server; a host
     * that wants one and has none set gets a pointer to the setting.
     */
    private suspend fun createOnHost(base: String, body: JsonObject): JsonObject {
        val token = model.server.tokenFor(base)
        val response = client.post("$base/zktls/sessions") {
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            token?.let { header(HttpHeaders.Authorization, "Bearer $it") }
            setBody(body.toString())
        }
        if (response.status == HttpStatusCode.Unauthorized) {
            throw ProtocolException("unauthorized", if (token == null) tr(Res.string.zktls_token_needed) else tr(Res.string.zktls_token_rejected))
        }
        val created = DiwJson.parseToJsonElement(response.bodyAsText()) as? JsonObject
            ?: throw ProtocolException("server_error", "HTTP ${response.status.value}")
        if (!response.status.isSuccess()) throw ProtocolException("server_error", created.str("error_description") ?: "HTTP ${response.status.value}")
        return created
    }

    private suspend fun verifyOnHost(profile: ZkTlsProfile, fields: List<String>, purpose: String, note: String) {
        val base = host() ?: throw ProtocolException("unavailable", tr(Res.string.zktls_no_host_note, note))
        val body = buildJsonObject {
            put("profile", profile.id)
            putJsonArray("fields") { fields.forEach { add(it) } }
            put("purpose", purpose)
        }
        val created = createOnHost(base, body)
        val link = created.str("request") ?: throw ProtocolException("server_error", "No request")
        val sid = created.str("sessionId") ?: throw ProtocolException("server_error", "No session")
        val token = created.str("token") ?: throw ProtocolException("server_error", "No token")
        val request = ZkTlsSessionRequest.read(ZkTlsSessionRequest.verify(ZkTlsSessionRequest.jwsOf(link), model.didResolver(),
            insecureHosts = insecureHosts()).request.payload(), insecureHosts())
        val where = Url(base).host
        ui.value = OfflineUi.ZkTlsVerifierWaiting(request, link, profile, where, local = false, note = note,
            details = transportDetails(request) + listOf(tr(Res.string.zktls_host_line, base), tr(Res.string.zktls_request_id, sid)))
        var verdict: JsonObject? = null
        while (Clock.System.now() < request.expiresAt + GRACE) {
            delay(POLL)
            val state = runCatching {
                DiwJson.parseToJsonElement(client.get("$base/zktls/sessions/$sid?token=${token.encodeURLParameter()}").bodyAsText()) as? JsonObject
            }.getOrNull() ?: continue
            when (state.str("status")) {
                "verifying" -> (ui.value as? OfflineUi.ZkTlsVerifierWaiting)?.takeIf { it.request == request && it.step == null }
                    ?.let { ui.value = it.copy(step = tr(Res.string.zktls_holder_connected)) }
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
            else -> OfflineUi.ZkTlsVerifierResult(profile, request, null, null, local = false, where = where, error = v.str("reason") ?: tr(Res.string.zktls_check_failed))
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
        val network = if (lan.isEmpty()) tr(Res.string.zktls_no_network) else tr(Res.string.zktls_listen_failed, lan.networks())
        val host = if (relay == null) tr(Res.string.zktls_no_host_relay) else tr(Res.string.zktls_host_relay_down, relay)
        return tr(Res.string.zktls_no_route_1, network, host) +
            tr(Res.string.zktls_no_route_2)
    }

    private suspend fun verifierKey(): HolderKey {
        val backend = model.backends.first()
        return model.holderIdentities.getOrCreate(VERIFIER_PROFILE, "did:key", backend.secureArea,
            backend.settings(ByteString(PlatformCrypto.randomBytes(16)), false))
    }

    private fun hostOf(url: String): String = runCatching { Url(url).host }.getOrDefault(url)

    private fun routeName(t: ZkTlsTransport): String = when (t) {
        is ZkTlsTransport.Lan -> tr(Res.string.age_route_label_lan)
        is ZkTlsTransport.Relay -> tr(Res.string.zktls_route_relay, hostOf(t.url))
        is ZkTlsTransport.Wss -> tr(Res.string.zktls_route_host, hostOf(t.url))
    }

    private fun transportDetails(request: ZkTlsSessionRequest): List<String> = request.transports.map { t ->
        when (t) {
            is ZkTlsTransport.Lan -> tr(Res.string.zktls_lan_listen, t.host, t.port)
            is ZkTlsTransport.Relay -> tr(Res.string.zktls_relay_room, t.url, t.room.take(6))
            is ZkTlsTransport.Wss -> tr(Res.string.zktls_host_connection, t.url)
        }
    } + tr(Res.string.zktls_channel)

    private fun record(r: OfflineUi.ZkTlsVerifierResult) {
        val failure = when {
            r.error != null -> r.error
            r.outcome == null -> tr(Res.string.zktls_no_result)
            !r.outcome.passed -> r.outcome.problems.firstOrNull() ?: tr(Res.string.zktls_page_no_data)
            else -> null
        }
        model.record(
            HistoryKind.VERIFIED, tr(Res.string.zktls_holder_name), null, listOf(r.profile.title),
            r.request.fields.mapNotNull { r.profile.field(it)?.label },
            tr(Res.string.zktls_history_verified, r.profile.host, if (r.local) tr(Res.string.zktls_verified_here) else tr(Res.string.zktls_verified_by, r.where), r.request.purpose.ifEmpty { tr(Res.string.age_unstated) }),
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
        val SELF_PURPOSE: String get() = tr(Res.string.zktls_saving_result)
        private val DOCUMENT_FORMATS = setOf(DocumentFormat.PDF, DocumentFormat.OFD, DocumentFormat.TEXT, DocumentFormat.XML)

        const val VERIFIER_PROFILE = "zktls-verifier"
        val EXPIRED: String get() = tr(Res.string.zktls_request_expired)
        val EXPIRED_VERIFIER: String get() = tr(Res.string.zktls_expired_no_presentation)
        private val POLL = 2.seconds
        private val GRACE = 30.seconds
        private const val HOST_REASON_TRIES = 3
    }
}

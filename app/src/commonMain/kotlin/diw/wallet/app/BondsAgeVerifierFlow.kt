package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.profile.bonds.AnimatedQrCollector
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerification
import diw.wallet.core.profile.bonds.BondsAgeVerifier
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.profile.bonds.BondsTransportException
import diw.wallet.core.profile.bonds.MAX_LAN_URLS
import diw.wallet.core.profile.bonds.networks
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.zk.OpenAcAgeVerifier
import diw.wallet.core.zk.ZkResult
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * The wallet as a Bonds age verifier. Through an age host (the test server, or the user's own deployment of it) it
 * issues a Bonds-compatible request QR and receives the holder's proof: when this device can check OpenAC proofs the
 * host only relays the package here and returns this device's verdict to the holder; otherwise the host verifies and
 * this device shows its verdict, labelled as such. Nearby ([startNearby]) there is no server at all: the holder's
 * phone sends the package over Bluetooth, or shows it as an animated QR, and this device verifies it.
 */
class BondsAgeVerifierFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var job: Job? = null

    /** The animated QR being collected for a nearby check. */
    private class PendingFrames(val request: BondsAgeRequest, val collector: AnimatedQrCollector, val scanned: Channel<ByteArray>)

    private var frames: PendingFrames? = null

    /** This device's OpenAC verifier, or why there is none; replaced in tests. */
    internal var engines: suspend () -> ZkResult<OpenAcAgeVerifier> = { model.zk.ageVerifier() }

    /** The configured age host: the user's setting, else the test server in the test environment. */
    fun host(): String? = model.settings.zkVerifierUrl.trim().trimEnd('/').takeIf { it.isNotEmpty() }
        ?: model.settings.takeIf { it.testEnvironment }?.testServerUrl?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }

    /**
     * Plain http is allowed in the test environment only: for the test server, this wallet's own server and the
     * other party's server when they were given an http address (accepted only there).
     */
    fun insecureHosts(): Set<String> {
        if (!model.settings.testEnvironment) return emptySet()
        return listOfNotNull(model.settings.testServerUrl, model.server.base(), model.server.peer.value?.url)
            .mapNotNull { runCatching { Url(it.trim()) }.getOrNull() }.filter { it.protocol == URLProtocol.HTTP }
            .map { "${it.host}:${it.port}" }.toSet()
    }

    /** The last request sent through an age host, to send again through the other party's server. */
    private var lastStart: Triple<Int, BondsCredentialSource, String>? = null

    /** Sends the last request again, now through the server [ServerModel.ageHost] picks (the other party's, once scanned). */
    fun restart() {
        val (minimumAge, source, purpose) = lastStart ?: return
        start(minimumAge, source, purpose)
    }

    fun start(minimumAge: Int, source: BondsCredentialSource, purpose: String) {
        val host = model.server.ageHost() ?: run {
            model.message.value = ServerStrings.AGE_NO_HOST
            return
        }
        stop()
        lastStart = Triple(minimumAge, source, purpose)
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working(tr(Res.string.agev_creating))
        job = model.scope.launch {
            try {
                val local = engines()
                val engine = (local as? ZkResult.Ok)?.value
                val created = createSession(host, minimumAge, source, purpose, relay = engine != null)
                val request = BondsAgeRequest.parse(created.str("request") ?: throw ProtocolException("server_error", "No request"), insecureHosts())
                val session = created.str("sessionId") ?: throw ProtocolException("server_error", "No session")
                val token = created.str("token") ?: throw ProtocolException("server_error", "No token")
                val note = (local as? ZkResult.Failed)?.let { tr(Res.string.agev_local_fallback, it.reason) }
                model.platform.keepScreenOn(true)
                ui.value = OfflineUi.AgeVerifierWaiting(request, Url(host).host, engine != null, note,
                    details = LanDetails.age(request) + tr(Res.string.agev_response_url, request.responseUrl), peerable = true)
                follow(host, session, token, request, engine, note)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed(tr(Res.string.agev_create_failed) + model.describe(e))
            } finally {
                // A request sent again through another server keeps the screen on for itself.
                if (job == null || job === currentCoroutineContext()[Job]) model.platform.keepScreenOn(false)
            }
        }
    }

    /**
     * A nearby check with no server: the QR carries a one-time service UUID instead of a response address. With
     * [bluetooth] this device scans for the holder advertising it over the Bonds BLE link, verifies the package here
     * and writes the verdict back; at the same time (or only, without Bluetooth) the holder's animated QR can be
     * scanned ([acceptFrame]). Whichever completes first is verified, the other is stopped.
     */
    fun startNearby(minimumAge: Int, source: BondsCredentialSource, purpose: String, bluetooth: Boolean = true) {
        val link = if (bluetooth) model.platform.bondsLinkCentral ?: run {
            model.message.value = NO_CENTRAL
            return
        } else null
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working(if (bluetooth) tr(Res.string.agev_preparing_ble) else tr(Res.string.agev_preparing_qr))
        job = model.scope.launch {
            try {
                val engine = localEngine(if (bluetooth) BLUETOOTH else ANIMATED_QR) ?: return@launch
                // Without Bluetooth the holder's animated QR still works, so a radio problem is a note, not a failure.
                val note = link?.unavailableReason()?.let { tr(Res.string.agev_ble_use_qr, it) }
                val request = BondsAgeRequest.create(minimumAge, source, purpose, null, qr = true)
                val host = if (bluetooth) BLUETOOTH else ANIMATED_QR
                val waiting = OfflineUi.AgeVerifierWaiting(request, host, relay = true, note = note, details = LanDetails.age(request))
                val scanned = Channel<ByteArray>(Channel.CONFLATED)
                frames = PendingFrames(request, AnimatedQrCollector(BondsLinkTransport.AGE_MAX_PAYLOAD), scanned)
                model.platform.keepScreenOn(true)
                ui.value = waiting
                fun update(change: (OfflineUi.AgeVerifierWaiting) -> OfflineUi.AgeVerifierWaiting) {
                    (ui.value as? OfflineUi.AgeVerifierWaiting)?.takeIf { it.request == request }?.let { ui.value = change(it) }
                }
                val result = withTimeoutOrNull(request.expiresAt + GRACE - Clock.System.now()) {
                    coroutineScope {
                        val done = CompletableDeferred<OfflineUi.AgeVerifierResult>()
                        if (link != null && note == null) launch {
                            var shown: OfflineUi.AgeVerifierResult? = null
                            try {
                                link.receive(request.linkServiceId!!, BondsLinkTransport.AGE_MAX_PAYLOAD, onProgress = { text ->
                                    update { it.copy(link = text) }
                                }, answer = { bytes ->
                                    update { it.copy(checking = true) }
                                    val (r, verdict) = check(request, BLUETOOTH, engine, bytes.decodeToString())
                                    shown = r
                                    verdict.encode().encodeToByteArray()
                                })
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                update { it.copy(link = tr(Res.string.agev_ble_incomplete, model.describe(e))) }
                            }
                            shown?.let { done.complete(it) }
                        }
                        launch {
                            // Something else read whole (another app's animated code) does not end the check.
                            for (bytes in scanned) {
                                update { it.copy(checking = true) }
                                val r = check(request, ANIMATED_QR, engine, bytes.decodeToString()).first
                                if (r.verification != null) {
                                    done.complete(r)
                                    break
                                }
                                update { it.copy(checking = false, scanned = null, note = r.error) }
                            }
                        }
                        done.await().also { coroutineContext.cancelChildren() }
                    }
                }
                show(result ?: OfflineUi.AgeVerifierResult(request, host, null, null, EXPIRED))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed(tr(Res.string.agev_incomplete) + model.describe(e))
            } finally {
                frames = null
                model.platform.keepScreenOn(false)
            }
        }
    }

    /** A frame of the holder's animated QR for the running nearby check; the camera closes once the package is whole. */
    fun acceptFrame(text: String): QrScanStep {
        val pending = frames ?: return QrScanStep(true, tr(Res.string.agev_no_qr_wait))
        val reception = try {
            pending.collector.accept(text)
        } catch (e: BondsTransportException) {
            return QrScanStep(false, tr(Res.string.agev_frame_unreadable))
        }
        val (got, total) = when (reception) {
            is BondsReception.Completed -> {
                pending.collector.reset()
                pending.scanned.trySend(reception.payload)
                return QrScanStep(true)
            }
            is BondsReception.Accepted -> reception.received to reception.total
            is BondsReception.Duplicate -> reception.received to reception.total
        }
        val progress = tr(Res.string.agev_qr_progress, got * 100 / total, got, total)
        (ui.value as? OfflineUi.AgeVerifierWaiting)?.takeIf { it.request == pending.request }?.let { ui.value = it.copy(scanned = progress) }
        return QrScanStep(false, progress)
    }

    /**
     * A check over the local network: this device listens on its Wi-Fi and hotspot addresses (every network card, since
     * it cannot know which one the holder shares), the QR names them, and the holder's phone posts the package to the
     * one on its own network. No server, no Internet; the verdict is the
     * reply to the holder's post.
     */
    fun startLan(minimumAge: Int, source: BondsCredentialSource, purpose: String) {
        val lan = model.platform.bondsLan ?: run {
            model.message.value = tr(Res.string.agev_no_lan_platform)
            return
        }
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working(tr(Res.string.agev_preparing_lan))
        job = model.scope.launch {
            try {
                val interfaces = lan.localInterfaces().take(MAX_LAN_URLS).ifEmpty {
                    ui.value = OfflineUi.Failed(NO_LAN)
                    return@launch
                }
                val addresses = interfaces.map { it.address }
                val engine = localEngine(tr(Res.string.age_route_label_lan)) ?: return@launch
                // People see the network; the addresses are in the technical details.
                val host = tr(Res.string.agev_lan_host, interfaces.networks())
                var details = emptyList<String>()
                var request: BondsAgeRequest? = null
                var result: OfflineUi.AgeVerifierResult? = null
                model.platform.keepScreenOn(true)
                withTimeoutOrNull(BondsAgeRequest.LIFETIME + GRACE) {
                    lan.serve(addresses, "/age/" + PlatformCrypto.randomBytes(16).toBase64Url(), BondsLinkTransport.AGE_MAX_PAYLOAD, onListening = { urls ->
                        request = BondsAgeRequest.create(minimumAge, source, purpose, urls.first(), otherLanUrls = urls.drop(1))
                            .also {
                                details = LanDetails.age(it, LanDetails.listening(urls, interfaces))
                                ui.value = OfflineUi.AgeVerifierWaiting(it, host, relay = true, note = null, details = details)
                            }
                    }) { body ->
                        val r = request!!
                        ui.value = OfflineUi.AgeVerifierWaiting(r, host, relay = true, note = null, checking = true, details = details)
                        val (shown, verdict) = check(r, host, engine, body.decodeToString())
                        // A body that is not a package for this request (another device on the network) does not end the check.
                        if (shown.verification != null) result = shown
                        else ui.value = OfflineUi.AgeVerifierWaiting(r, host, relay = true, note = shown.error, details = details)
                        verdict.encode().encodeToByteArray() to (shown.verification != null)
                    }
                }
                show(result ?: OfflineUi.AgeVerifierResult(request ?: return@launch, host, null, null, EXPIRED))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed(tr(Res.string.agev_lan_incomplete) + model.describe(e))
            } finally {
                model.platform.keepScreenOn(false)
            }
        }
    }

    /** This device's verifier for a serverless check over [how], or null after showing why there is none. */
    private suspend fun localEngine(how: String): OpenAcAgeVerifier? = when (val r = engines()) {
        is ZkResult.Ok -> r.value
        is ZkResult.Failed -> {
            ui.value = OfflineUi.Failed(tr(Res.string.agev_no_local_engine, r.reason, how))
            null
        }
        ZkResult.Cancelled -> null
    }

    fun stop() {
        job?.cancel()
        job = null
        frames = null
    }

    private suspend fun createSession(host: String, minimumAge: Int, source: BondsCredentialSource, purpose: String, relay: Boolean): JsonObject {
        val response = model.http.post("$host/api/zkp/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("credentialSource", if (source == BondsCredentialSource.SELF_ISSUED) "selfIssued" else "government")
                put("minimumAge", minimumAge)
                put("purpose", purpose)
                put("mode", if (relay) "relay" else "server")
            }.toString())
        }
        val body = response.bodyAsText()
        val json = runCatching { DiwJson.parseToJsonElement(body) as? JsonObject }.getOrNull()
        if (!response.status.isSuccess() || json == null) {
            throw ProtocolException("server_error", json?.str("error_description") ?: tr(Res.string.agev_host_http, response.status.value))
        }
        return json
    }

    /** Polls the host until the proof arrives (relay: verify it here and answer) or the host's verdict is in. */
    private suspend fun follow(host: String, session: String, token: String, request: BondsAgeRequest, engine: OpenAcAgeVerifier?, note: String?) {
        val url = "$host/api/zkp/sessions/$session?token=${token.encodeURLParameter()}"
        val hostName = Url(host).host
        while (Clock.System.now() < request.expiresAt + GRACE) {
            val state = runCatching { DiwJson.parseToJsonElement(model.http.get(url).bodyAsText()) as? JsonObject }.getOrNull()
            val posted = state?.str("package")
            when {
                engine != null && posted != null -> {
                    ui.value = OfflineUi.AgeVerifierWaiting(request, hostName, true, note, checking = true)
                    finishHere(host, session, token, request, engine, posted)
                    return
                }
                state?.str("state") == "done" -> {
                    val verdict = (state["verdict"] as? JsonObject)?.let { BondsAgeVerdict.parse(it.toString()) }
                    show(OfflineUi.AgeVerifierResult(request, hostName, null, verdict, if (verdict == null) tr(Res.string.agev_host_unreadable) else null))
                    return
                }
                state?.str("state") == "received" ->
                    ui.value = OfflineUi.AgeVerifierWaiting(request, hostName, engine != null, note, checking = true)
            }
            delay(POLL)
        }
        show(OfflineUi.AgeVerifierResult(request, hostName, null, null, EXPIRED))
    }

    private suspend fun finishHere(host: String, session: String, token: String, request: BondsAgeRequest, engine: OpenAcAgeVerifier, posted: String) {
        val (result, verdict) = check(request, Url(host).host, engine, posted)
        answer(host, session, token, verdict)
        show(result)
    }

    /** Verifies a received package on this device: what to show here and the verdict to return to the holder. */
    private suspend fun check(request: BondsAgeRequest, host: String, engine: OpenAcAgeVerifier, posted: String): Pair<OfflineUi.AgeVerifierResult, BondsAgeVerdict> = try {
        val pkg = BondsAgePackage.parse(posted, request)
        val verification = BondsAgeVerifier.verify(pkg, engine, model.didResolver(), model.didTrust)
        OfflineUi.AgeVerifierResult(request, host, verification, null, null) to verification.verdict()
    } catch (e: CancellationException) {
        throw e
    } catch (e: ProtocolException) {
        OfflineUi.AgeVerifierResult(request, host, null, null, tr(Res.string.agev_proof_unreadable) + model.describe(e)) to
            BondsAgeVerdict("failed", false, tr(Res.string.agev_proof_incomplete), request.minimumAge, null)
    } catch (e: Exception) {
        OfflineUi.AgeVerifierResult(request, host, null, null, tr(Res.string.agev_local_failed) + model.describe(e)) to
            BondsAgeVerdict("failed", false, tr(Res.string.agev_verifier_failed), request.minimumAge, null)
    }

    private suspend fun answer(host: String, session: String, token: String, verdict: BondsAgeVerdict) {
        runCatching {
            model.http.post("$host/api/zkp/sessions/$session/verdict?token=${token.encodeURLParameter()}") {
                contentType(ContentType.Application.Json)
                setBody(verdict.encode())
            }
        }
    }

    private fun show(result: OfflineUi.AgeVerifierResult) {
        // No frame is awaited once a result is on screen, so a camera still open closes on the next one.
        frames = null
        ui.value = result
        val v = result.verification
        val accepted = v?.accepted ?: result.remote?.accepted ?: false
        val failure = when {
            accepted -> null
            v != null -> v.reason
            else -> result.remote?.reason ?: result.error ?: tr(Res.string.agev_no_proof)
        }
        model.record(
            HistoryKind.VERIFIED, tr(Res.string.agev_age_proof), v?.issuerTrust,
            listOfNotNull(v?.let { if (it.selfIssued) tr(Res.string.agev_self_issued) else tr(Res.string.agev_issuer, shortDid(it.issuerDid)) }),
            listOf(tr(Res.string.age_over_n, result.request.minimumAge)),
            tr(Res.string.agev_note_start) + (if (result.request.nearby) (if (result.host == ANIMATED_QR) tr(Res.string.agev_note_qr) else tr(Res.string.agev_note_ble)) else if (result.request.lan) tr(Res.string.agev_note_lan) else "") +
                (if (v != null) tr(Res.string.agev_note_here) else tr(Res.string.agev_note_by, result.host)) +
                tr(Res.string.agev_note_purpose, result.request.purpose.ifEmpty { tr(Res.string.age_unstated) }),
            failure,
        )
    }

    /** What the result screen says about a local verification. */
    companion object {
        /** A long DID cut to its start and end for display. */
        fun shortDid(did: String) = if (did.length > 28) did.take(18) + "…" + did.takeLast(6) else did

        private fun seconds(ms: Long) = ((ms + 50) / 100).let { tr(Res.string.agev_seconds, it / 10, it % 10) }

        val POLL = 1.seconds
        val GRACE = 30.seconds
        val EXPIRED: String get() = tr(Res.string.agev_expired)
        val BLUETOOTH: String get() = tr(Res.string.age_route_label_bluetooth)
        val ANIMATED_QR: String get() = tr(Res.string.agev_animated_qr)
        val NO_LAN: String get() = tr(Res.string.agev_no_lan)
        val NO_CENTRAL: String get() = tr(Res.string.agev_no_central)

        fun summary(v: BondsAgeVerification): List<String> = listOfNotNull(
            tr(Res.string.agev_summary_age, v.request.minimumAge, v.request.cutoff),
            tr(Res.string.agev_summary_zk, seconds(v.verifyMs), seconds(v.prepareMs + v.showMs)),
            tr(Res.string.agev_summary_claim, v.claimName),
            if (v.selfIssued) tr(Res.string.agev_summary_self) else null,
            v.reason,
        )
    }
}

package diw.wallet.app

import diw.wallet.app.legal.Integration
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.document.mrtd.Lds
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportAnswer
import diw.wallet.core.zkpassport.ZkPassportAnswerFailure
import diw.wallet.core.zkpassport.ZkPassportAnswerProgress
import diw.wallet.core.zkpassport.ZkPassportChip
import diw.wallet.core.zkpassport.ZkPassportCscaCheck
import diw.wallet.core.zkpassport.ZkPassportConfig
import diw.wallet.core.zkpassport.ZkPassportFaceMatch
import diw.wallet.core.zkpassport.ZkPassportFaceMatchApp
import diw.wallet.core.zkpassport.ZkPassportFaceMatchAttestation
import diw.wallet.core.zkpassport.ZkPassportFaceMatchEvidence
import diw.wallet.core.zkpassport.ZkPassportFaceMatchKind
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportIncoming
import diw.wallet.core.zkpassport.ZkPassportPairedProver
import diw.wallet.core.zkpassport.ZkPassportProverTarget
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportResult
import diw.wallet.core.zkpassport.ZkPassportSession
import diw.wallet.core.zkpassport.ZkPassportState
import io.ktor.http.Url
import diw.wallet.core.zkpassport.ZkPassportChannel
import diw.wallet.core.zkpassport.ZkPassportDiwNearby
import diw.wallet.core.zkpassport.ZkPassportNearbyLink
import diw.wallet.core.zkpassport.ZkPassportResponder
import diw.wallet.core.zktls.ZkTlsTransport
import diw.wallet.core.profile.bonds.postFirstFrom
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/**
 * The wallet as a zkPassport verifier (docs/design/zkpassport.md 5.2): a request QR for the holder's zkPassport app,
 * proofs received over zkPassport's bridge and verified on this device against the on-chain registries. Needs the
 * zkPassport statement; the bridge, the circuit CDN and the Ethereum node are the only parties contacted.
 */
class ZkPassportFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var session: ZkPassportSession? = null
    private var job: Job? = null
    private var answer: ZkPassportAnswer? = null

    /** The temporary prover this wallet is paired with (diw-server prover); in memory only, gone with the app. */
    val paired = MutableStateFlow<ZkPassportPairedProver?>(null)

    /**
     * Pairs with a temporary prover from its one-time code. Nothing about a passport is sent here: the consent screen
     * of each request names where the proofs are made.
     */
    fun pair(link: String) {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.message.value = model.legal.disabledMessage(Integration.ZKPASSPORT)
            return
        }
        val holder = model.platform.zk?.zkPassportHolder ?: run {
            model.message.value = tr(Res.string.zkp_answer_no_engine)
            return
        }
        model.scope.launch {
            try {
                val prover = holder.pair(link)
                paired.value?.let { old -> runCatching { old.end() } }
                paired.value = prover
                model.message.value = tr(Res.string.zkp_pair_done, prover.url)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                model.message.value = tr(Res.string.zkp_pair_failed, answerFailure((e as? ZkPassportAnswerFailure)?.code ?: "other"))
            }
        }
    }

    /** Ends the session with the temporary prover. */
    fun endPairing() {
        val prover = paired.value ?: return
        paired.value = null
        model.scope.launch { runCatching { prover.end() } }
    }

    /** What preparing offline use is doing now; null when idle. */
    val offlineProgress = MutableStateFlow<String?>(null)
    /** Changes whenever what is kept for offline use may have changed, so the settings read it again. */
    val offlineStamp = MutableStateFlow(0)

    /**
     * What this device keeps for offline zkPassport checks, in one line: the registry state's date and the files kept;
     * null when nothing is kept.
     */
    fun offlineSummary(): String? {
        val state = model.platform.zk?.zkPassport?.offlineState(false) ?: return null
        val date = state.certificateRootAt?.let { kotlin.time.Instant.fromEpochSeconds(it).toString().substringBefore('T') } ?: "-"
        val megabytes = ((state.bytes + 524_288) / 1_048_576).toString()
        return tr(Res.string.zkp_offline_summary, date, state.files, megabytes, state.versions.joinToString(", ").ifEmpty { "-" })
    }

    /**
     * Fetches ahead what checks and answers without the Internet take (5.8): the registry state and the current
     * manifest for verifying (mainnet, and Sepolia in the test environment), then for each stored passport the
     * packaged circuits answering this wallet's requests with it takes, when this device proves itself.
     */
    fun prepareOffline() {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.message.value = model.legal.disabledMessage(Integration.ZKPASSPORT)
            return
        }
        val verifier = model.platform.zk?.zkPassport ?: run {
            model.message.value = tr(Res.string.zkp_no_engine)
            return
        }
        if (offlineProgress.value != null) return
        val settings = model.settings
        val config = ZkPassportConfig(
            mainnetRpc = settings.zkPassportMainnetRpc.trim().ifEmpty { null },
            sepoliaRpc = settings.zkPassportSepoliaRpc.trim().ifEmpty { null },
        )
        offlineProgress.value = tr(Res.string.zkp_offline_registry)
        model.scope.launch {
            try {
                for (dev in listOf(false) + listOfNotNull(true.takeIf { settings.testEnvironment })) verifier.prepareOffline(dev, config)
                val holder = model.platform.zk?.zkPassportHolder
                var circuits = 0
                var passports = 0
                // Answering also needs the proof parameters; without them the passports are not called ready.
                var note: String? = null
                if (holder != null && deviceCanProve() != false) {
                    try {
                        for (file in passports()) {
                            val chip = chip(file) ?: continue
                            offlineProgress.value = tr(Res.string.zkp_offline_passport, file.name)
                            circuits = maxOf(circuits, holder.prepareOffline(chip, false, config.mainnetRpc) { p ->
                                if (p is ZkPassportAnswerProgress.Circuits) offlineProgress.value = tr(Res.string.zkp_offline_circuits, file.name, p.count)
                            })
                            passports++
                        }
                    } catch (e: ZkPassportAnswerFailure) {
                        if (e.code != "crs_missing") throw e
                        passports = 0
                        note = tr(Res.string.zkp_answer_err_crs)
                    }
                }
                model.message.value = (if (passports > 0) tr(Res.string.zkp_offline_done_passports, passports, circuits) else tr(Res.string.zkp_offline_done)) +
                    (note?.let { "\n" + it } ?: "")
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                model.message.value = tr(Res.string.zkp_offline_failed, answerFailure((e as? ZkPassportAnswerFailure)?.code ?: "other"))
            } finally {
                offlineProgress.value = null
                offlineStamp.value++
            }
        }
    }

    /** Deletes what is kept for offline use; requests download it again when online. */
    fun clearOffline() {
        model.platform.zk?.zkPassport?.clearOffline()
        offlineStamp.value++
        model.message.value = tr(Res.string.zkp_offline_cleared)
    }

    /** Where an answer can be proved: this device, the self-hosted prover when set, the paired one when paired. */
    fun targets(): List<ZkPassportProverTarget> = buildList {
        add(ZkPassportProverTarget.Device)
        val s = model.settings
        if (s.zkProverUrl.isNotEmpty() && s.zkProverToken.isNotEmpty()) add(ZkPassportProverTarget.Host(s.zkProverUrl, s.zkProverToken))
        paired.value?.let { add(ZkPassportProverTarget.Paired(it)) }
    }

    /** Whether this device can prove itself (UltraHonk in its native library); null while not yet known. */
    fun deviceCanProve(): Boolean? = model.zk.capability.value?.backends?.contains(diw.wallet.core.zk.ZkBackend.NOIR_ULTRAHONK)

    /** The domain requests are made for: the user's setting, else [serverDomain]. */
    fun defaultDomain(): String = model.settings.zkPassportDomain.trim().ifEmpty { serverDomain() }

    /** The host of this wallet's own production server, what an empty domain setting falls back to; empty without one. */
    fun serverDomain(): String =
        model.settings.zkVerifierUrl.trim().takeIf { it.isNotEmpty() }?.let { runCatching { Url(it).host }.getOrNull() }.orEmpty()

    fun openSetup() {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.screen.value = Screen.IntegrationStatement(Integration.ZKPASSPORT)
            return
        }
        stop()
        val note = if (model.platform.zk?.zkPassport == null) tr(Res.string.zkp_no_engine) else null
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.ZkPassportSetup(defaultDomain(), model.settings.testEnvironment, note)
    }

    fun start(request: ZkPassportRequest) {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.message.value = model.legal.disabledMessage(Integration.ZKPASSPORT)
            return
        }
        val engine = model.platform.zk?.zkPassport ?: run {
            model.message.value = tr(Res.string.zkp_no_engine)
            return
        }
        stop()
        val settings = model.settings
        val config = ZkPassportConfig(
            mainnetRpc = settings.zkPassportMainnetRpc.trim().ifEmpty { null },
            sepoliaRpc = settings.zkPassportSepoliaRpc.trim().ifEmpty { null },
            verifierApi = settings.zkPassportVerifierApi,
            verifierApiNow = { model.settings.zkPassportVerifierApi },
        )
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.ZkPassportWaiting(request, null, ZkPassportState.Connecting)
        model.platform.keepScreenOn(true)
        // Another copy of this wallet may answer through the user's relay (DIW extension, 5.7).
        val relay = model.server.relaysForVerifier().firstOrNull()?.let { runCatching { ZkTlsTransport.relayAddress(it) }.getOrNull() }
        job = model.scope.launch {
            coroutineScope {
                val ready = CompletableDeferred<ZkPassportSession>()
                val nearby = if (settings.zkPassportNearby) listenNearby(ready) else null
                val routes = listOfNotNull(
                    relay?.let { tr(Res.string.zkp_route_relay, hostOf(it)) },
                    nearby?.lan?.takeIf { it.isNotEmpty() }?.let { tr(Res.string.zkp_route_lan) },
                    nearby?.ble?.let { tr(Res.string.zkp_route_ble) },
                )
                val opened = engine.open(
                    request,
                    config.copy(cscaAnchors = cscaAnchors(), oprfKeyHash = oprfKeyHash(), diwRelay = relay, diwNearby = nearby),
                    model.scope,
                )
                session = opened
                ready.complete(opened)
                try {
                    var url: String? = null
                    opened.state.takeWhile { s ->
                        when (s) {
                            is ZkPassportState.Waiting -> url = s.url
                            is ZkPassportState.Scanned -> url = s.url
                            else -> {}
                        }
                        when (s) {
                            is ZkPassportState.Done -> show(request, s.result, null)
                            ZkPassportState.Rejected -> show(request, null, tr(Res.string.zkp_rejected))
                            is ZkPassportState.Failed -> show(request, null, failure(s.code, s.detail))
                            else -> ui.value = OfflineUi.ZkPassportWaiting(request, url, s, routes, nearby?.lan.orEmpty())
                        }
                        s !is ZkPassportState.Done && s != ZkPassportState.Rejected && s !is ZkPassportState.Failed
                    }.collect {}
                } finally {
                    opened.close()
                    model.platform.keepScreenOn(false)
                    // The local network listener and the BLE scan end with the request.
                    coroutineContext.cancelChildren()
                }
            }
        }
    }

    /**
     * Starts listening for a nearby answer of another copy of this wallet (DIW extension, 5.8): on this device's local
     * network addresses (every card, as the holder's phone may share any of them) and, where the platform has the
     * Bonds BLE central and it can be used now, on a one-time BLE service. Whatever arrives goes to the session once
     * [ready]. Returns what the request link names, or null when neither way is open.
     */
    private suspend fun CoroutineScope.listenNearby(ready: CompletableDeferred<ZkPassportSession>): ZkPassportDiwNearby? {
        val lan = model.platform.bondsLan
        val interfaces = lan?.let { runCatching { it.localInterfaces() }.getOrNull() }.orEmpty().take(ZkPassportDiwNearby.MAX_LAN)
        val urls = CompletableDeferred<List<String>>()
        if (lan != null && interfaces.isNotEmpty()) {
            launch {
                try {
                    lan.serve(interfaces.map { it.address }, ZkPassportDiwNearby.newPath(), ZkPassportDiwNearby.MAX_PAYLOAD, onListening = { urls.complete(it) }) { body ->
                        val reply = ready.await().nearby(body)
                        // Anything that is not this request's answer (another device on the network) keeps the listener open.
                        reply to (diw.wallet.core.zkpassport.ZkPassportNearbyPayload.replyError(reply) == null)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Exception) {
                    urls.complete(emptyList())
                }
            }
        } else {
            urls.complete(emptyList())
        }
        // A permission asked for just now may still be granted during the request: the link names the service anyway,
        // and the scan starts once the person allowed it.
        val central = model.platform.bondsLinkCentral?.let { c ->
            val usable = runCatching { c.unavailableReason() }.getOrNull() == null
            c.takeIf { usable || runCatching { c.permissionPending() }.getOrDefault(false) }
        }
        val service = central?.let { ZkPassportDiwNearby.newServiceId() }
        if (central != null && service != null) {
            launch {
                while (runCatching { central.permissionPending() }.getOrDefault(false)) delay(1000)
                // Denied, or Bluetooth is off once allowed: the link's other ways remain.
                if (runCatching { central.unavailableReason() }.getOrNull() != null) return@launch
                // The holder advertises only once its answer is ready; a failed or foreign exchange starts the scan again.
                while (isActive) {
                    try {
                        central.receive(service, ZkPassportDiwNearby.MAX_PAYLOAD, onProgress = {}) { body -> ready.await().nearby(body) }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        delay(1000)
                    }
                }
            }
        }
        val lanUrls = withTimeoutOrNull(5_000) { urls.await() }.orEmpty()
        return ZkPassportDiwNearby(lanUrls, service).takeUnless { it.isEmpty }
    }

    /** This wallet's CSCA anchors (production and the user's own), as DER. */
    private suspend fun cscaAnchors(): List<ByteArray> =
        listOf(TrustEnvironment.PRODUCTION, TrustEnvironment.USER).flatMap { env ->
            runCatching { model.trust.travelDocumentAnchors(env) }.getOrDefault(emptyList()).map { it.encoded.toByteArray() }
        }.distinctBy { it.toList() }

    /**
     * The OPRF key hash this wallet's server publishes (5.5), read fresh at each request; salted identifiers are
     * accepted only under it. Null without a server or when it offers no OPRF, so salted identifiers are refused.
     */
    private suspend fun oprfKeyHash(): String? =
        model.server.base()?.let { runCatching { model.server.oprfKeyHash(it) }.getOrNull() }

    /**
     * Answers a zkPassport request link with a passport stored in this wallet (Z3, docs/design/zkpassport.md 5.3):
     * the bridge is opened first, so the consent screen can show the origin the bridge reports for the requester.
     * Covered by version 3 of the zkPassport statement.
     */
    fun answer(incoming: ZkPassportIncoming) {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.screen.value = Screen.IntegrationStatement(Integration.ZKPASSPORT, pendingUri = incoming.link)
            return
        }
        stop()
        model.screen.value = Screen.Offline
        val holder = model.platform.zk?.zkPassportHolder ?: run {
            ui.value = OfflineUi.ZkPassportAnswerDone(incoming, false, tr(Res.string.zkp_answer_no_engine))
            return
        }
        ui.value = OfflineUi.ZkPassportAnswerConnecting(incoming)
        // Under "own server only" a relay on another server is not used; the bridge or a nearby way still are.
        val own = model.server.base()
        val allowed = incoming.diwRelay?.takeIf { r ->
            model.server.policy != ServerPolicy.OWN_ONLY || (own != null && ZkTlsTransport.sameRelay(r.url, own))
        }
        val routed = incoming.copy(diwRelay = allowed)
        job = model.scope.launch {
            val opened = try {
                holder.connect(routed, rpc(incoming), routed.diwNearby?.let { nearbyLink(it) })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.ZkPassportAnswerDone(incoming, false, answerFailure((e as? ZkPassportAnswerFailure)?.code ?: "connection"))
                return@launch
            }
            answer = opened
            ui.value = OfflineUi.ZkPassportAnswerConsent(
                incoming, opened.origin, opened.originMatches, passports(), unsupported(incoming, model.platform.faceMatch != null),
                opened.channel,
            )
        }
    }

    /**
     * The holder's way to a requester of this wallet nearby (5.8): one of its local network addresses this phone
     * reaches (any HTTP reply counts), else its BLE service when this phone's Bonds BLE link can be used now. The
     * answer goes the probed way, and over BLE when the network fails at delivery.
     */
    private fun nearbyLink(nearby: ZkPassportDiwNearby): ZkPassportNearbyLink = object : ZkPassportNearbyLink {
        private var url: String? = null

        override suspend fun probe(): String? {
            val lan = model.platform.bondsLan
            if (lan != null && nearby.lan.isNotEmpty()) {
                for (u in lan.preferred(nearby.lan)) {
                    val reached = runCatching { lan.exchange(u, null, null, null, PROBE_TIMEOUT) }.isSuccess
                    if (reached) {
                        url = u
                        return ZkPassportResponder.NEARBY_LAN
                    }
                }
            }
            return if (ble()) ZkPassportResponder.NEARBY_BLE else null
        }

        private suspend fun ble(): Boolean = nearby.ble != null &&
            model.platform.bondsLink?.let { runCatching { it.unavailableReason() }.getOrNull() == null } == true

        override suspend fun deliver(payload: ByteArray, onProgress: (String) -> Unit): ByteArray {
            val lan = model.platform.bondsLan
            val first = url
            if (lan != null && first != null) {
                try {
                    val (status, text, _) = lan.postFirstFrom(listOf(first) + (nearby.lan - first), payload, SEND_TIMEOUT)
                    if (status in 200..299) return text.encodeToByteArray()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    if (!ble()) throw e
                }
            }
            val link = model.platform.bondsLink ?: throw ZkPassportAnswerFailure("nearby_unavailable")
            val service = nearby.ble ?: throw ZkPassportAnswerFailure("nearby_unavailable")
            val reply = link.exchange(service, payload, onProgress) ?: throw ZkPassportAnswerFailure("nearby_ble")
            // An empty reply is a receipt without a verdict.
            return if (reply.isEmpty()) diw.wallet.core.zkpassport.ZkPassportNearbyPayload.reply() else reply
        }
    }

    /** Proves the request from the stored passport [file] and sends the proofs. */
    fun accept(file: StoredFile, target: ZkPassportProverTarget = ZkPassportProverTarget.Device) {
        val a = answer ?: return
        val incoming = (ui.value as? OfflineUi.ZkPassportAnswerConsent)?.incoming ?: return
        ui.value = OfflineUi.ZkPassportAnswerProving(incoming, null)
        model.platform.keepScreenOn(true)
        job = model.scope.launch {
            try {
                val chip = chip(file) ?: throw ZkPassportAnswerFailure("passport")
                // The comparison comes before the request is accepted, so a failed one sends the requester nothing.
                val face = incoming.faceMatchMode?.let { faceEvidence(chip, incoming, it == "strict") }
                a.answer(chip, target, face) { p -> ui.value = OfflineUi.ZkPassportAnswerProving(incoming, p) }
                answered(incoming, whereFrom(a), file, null, target)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                answered(incoming, whereFrom(a), file, answerFailure((e as? ZkPassportAnswerFailure)?.code ?: "other"), target)
            } finally {
                a.close()
                if (answer === a) answer = null
                model.platform.keepScreenOn(false)
            }
        }
    }

    /**
     * FaceMatch for an answer (docs/design/zkpassport.md 5.6): the holder's face is compared with the photo of
     * [chip] on this device, then a new hardware key signs the statement of that comparison where the requester
     * takes key attested proofs and the device attests its keys; otherwise the proof is the self-declared kind,
     * when the requester takes that. Nothing is claimed without a comparison that passed.
     */
    private suspend fun faceEvidence(chip: ZkPassportChip, incoming: ZkPassportIncoming, strict: Boolean): ZkPassportFaceMatchEvidence {
        val service = model.platform.faceMatch ?: throw ZkPassportAnswerFailure("facematch_unsupported")
        val holder = model.platform.zk?.zkPassportHolder ?: throw ZkPassportAnswerFailure("native_unavailable")
        val kinds = incoming.faceMatchKinds
        if (kinds.isEmpty()) throw ZkPassportAnswerFailure("facematch_unsupported")
        val photo = withContext(Dispatchers.Default) { chip.dg2?.let { Lds.dg2(it).firstOrNull() }?.data }
            ?: throw ZkPassportAnswerFailure("facematch_photo")
        ui.value = OfflineUi.ZkPassportAnswerProving(incoming, null, comparing = true)
        val comparison = try {
            service.compare(photo, strict, model.settings.zkPassportFaceNet)
        } catch (e: FaceMatchFailure) {
            throw ZkPassportAnswerFailure("facematch_" + e.code)
        }
        ui.value = OfflineUi.ZkPassportAnswerProving(incoming, null)
        val attestation = if (ZkPassportFaceMatchKind.KEY_ATTESTATION in kinds) {
            val statement = holder.faceMatchStatement(chip, service.appVersion, strict, comparison.embedding, comparison.cosine, comparison.threshold)
            service.attest(statement.toSign)?.let { ZkPassportFaceMatchAttestation(statement.clientData, it.chain, it.signature, it.signerDigest) }
        } else {
            null
        }
        if (attestation == null && ZkPassportFaceMatchKind.SELF !in kinds) throw ZkPassportAnswerFailure("facematch_attestation")
        return ZkPassportFaceMatchEvidence(strict, service.appId, attestation)
    }

    /** Tells the requester the holder declined. */
    fun reject() {
        val a = answer ?: return
        val incoming = (ui.value as? OfflineUi.ZkPassportAnswerConsent)?.incoming ?: return
        answer = null
        job = model.scope.launch {
            try {
                runCatching { a.reject() }
            } finally {
                a.close()
            }
            ui.value = OfflineUi.ZkPassportAnswerDone(incoming, false, null)
            model.record(
                HistoryKind.DECLINED, incoming.domain, null, emptyList(), asks(incoming.query),
                tr(Res.string.zkp_answer_history_note, whereFrom(a)),
            )
        }
    }

    private fun answered(incoming: ZkPassportIncoming, origin: String, file: StoredFile, error: String?, target: ZkPassportProverTarget) {
        ui.value = OfflineUi.ZkPassportAnswerDone(incoming, error == null, error)
        model.record(
            HistoryKind.PRESENTED, incoming.domain, null, listOf(file.name), asks(incoming.query),
            tr(Res.string.zkp_answer_history_note, origin) + (if (incoming.devMode) tr(Res.string.zkp_answer_history_test) else "") +
                (targetAddress(target)?.let { tr(Res.string.zkp_answer_history_remote, it) } ?: ""),
            error,
        )
    }

    /** Where the request came from, for the history: the origin, or the nearby way, which reports none. */
    private fun whereFrom(a: ZkPassportAnswer): String = when (a.channel) {
        ZkPassportChannel.DIW_LAN -> tr(Res.string.zkp_route_lan)
        ZkPassportChannel.DIW_BLE -> tr(Res.string.zkp_route_ble)
        else -> a.origin
    }

    /** The Ethereum node for the registries of the request's chain; null uses the built-in one. */
    private fun rpc(incoming: ZkPassportIncoming): String? =
        (if (incoming.devMode) model.settings.zkPassportSepoliaRpc else model.settings.zkPassportMainnetRpc).trim().ifEmpty { null }

    /** The electronic passports stored in this wallet, newest first. */
    private fun passports(): List<StoredFile> =
        model.files.files.value.filter { it.report?.format == DocumentFormat.EMRTD }.sortedByDescending { it.addedAt }

    /**
     * What answering [query] with the stored passport [file] would send, one line per disclosed field as zkPassport
     * reads it, and whether its first name leaves out given-name components.
     */
    suspend fun preview(file: StoredFile, query: JsonObject): Pair<List<String>, Boolean> = withContext(Dispatchers.Default) {
        val none = emptyList<String>() to false
        val dg1 = MrtdDump.decode(model.files.data(file.id))?.file(LdsFile.DG1) ?: return@withContext none
        val mrz = Lds.dg1(dg1)?.takeIf { it.format == Mrz.Format.TD3 || it.format == Mrz.Format.TD1 }?.text ?: return@withContext none
        val values = ZkPassport.disclosedPreview(mrz, query)
        val lines = values.map { (key, value) -> tr(Res.string.zkp_line, keyTitle(key), value.ifEmpty { "-" }) }
        lines to (values.any { it.first == "firstname" } && ZkPassport.firstNameDropsParts(mrz))
    }

    /** The chip files of the stored passport [file]; null when its read lacks the SOD or DG1. */
    private suspend fun chip(file: StoredFile): ZkPassportChip? = withContext(Dispatchers.Default) {
        val dump = MrtdDump.decode(model.files.data(file.id)) ?: return@withContext null
        val sod = dump.file(LdsFile.SOD) ?: return@withContext null
        val dg1 = dump.file(LdsFile.DG1) ?: return@withContext null
        ZkPassportChip(sod, dg1, dump.file(LdsFile.DG2))
    }

    fun stop() {
        answer?.close()
        answer = null
        session?.close()
        session = null
        job?.cancel()
        job = null
    }

    private fun show(request: ZkPassportRequest, result: ZkPassportResult?, error: String?) {
        session = null
        ui.value = OfflineUi.ZkPassportVerified(request, result, error)
        val passed = result?.verified == true
        val failure = when {
            passed -> null
            error != null -> error
            result != null -> problems(result.errors).joinToString(tr(Res.string.sep_list))
            else -> tr(Res.string.zkp_no_result)
        }
        model.record(
            HistoryKind.VERIFIED, "zkPassport", null,
            listOf(tr(Res.string.zkp_document)),
            result?.let { claimNames(it) }.orEmpty(),
            tr(Res.string.zkp_history_note, ZkPassport.normalizeDomain(request.domain), request.purpose) +
                (if (request.devMode) tr(Res.string.zkp_history_test) else "") +
                (if (result?.viaVerifierApi == true) tr(Res.string.zkp_history_api) else ""),
            failure,
        )
    }

    private fun hostOf(url: String): String = runCatching { Url(url).host }.getOrDefault(url)

    companion object {
        /** How long a local network address may take to answer before the next one, or BLE, is tried. */
        private val PROBE_TIMEOUT = 3.seconds
        /** The whole answer over the local network; a phone's Wi-Fi carries a few hundred kilobytes in seconds. */
        private val SEND_TIMEOUT = 60.seconds

        /** Fields the setup screen offers; the document type and issuing country are always disclosed. */
        val OPTIONAL_FIELDS = listOf(
            ZkPassportField.FULLNAME, ZkPassportField.NATIONALITY, ZkPassportField.BIRTHDATE,
            ZkPassportField.EXPIRY_DATE, ZkPassportField.DOCUMENT_NUMBER, ZkPassportField.GENDER,
        )

        fun fieldTitle(field: ZkPassportField): String = when (field) {
            ZkPassportField.DOCUMENT_TYPE -> tr(Res.string.zkp_field_document_type)
            ZkPassportField.ISSUING_COUNTRY -> tr(Res.string.zkp_field_issuing_country)
            ZkPassportField.FULLNAME -> tr(Res.string.zkp_field_fullname)
            ZkPassportField.NATIONALITY -> tr(Res.string.zkp_field_nationality)
            ZkPassportField.BIRTHDATE -> tr(Res.string.zkp_field_birthdate)
            ZkPassportField.EXPIRY_DATE -> tr(Res.string.zkp_field_expiry_date)
            ZkPassportField.DOCUMENT_NUMBER -> tr(Res.string.zkp_field_document_number)
            ZkPassportField.GENDER -> tr(Res.string.zkp_field_gender)
        }

        /** A query key in words: the fields this wallet asks for, and the first name and surname others may ask. */
        fun keyTitle(key: String): String = when (key) {
            "firstname" -> tr(Res.string.zkp_field_firstname)
            "lastname" -> tr(Res.string.zkp_field_lastname)
            else -> ZkPassportField.entries.firstOrNull { it.key == key }?.let(::fieldTitle) ?: key
        }

        /** ISO 3166-1 alpha-3 codes from free text (commas, spaces or semicolons), or null when one is not a code. */
        fun countries(text: String): List<String>? {
            val codes = text.split(',', ' ', ';', '\n', '、', '，').map { it.trim().uppercase() }.filter { it.isNotEmpty() }
            if (codes.size > MAX_COUNTRIES || codes.any { !Regex("[A-Z]{3}").matches(it) }) return null
            return codes.distinct()
        }

        /** Why [domain] cannot be used, or null. */
        fun domainProblem(domain: String): String? {
            val d = ZkPassport.normalizeDomain(domain)
            return when {
                d.isEmpty() -> tr(Res.string.zkp_domain_missing)
                d.length > 253 || !Regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+").matches(d) -> tr(Res.string.zkp_domain_invalid)
                else -> null
            }
        }

        fun failure(code: String, detail: String?): String = when (code) {
            "unsupported_document" -> tr(Res.string.zkp_fail_unsupported)
            "proof_failed" -> tr(Res.string.zkp_fail_proof)
            "holder_error" -> tr(Res.string.zkp_fail_holder, detail.orEmpty())
            "connection" -> tr(Res.string.zkp_fail_connection)
            else -> tr(Res.string.zkp_fail_other, code)
        }

        /** The checker's error codes in words, each kind once. */
        fun problems(errors: List<String>): List<String> = errors.filterNot { e ->
            // A proof Barretenberg 5 keyed was never checked here, so it is not reported as invalid.
            e.startsWith("proof:") && errors.any { it.startsWith("backend_legacy:") }
        }.map { e ->
            when {
                e == "native_unavailable" -> tr(Res.string.zkp_err_native)
                e == "registry_unreachable" -> tr(Res.string.zkp_err_registry) + "\n" + tr(Res.string.zkp_offline_hint)
                e == "manifest_unavailable" || e == "circuit_unavailable" -> tr(Res.string.zkp_err_cdn) + "\n" + tr(Res.string.zkp_offline_hint)
                e.startsWith("certificate_root") -> tr(Res.string.zkp_err_certificate_root)
                e.startsWith("circuit_root") || e.startsWith("manifest") || e.startsWith("vkey:") -> tr(Res.string.zkp_err_circuit_root)
                e.startsWith("backend_legacy:") -> tr(Res.string.zkp_err_backend_legacy, e.substringAfter(':'))
                e == "verifier_api:rejected" -> tr(Res.string.zkp_err_api_rejected)
                e.startsWith("verifier_api:") -> tr(Res.string.zkp_err_api_unavailable, e.substringAfterLast(':'))
                e.startsWith("proof:") -> tr(Res.string.zkp_err_proof)
                e.startsWith("commitment:") -> tr(Res.string.zkp_err_commitment)
                e.startsWith("scope:") -> tr(Res.string.zkp_err_scope)
                e.startsWith("date_expired") -> tr(Res.string.zkp_err_date_expired)
                e.startsWith("date_future") -> tr(Res.string.zkp_err_date_future)
                e == "mock" -> tr(Res.string.zkp_err_mock)
                e.startsWith("verification_method:") -> tr(Res.string.zkp_err_verification_method, e.substringAfter(':'))
                e == "oprf_key" -> tr(Res.string.zkp_err_oprf_key)
                e == "nullifier_mismatch" -> tr(Res.string.zkp_err_nullifier)
                e.startsWith("facematch_level:") -> tr(Res.string.zkp_err_facematch_level, faceKind(e.substringAfter(':')))
                e == "facematch_root" -> tr(Res.string.zkp_err_facematch_root)
                e == "facematch_app" -> tr(Res.string.zkp_err_facematch_app)
                e == "facematch_environment" -> tr(Res.string.zkp_err_facematch_environment)
                e == "query:facematch" -> tr(Res.string.zkp_err_facematch_mode)
                e.startsWith("parameters:") || e.startsWith("facematch") -> tr(Res.string.zkp_err_facematch)
                e.startsWith("query") || e.startsWith("missing:") -> tr(Res.string.zkp_err_query)
                else -> tr(Res.string.zkp_err_bundle)
            }
        }.distinct()

        /** What the proofs establish, one line each, as committed to by the proofs. */
        /** The names of what [r] disclosed or proved, without the values: what the history log keeps. */
        fun claimNames(r: ZkPassportResult): List<String> = buildList {
            r.disclosed?.let { d ->
                if (d.documentCode != null) add(fieldTitle(ZkPassportField.DOCUMENT_TYPE))
                if (d.issuingCountry != null) add(fieldTitle(ZkPassportField.ISSUING_COUNTRY))
                if (d.nationality != null) add(fieldTitle(ZkPassportField.NATIONALITY))
                if (!d.lastName.isNullOrEmpty() || !d.givenNames.isNullOrEmpty()) add(fieldTitle(ZkPassportField.FULLNAME))
                if (d.birthdate != null) add(fieldTitle(ZkPassportField.BIRTHDATE))
                if (d.expiryDate != null) add(fieldTitle(ZkPassportField.EXPIRY_DATE))
                if (d.documentNumber != null) add(fieldTitle(ZkPassportField.DOCUMENT_NUMBER))
                if (d.gender != null) add(fieldTitle(ZkPassportField.GENDER))
            }
            if ((r.minAge ?: 0) > 0 || r.maxAge?.takeIf { it in 1..149 } != null) add(tr(Res.string.zkp_field_age))
            if (r.nationalityIn.isNotEmpty() || r.nationalityOut.isNotEmpty()) add(fieldTitle(ZkPassportField.NATIONALITY))
            if (r.issuingCountryIn.isNotEmpty() || r.issuingCountryOut.isNotEmpty()) add(fieldTitle(ZkPassportField.ISSUING_COUNTRY))
            if (r.boundData != null) add(tr(Res.string.zkp_field_bound))
            if (r.faceMatch != null) add(tr(Res.string.zkp_field_facematch))
        }.distinct()

        fun claims(r: ZkPassportResult): List<String> = buildList {
            r.disclosed?.let { d ->
                d.documentCode?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.DOCUMENT_TYPE), it)) }
                d.issuingCountry?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.ISSUING_COUNTRY), it)) }
                d.nationality?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.NATIONALITY), it)) }
                listOfNotNull(d.lastName, d.givenNames).filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }?.let {
                    add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.FULLNAME), it.joinToString(", ")))
                }
                d.birthdate?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.BIRTHDATE), it)) }
                d.expiryDate?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.EXPIRY_DATE), it)) }
                d.documentNumber?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.DOCUMENT_NUMBER), it)) }
                d.gender?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.GENDER), it)) }
            }
            val min = r.minAge
            val max = r.maxAge?.takeIf { it in 1..149 }
            when {
                min != null && min > 0 && max != null -> add(tr(Res.string.zkp_age_between, min, max))
                min != null && min > 0 -> add(tr(Res.string.zkp_age_at_least, min))
                max != null -> add(tr(Res.string.zkp_age_below, max))
            }
            val sep = tr(Res.string.sep_list)
            if (r.nationalityIn.isNotEmpty()) add(tr(Res.string.zkp_nationality_in, r.nationalityIn.joinToString(sep)))
            if (r.nationalityOut.isNotEmpty()) add(tr(Res.string.zkp_nationality_out, r.nationalityOut.joinToString(sep)))
            if (r.issuingCountryIn.isNotEmpty()) add(tr(Res.string.zkp_issuing_in, r.issuingCountryIn.joinToString(sep)))
            if (r.issuingCountryOut.isNotEmpty()) add(tr(Res.string.zkp_issuing_out, r.issuingCountryOut.joinToString(sep)))
            r.boundData?.let { add(tr(Res.string.zkp_bound, it)) }
            r.faceMatch?.let { add(tr(Res.string.zkp_facematch_line, faceMode(it.strict), faceKind(it.kind))) }
        }

        /** A FaceMatch kind in words. */
        fun faceKind(kind: String): String = when (kind) {
            ZkPassportFaceMatchKind.OFFICIAL -> tr(Res.string.zkp_facematch_kind_official)
            ZkPassportFaceMatchKind.KEY_ATTESTATION -> tr(Res.string.zkp_facematch_kind_keyattest)
            ZkPassportFaceMatchKind.SELF -> tr(Res.string.zkp_facematch_kind_self)
            else -> kind
        }

        fun faceMode(strict: Boolean): String = tr(if (strict) Res.string.zkp_facematch_mode_strict else Res.string.zkp_facematch_mode_regular)

        /** Who vouches for a verified FaceMatch proof and what it leaves open, one line each. */
        fun faceCaveats(f: ZkPassportFaceMatch): List<String> = buildList {
            when (f.kind) {
                ZkPassportFaceMatchKind.OFFICIAL -> add(tr(Res.string.zkp_facematch_official_note, f.platform ?: "-"))
                ZkPassportFaceMatchKind.KEY_ATTESTATION -> {
                    add(tr(Res.string.zkp_facematch_keyattest_note, f.appId ?: "-"))
                    when (f.environment) {
                        "production" -> add(tr(Res.string.zkp_facematch_env_production))
                        "self_signed" -> add(tr(Res.string.zkp_facematch_env_self_signed))
                        else -> add(tr(Res.string.zkp_facematch_env_development))
                    }
                }
                else -> add(tr(Res.string.zkp_facematch_self_note, f.appId ?: "-"))
            }
        }

        /**
         * The apps of the setting's text (one per line: package name, then signing certificate digests) and the
         * lines that do not read as one.
         */
        fun faceApps(text: String): Pair<List<ZkPassportFaceMatchApp>, List<String>> {
            val apps = ArrayList<ZkPassportFaceMatchApp>()
            val bad = ArrayList<String>()
            for (line in text.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
                val parts = line.split(' ', ',', ';', '\t').filter { it.isNotEmpty() }
                val signers = parts.drop(1).map { it.replace(":", "").lowercase() }
                val named = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+").matches(parts[0]) && parts[0].length <= MAX_APP_ID
                if (named && signers.isNotEmpty() && signers.all { Regex("[0-9a-f]{64}").matches(it) }) apps.add(ZkPassportFaceMatchApp(parts[0], signers))
                else bad.add(line)
            }
            return apps to bad
        }

        /** The trust line of a passed check (docs/design/zkpassport.md 4.3): T2 when every key is an anchor. */
        fun trust(check: ZkPassportCscaCheck?): String {
            val sep = tr(Res.string.sep_list)
            val line = when {
                check == null -> tr(Res.string.zkp_trust_registry)
                check.allAnchored -> tr(Res.string.zkp_trust_anchored, check.countries.joinToString(sep))
                check.error != null -> tr(Res.string.zkp_trust_unchecked, if (check.error == "certificates_root") tr(Res.string.zkp_err_certificates_root) else tr(Res.string.zkp_err_certificates))
                else -> tr(Res.string.zkp_trust_partial, check.countries.joinToString(sep), check.inPackage, check.anchored)
            }
            return if (check != null && check.error == null && check.expired > 0) line + " " + tr(Res.string.zkp_trust_expired, check.expired) else line
        }

        /**
         * Why this wallet cannot answer [incoming], or null: modes other than fast are not offered, and a FaceMatch
         * needs a requester that takes this project's proofs and, with [canCompare], a camera screen on this device.
         */
        fun unsupported(incoming: ZkPassportIncoming, canCompare: Boolean = false): String? = when {
            !incoming.fastMode -> tr(Res.string.zkp_answer_unsupported_mode, incoming.mode.ifEmpty { "-" })
            incoming.faceMatchMode == null -> null
            incoming.faceMatchKinds.isEmpty() -> tr(Res.string.zkp_answer_unsupported_facematch)
            !canCompare -> tr(Res.string.zkp_answer_unsupported_facematch_device)
            else -> null
        }

        /** How this wallet would answer the FaceMatch of [incoming], for the consent screen; empty without one. */
        fun faceNotes(incoming: ZkPassportIncoming): List<String> {
            val mode = incoming.faceMatchMode ?: return emptyList()
            val kinds = incoming.faceMatchKinds
            return buildList {
                add(tr(if (mode == "strict") Res.string.zkp_answer_facematch_strict else Res.string.zkp_answer_facematch_regular))
                add(tr(Res.string.zkp_answer_facematch_private))
                if (ZkPassportFaceMatchKind.KEY_ATTESTATION in kinds) add(tr(Res.string.zkp_answer_facematch_keyattest))
                if (ZkPassportFaceMatchKind.SELF in kinds) add(tr(Res.string.zkp_answer_facematch_self))
            }
        }

        /** What a request's query asks for, one line each, in the order of the query. */
        fun asks(query: JsonObject): List<String> = buildList {
            for ((key, value) in query) {
                val o = value as? JsonObject
                val field = ZkPassportField.entries.firstOrNull { it.key == key }
                when {
                    key == "age" && o != null -> {
                        val gte = (o["gte"] as? JsonPrimitive)?.intOrNull
                        val lt = (o["lt"] as? JsonPrimitive)?.intOrNull
                        when {
                            gte != null && o.size == 1 -> add(tr(Res.string.zkp_age_at_least, gte))
                            lt != null && o.size == 1 -> add(tr(Res.string.zkp_age_below, lt))
                            else -> add(tr(Res.string.zkp_answer_ask_condition, tr(Res.string.zkp_answer_age)))
                        }
                    }
                    key == "bind" && o != null -> {
                        val data = (o["custom_data"] as? JsonPrimitive)?.contentOrNull
                        if (data != null) add(tr(Res.string.zkp_bound, data))
                        if (o.keys.any { it != "custom_data" }) add(tr(Res.string.zkp_answer_ask_other, key))
                    }
                    key == "sanctions" -> add(tr(Res.string.zkp_answer_ask_sanctions))
                    key == "facematch" -> add(tr(Res.string.zkp_answer_ask_facematch))
                    o != null -> {
                        val title = field?.let(::fieldTitle) ?: keyTitle(key)
                        if ((o["disclose"] as? JsonPrimitive)?.contentOrNull == "true") add(tr(Res.string.zkp_answer_ask_disclose, title))
                        if (o.keys.any { it != "disclose" }) add(tr(Res.string.zkp_answer_ask_condition, title))
                    }
                    else -> add(tr(Res.string.zkp_answer_ask_other, key))
                }
            }
        }

        /** An answer's failure code in words. */
        /** The prover's address for [target]; null on this device. */
        fun targetAddress(target: ZkPassportProverTarget): String? = when (target) {
            ZkPassportProverTarget.Device -> null
            is ZkPassportProverTarget.Host -> target.url
            is ZkPassportProverTarget.Paired -> target.prover.url
        }

        fun answerFailure(code: String): String = when {
            code == "remote_unreachable" -> tr(Res.string.zkp_answer_err_remote_unreachable)
            code == "remote_unauthorized" || code == "pairing_lost" -> tr(Res.string.zkp_answer_err_remote_auth)
            code == "remote_busy" -> tr(Res.string.zkp_answer_err_remote_busy)
            code == "remote_unavailable" -> tr(Res.string.zkp_answer_err_remote_unavailable)
            code == "remote_lost" -> tr(Res.string.zkp_answer_err_remote_lost)
            code == "pairing_link" -> tr(Res.string.zkp_pair_err_link)
            code == "pairing_used" -> tr(Res.string.zkp_pair_err_used)
            code == "pairing_refused" -> tr(Res.string.zkp_pair_err_refused)
            code == "bridge_origin" -> tr(Res.string.zkp_answer_err_origin)
            code == "bridge_unknown_request" -> tr(Res.string.zkp_answer_err_unknown_request)
            code.startsWith("bridge_origin:") -> tr(Res.string.zkp_answer_err_origin) + "\n" + tr(Res.string.zkp_answer_err_reason, code.substringAfter(':'))
            code == "connection" -> tr(Res.string.zkp_fail_connection)
            code == "passport" -> tr(Res.string.zkp_answer_err_passport)
            code == "facematch_unsupported" -> tr(Res.string.zkp_answer_unsupported_facematch)
            code == "facematch_unavailable" -> tr(Res.string.zkp_answer_unsupported_facematch_device)
            code == "facematch_remote" -> tr(Res.string.zkp_answer_err_facematch_remote)
            code == "facematch_photo" -> tr(Res.string.zkp_answer_err_facematch_photo)
            code == "facematch_model" -> tr(Res.string.zkp_answer_err_facematch_model)
            code == "facematch_cancelled" -> tr(Res.string.zkp_answer_err_facematch_cancelled)
            code == "facematch_no_match" -> tr(Res.string.zkp_answer_err_facematch_no_match)
            code.startsWith("facematch_mismatch:") -> code.split(':').let { tr(Res.string.zkp_answer_err_facematch_mismatch, it.getOrElse(1) { "-" }, it.getOrElse(2) { "-" }) }
            code == "facematch_liveness" -> tr(Res.string.zkp_answer_err_facematch_liveness)
            code == "facematch_timeout" -> tr(Res.string.zkp_answer_err_facematch_timeout)
            code == "facematch_attestation" -> tr(Res.string.zkp_answer_err_facematch_attestation)
            code.startsWith("facematch") -> tr(Res.string.zkp_answer_err_facematch, code)
            code == "native_unavailable" -> tr(Res.string.zkp_answer_no_engine)
            code == "crs_missing" -> tr(Res.string.zkp_answer_err_crs)
            code == "inputs" -> tr(Res.string.zkp_answer_err_inputs)
            code.startsWith("inputs:") -> tr(Res.string.zkp_answer_err_inputs) + "\n" + tr(Res.string.zkp_answer_err_reason, code.substringAfter(':'))
            code.startsWith("nearby") -> tr(Res.string.zkp_answer_err_nearby, code)
            code.startsWith("registry") -> tr(Res.string.zkp_err_registry) + "\n" + tr(Res.string.zkp_offline_hint)
            code == "manifest_unavailable" || code == "circuit_unavailable" -> tr(Res.string.zkp_err_cdn) + "\n" + tr(Res.string.zkp_offline_hint)
            code == "certificates_unavailable" -> tr(Res.string.zkp_answer_err_certificates)
            code.endsWith("_root") || code.startsWith("vkey:") -> tr(Res.string.zkp_answer_err_circuit)
            else -> tr(Res.string.zkp_answer_err_other, code)
        }

        const val MAX_COUNTRIES = 200
        /** The longest package name the circuits take. */
        const val MAX_APP_ID = 100
    }
}

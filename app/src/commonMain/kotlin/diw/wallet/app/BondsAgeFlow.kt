package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.AnimatedQrTransport
import diw.wallet.core.profile.bonds.postFirst
import diw.wallet.core.profile.bonds.postFirstFrom
import diw.wallet.core.profile.bonds.BondsAgeCredential
import diw.wallet.core.profile.bonds.BondsAgeMaterial
import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVcCredential
import diw.wallet.core.zk.OpenAcAgeInput
import diw.wallet.core.zk.ZkResult
import io.ktor.client.request.accept
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.multipaz.document.Document
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/** A card that can answer a Bonds age request: a TWDIW card with a birth date disclosure, or the national ID card. */
data class AgeCard(
    val name: String,
    val source: BondsCredentialSource,
    /** The birth date claim the circuit reads. */
    val claim: String,
    val document: Document? = null,
    val credential: W3cVcCredential? = null,
    val moica: MoicaSignedCredential? = null,
)

/**
 * Answers a Bonds age request (BondsAgeRequest) with an OpenAC proof: the holder picks a card, the proof is produced
 * and checked on this device, then posted to the response address, or for a nearby request sent over the Bonds BLE
 * link (or shown as an animated QR) to the verifier's phone, with the verdict shown. Only the two proofs, the statement and the issuer DID leave
 * the device; the history records the statement, never a value.
 */
class BondsAgeFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var job: Job? = null
    private var scanned: CompletableDeferred<String?>? = null
    private val client by lazy { model.http.config { followRedirects = false } }

    fun start(text: String) {
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working(tr(Res.string.age_reading_request))
        model.scope.launch {
            ui.value = try {
                val verifier = model.taiwan.ageVerifier
                val request = BondsAgeRequest.parse(text, verifier.insecureHosts())
                val cards = cards(request.source)
                // Asked before proving, so a permission prompt does not come after the wait.
                val link = model.platform.bondsLink
                val linkProblem = when {
                    !request.nearby || cards.isEmpty() -> null
                    link == null -> NO_LINK
                    else -> link.unavailableReason()?.let { tr(Res.string.age_ble_unavailable_rescan, it) }
                }?.takeUnless { request.qr } // the animated QR does not need the radio
                when {
                    !request.isFresh(Clock.System.now()) -> OfflineUi.Failed(EXPIRED)
                    cards.isEmpty() -> OfflineUi.Failed(noCard(request.source))
                    linkProblem != null -> OfflineUi.Failed(linkProblem)
                    else -> OfflineUi.AgeChoose(request, cards, known(request))
                }
            } catch (e: Exception) {
                OfflineUi.Failed(tr(Res.string.age_request_unreadable) + model.describe(e))
            }
        }
    }

    private suspend fun cards(source: BondsCredentialSource): List<AgeCard> = when (source) {
        BondsCredentialSource.SELF_ISSUED -> model.files.nationalIdCards().mapNotNull { (_, card) ->
            card.takeIf { c -> BondsOfflinePresentation.disclosableClaims(c).any { it.first == "birthdate" } }
                ?.let { AgeCard(TaiwanModel.NATIONAL_ID_NAME, source, "birthdate", moica = it) }
        }
        else -> model.taiwan.twdiwDocuments(model.documents.value).mapNotNull { doc ->
            doc.getCertifiedCredentials().filterIsInstance<W3cVcCredential>()
                .firstOrNull { it.encoding == W3cEncoding.SD_JWT && it.keyBound }
                ?.let { c -> BondsAgeCredential.birthClaim(c.raw)?.let { AgeCard(doc.displayName ?: tr(Res.string.tw_card_fallback), source, it, doc, c) } }
        }
    }

    private fun jobId(request: BondsAgeRequest) = "bonds-age-" + request.requestId

    /** Bonds' own list, or the user's age host, which is as known; a nearby verifier is the person in front of the holder. */
    private fun known(request: BondsAgeRequest): Boolean = request.nearby || request.lan || request.knownHost ||
        model.taiwan.ageVerifier.host()?.let { runCatching { Url(it).host }.getOrNull() } == request.responseHost

    /** Produces and sends the proof; [extended] is the user's choice to produce it here against the advice. */
    fun prove(request: BondsAgeRequest, card: AgeCard, extended: Boolean) {
        val prover = model.platform.zk?.ageProver
        if (prover == null) {
            ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.age_cannot_prove), listOf(tr(Res.string.age_no_engine)), retry = false)
            return
        }
        val id = jobId(request)
        model.zk.clear(id)
        ui.value = OfflineUi.AgeWorking(request, card, id)
        job?.cancel()
        job = model.scope.launch {
            val failure = try {
                val (material, signature) = try {
                    withContext(model.unlockProvider) {
                        val holder = holderKey(card)
                        material(card, holder) to BondsAgeCredential.deviceSignature(request.nonce, holder)
                    }
                } finally {
                    model.endOperation()
                }
                // Keyed by the stored card, not the per-request derivative, so a self-issued card reuses its Prepare too.
                val stored = card.moica?.serialized() ?: card.credential!!.raw
                val input = OpenAcAgeInput(material.sdJwt, material.issuerKeyX, material.issuerKeyY, request.nonce, signature,
                    cacheKey = card.source.wire + ":" + stored) { request.cutoffValue(it) }
                when (val r = model.zk.prove(id, ZkProofKind.AGE, extended) { step -> prover.prove(input, step) }.await()) {
                    is ZkResult.Ok -> send(request, card, material, r.value)
                    is ZkResult.Failed -> {
                        ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.age_cannot_prove), listOf(r.reason), r.retryable)
                        r.reason
                    }
                    ZkResult.Cancelled -> {
                        ui.value = OfflineUi.AgeChoose(request, cards(request.source), known(request))
                        return@launch
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val reason = model.describe(e)
                ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.age_cannot_prove), listOf(reason), retry = true)
                reason
            }
            record(request, card, failure)
        }
    }

    /** Stops the running proof and returns to the card choice. */
    fun cancel(state: OfflineUi.AgeWorking) {
        stop()
        model.scope.launch { ui.value = OfflineUi.AgeChoose(state.request, cards(state.request.source), known(state.request)) }
    }

    /** Stops whatever runs, when the screen is left. */
    fun stop() {
        (ui.value as? OfflineUi.AgeWorking)?.let { model.zk.cancel(it.jobId) }
        job?.cancel()
        job = null
    }

    /** Posts the proof and shows the verdict; returns the failure for the history, or null when accepted. */
    internal suspend fun send(request: BondsAgeRequest, card: AgeCard, material: BondsAgeMaterial, proof: diw.wallet.core.zk.OpenAcAgeProof): String? {
        val now = Clock.System.now()
        if (!request.isFresh(now)) {
            ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.zktls_expired), listOf(EXPIRED, tr(Res.string.age_proof_not_sent)), retry = false)
            return EXPIRED
        }
        val pkg = BondsAgePackage(request, proof.claimName, proof.claimFormat, material.issuerDid, proof.prepareProof, proof.showProof,
            proof.prepareMs, proof.showMs, now)
        ui.value = OfflineUi.AgeWorking(request, card, jobId(request), sending = true)
        val timing = tr(Res.string.age_proof_time, seconds(proof.prepareMs + proof.showMs))
        val who = who(request)
        var reached: String? = null
        val (status, body) = try {
            val lan = model.platform.bondsLan?.takeIf { request.lan }
            if (request.nearby) HttpStatusCode.OK to (nearby(request, card, pkg) ?: run {
                ui.value = OfflineUi.AgeResult(request, card, true, tr(Res.string.age_qr_shown), listOf(
                    tr(Res.string.age_qr_verify_there), tr(Res.string.age_nothing_else), timing,
                ), retry = false)
                return null
            })
            // A socket of its own: Android release builds refuse clear text in their HTTP stacks.
            else if (lan != null) lan.postFirstFrom(request.lanUrls.ifEmpty { listOf(request.responseUrl!!) }, pkg.encode().encodeToByteArray(), SEND_TIMEOUT)
                .let { (code, text, url) -> reached = url; HttpStatusCode.fromValue(code) to text }
            else withTimeout(SEND_TIMEOUT) {
                val response = client.post(request.responseUrl!!) {
                    contentType(ContentType.Application.Json)
                    accept(ContentType.Application.Json)
                    setBody(pkg.encode())
                }
                response.status to response.bodyAsText()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            val reason = if (request.nearby) tr(Res.string.age_ble_send_incomplete, model.describe(e))
            else if (request.lan) tr(Res.string.age_lan_send_failed, who, model.describe(e))
            else tr(Res.string.age_send_failed, who)
            ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.age_not_sent), listOf(reason), retry = true)
            return reason
        }
        if (request.nearby && body.isEmpty()) {
            ui.value = OfflineUi.AgeResult(request, card, true, tr(Res.string.age_delivered), listOf(
                tr(Res.string.age_no_verdict),
                tr(Res.string.age_nothing_else), timing,
            ), retry = false)
            return null
        }
        val verdict = BondsAgeVerdict.parse(body)
        return when {
            verdict?.accepted == true -> {
                ui.value = OfflineUi.AgeResult(request, card, true, tr(Res.string.age_accepted_by, who),
                    listOfNotNull(tr(Res.string.age_confirmed_over, verdict.minimumAge ?: request.minimumAge), timing,
                        verdict.verifyMs?.let { tr(Res.string.age_verifier_time, seconds(it)) }, reached?.let { tr(Res.string.age_via_lan) + LanDetails.hostPort(it) }), retry = false)
                null
            }
            verdict != null -> {
                val reason = verdict.reason?.takeIf { it.isNotBlank() } ?: verdict.status
                // A 5xx verdict is the verifier's own failure (its backend down), not a judgement of the proof.
                ui.value = if (status.value >= 500) OfflineUi.AgeResult(request, card, false, tr(Res.string.age_unavailable_at, who),
                    listOf(tr(Res.string.age_their_reason, reason), tr(Res.string.age_verifier_fault), timing), retry = false)
                else OfflineUi.AgeResult(request, card, false, tr(Res.string.age_rejected_by, who), listOf(tr(Res.string.age_their_reason, reason), timing), retry = false)
                reason
            }
            status.isSuccess() -> {
                val reason = tr(Res.string.age_unreadable_reply, who)
                ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.age_unknown_result), listOf(reason), retry = false)
                reason
            }
            else -> {
                val text = body.filter { !it.isISOControl() }.take(200).ifBlank { "HTTP ${status.value}" }
                ui.value = OfflineUi.AgeResult(request, card, false, tr(Res.string.age_rejected_by, who), listOf(tr(Res.string.age_their_reason, text)), retry = false)
                text
            }
        }
    }

    /**
     * Sends the package over the verifier's one-time BLE service and waits for its verdict, which the verifier's phone
     * reaches by checking the proofs itself; the reply is read as an HTTP 200 body would be. An empty body: the
     * verifier (Bonds) only confirmed receipt. When the verifier can also scan an animated QR, it is shown at the same
     * time and stays up if Bluetooth fails; null when the holder said the verifier finished scanning it ([qrDone]).
     */
    private suspend fun nearby(request: BondsAgeRequest, card: AgeCard, pkg: BondsAgePackage): String? {
        val link = model.platform.bondsLink
        val bytes = pkg.encode().encodeToByteArray()
        val id = jobId(request)
        fun update(change: (OfflineUi.AgeWorking) -> OfflineUi.AgeWorking) {
            (ui.value as? OfflineUi.AgeWorking)?.takeIf { it.jobId == id }?.let { ui.value = change(it) }
        }
        if (!request.qr) {
            if (link == null) throw ProtocolException("unsupported", NO_LINK)
            val reply = link.exchange(request.linkServiceId!!, bytes) { text -> update { it.copy(link = text) } }
                ?: throw ProtocolException("link_failed", tr(Res.string.age_no_reply))
            return reply.decodeToString()
        }
        val done = CompletableDeferred<String?>()
        scanned = done
        update { it.copy(qr = AnimatedQrTransport.Encoder(bytes)) }
        model.platform.keepScreenOn(true)
        return try {
            coroutineScope {
                val viaLink = launch {
                    val problem = if (link == null) tr(Res.string.age_no_peripheral) else link.unavailableReason()
                    if (link == null || problem != null) {
                        update { it.copy(link = tr(Res.string.age_ble_use_qr, problem)) }
                        return@launch
                    }
                    val reply = try {
                        link.exchange(request.linkServiceId!!, bytes) { text -> update { it.copy(link = text) } }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        null
                    }
                    if (reply != null) done.complete(reply.decodeToString())
                    else update { it.copy(link = tr(Res.string.age_ble_not_connected)) }
                }
                done.await().also { viaLink.cancel() }
            }
        } finally {
            scanned = null
            model.platform.keepScreenOn(false)
        }
    }

    /** The verifier finished scanning the animated QR: stop showing it and Bluetooth. */
    fun qrDone() {
        scanned?.complete(null)
    }

    /** Who the proof goes to, for the screens and the history. */
    private fun who(request: BondsAgeRequest): String = when {
        request.nearby -> NEARBY
        request.lan -> tr(Res.string.age_lan_verifier_name)
        else -> request.responseHost!!
    }

    private suspend fun holderKey(card: AgeCard): HolderKey = when (card.source) {
        BondsCredentialSource.SELF_ISSUED -> model.holderIdentities.find(HolderIdentities.BONDS_SELF_ISSUED)
        else -> {
            val cred = card.credential!!
            cred.holderPublicKey()?.let { model.holderIdentities.findByPublicKey(it) }
                ?: cred.secureArea?.let { area -> cred.alias?.let { HolderKey(area, area.getKeyInfo(it), cred.sharedKey, cred.holderDid) } }
                ?: model.holderIdentities.find(HolderIdentities.TWDIW)
        }
    } ?: throw ProtocolException("credential_unavailable", tr(Res.string.age_no_card_key))

    private suspend fun material(card: AgeCard, holder: HolderKey): BondsAgeMaterial = when (card.source) {
        BondsCredentialSource.SELF_ISSUED -> BondsAgeCredential.selfIssued(card.moica!!, holder, Clock.System.now())
        else -> BondsAgeCredential.twdiw(card.credential!!.raw, model.didResolver())
    }

    private fun record(request: BondsAgeRequest, card: AgeCard, failure: String?) {
        model.record(
            HistoryKind.PRESENTED, who(request), null, listOf(card.name), listOf(tr(Res.string.age_over_n, request.minimumAge)),
            tr(Res.string.age_note_start) + (when {
                request.nearby && request.qr -> tr(Res.string.age_note_nearby_qr)
                request.nearby -> tr(Res.string.age_note_nearby)
                request.lan -> tr(Res.string.age_note_lan)
                else -> tr(Res.string.age_note_online)
            }) +
                tr(Res.string.age_note_end, request.purpose.ifEmpty { tr(Res.string.age_unstated) }), failure,
        )
    }

    private fun seconds(ms: Long) = (ms / 100) / 10.0

    companion object {
        val SEND_TIMEOUT = 90.seconds
        val EXPIRED: String get() = tr(Res.string.age_request_expired)
        val NEARBY: String get() = tr(Res.string.age_nearby_verifier)
        val NO_LINK: String get() = tr(Res.string.age_no_link)

        fun noCard(source: BondsCredentialSource): String = when (source) {
            BondsCredentialSource.SELF_ISSUED ->
                tr(Res.string.age_needs_bonds_id)
            else -> tr(Res.string.age_needs_gov_card)
        }
    }
}

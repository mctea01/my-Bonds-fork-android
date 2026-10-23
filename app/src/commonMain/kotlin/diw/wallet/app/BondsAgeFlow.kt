package diw.wallet.app

import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.profile.bonds.AnimatedQrTransport
import diw.wallet.core.profile.bonds.postFirst
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
        ui.value = OfflineUi.Working("讀取年齡證明請求")
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
                    else -> link.unavailableReason()?.let { "藍牙無法使用：$it。處理後請再掃描一次。" }
                }?.takeUnless { request.qr } // the animated QR does not need the radio
                when {
                    !request.isFresh(Clock.System.now()) -> OfflineUi.Failed(EXPIRED)
                    cards.isEmpty() -> OfflineUi.Failed(noCard(request.source))
                    linkProblem != null -> OfflineUi.Failed(linkProblem)
                    else -> OfflineUi.AgeChoose(request, cards, known(request))
                }
            } catch (e: Exception) {
                OfflineUi.Failed("無法讀取年齡證明請求：" + model.describe(e))
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
                ?.let { c -> BondsAgeCredential.birthClaim(c.raw)?.let { AgeCard(doc.displayName ?: "數位憑證", source, it, doc, c) } }
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
            ui.value = OfflineUi.AgeResult(request, card, false, "無法產生證明", listOf("這個版本沒有年齡零知識證明引擎。"), retry = false)
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
                        ui.value = OfflineUi.AgeResult(request, card, false, "無法產生證明", listOf(r.reason), r.retryable)
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
                ui.value = OfflineUi.AgeResult(request, card, false, "無法產生證明", listOf(reason), retry = true)
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
            ui.value = OfflineUi.AgeResult(request, card, false, "請求已過期", listOf(EXPIRED, "證明已產生但沒有送出。"), retry = false)
            return EXPIRED
        }
        val pkg = BondsAgePackage(request, proof.claimName, proof.claimFormat, material.issuerDid, proof.prepareProof, proof.showProof,
            proof.prepareMs, proof.showMs, now)
        ui.value = OfflineUi.AgeWorking(request, card, jobId(request), sending = true)
        val timing = "產生證明 ${seconds(proof.prepareMs + proof.showMs)} 秒"
        val who = who(request)
        val (status, body) = try {
            val lan = model.platform.bondsLan?.takeIf { request.lan }
            if (request.nearby) HttpStatusCode.OK to (nearby(request, card, pkg) ?: run {
                ui.value = OfflineUi.AgeResult(request, card, true, "已出示動態 QR Code", listOf(
                    "對方掃描後在自己的手機驗證，結果以對方手機的畫面為準。", "對方沒有收到出生日期或其他欄位。", timing,
                ), retry = false)
                return null
            })
            // A socket of its own: Android release builds refuse clear text in their HTTP stacks.
            else if (lan != null) lan.postFirst(request.lanUrls.ifEmpty { listOf(request.responseUrl!!) }, pkg.encode().encodeToByteArray(), SEND_TIMEOUT).let { (code, text) -> HttpStatusCode.fromValue(code) to text }
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
            val reason = if (request.nearby) "藍牙傳送沒有完成（${model.describe(e)}），請靠近對方的手機後重試。"
            else if (request.lan) "無法把證明送到 $who（${model.describe(e)}），請確認兩支手機連在同一個 Wi-Fi（或熱點）後重試。"
            else "無法把證明送到 $who，請檢查網路後重試。"
            ui.value = OfflineUi.AgeResult(request, card, false, "沒有送出", listOf(reason), retry = true)
            return reason
        }
        if (request.nearby && body.isEmpty()) {
            ui.value = OfflineUi.AgeResult(request, card, true, "證明已送達對方手機", listOf(
                "對方只確認收到，沒有回傳查驗結果（Bonds App 就是如此），結果以對方手機的畫面為準。",
                "對方沒有收到出生日期或其他欄位。", timing,
            ), retry = false)
            return null
        }
        val verdict = BondsAgeVerdict.parse(body)
        return when {
            verdict?.accepted == true -> {
                ui.value = OfflineUi.AgeResult(request, card, true, "$who 已接受證明",
                    listOfNotNull("查驗方確認你年滿 ${verdict.minimumAge ?: request.minimumAge} 歲，沒有收到出生日期或其他欄位。", timing,
                        verdict.verifyMs?.let { "查驗方驗證 ${seconds(it)} 秒" }), retry = false)
                null
            }
            verdict != null -> {
                val reason = verdict.reason?.takeIf { it.isNotBlank() } ?: verdict.status
                // A 5xx verdict is the verifier's own failure (its backend down), not a judgement of the proof.
                ui.value = if (status.value >= 500) OfflineUi.AgeResult(request, card, false, "$who 暫時無法驗證",
                    listOf("對方的說明：$reason", "證明已送達，是查驗方網站的問題；請對方稍後重新產生 QR Code 再試。", timing), retry = false)
                else OfflineUi.AgeResult(request, card, false, "$who 沒有接受證明", listOf("對方的說明：$reason", timing), retry = false)
                reason
            }
            status.isSuccess() -> {
                val reason = "$who 的回應無法讀取。"
                ui.value = OfflineUi.AgeResult(request, card, false, "結果不明", listOf(reason), retry = false)
                reason
            }
            else -> {
                val text = body.filter { !it.isISOControl() }.take(200).ifBlank { "HTTP ${status.value}" }
                ui.value = OfflineUi.AgeResult(request, card, false, "$who 沒有接受證明", listOf("對方的說明：$text"), retry = false)
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
                ?: throw ProtocolException("link_failed", "對方沒有回覆結果")
            return reply.decodeToString()
        }
        val done = CompletableDeferred<String?>()
        scanned = done
        update { it.copy(qr = AnimatedQrTransport.Encoder(bytes)) }
        model.platform.keepScreenOn(true)
        return try {
            coroutineScope {
                val viaLink = launch {
                    val problem = if (link == null) "這支手機無法以藍牙周邊模式傳送" else link.unavailableReason()
                    if (link == null || problem != null) {
                        update { it.copy(link = "藍牙無法使用（$problem），請讓對方掃描動態 QR Code。") }
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
                    else update { it.copy(link = "藍牙沒有連上，請讓對方掃描動態 QR Code。") }
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
        request.lan -> "區網查驗方 ${request.responseHost}"
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
    } ?: throw ProtocolException("credential_unavailable", "找不到這張卡片的持有者金鑰")

    private suspend fun material(card: AgeCard, holder: HolderKey): BondsAgeMaterial = when (card.source) {
        BondsCredentialSource.SELF_ISSUED -> BondsAgeCredential.selfIssued(card.moica!!, holder, Clock.System.now())
        else -> BondsAgeCredential.twdiw(card.credential!!.raw, model.didResolver())
    }

    private fun record(request: BondsAgeRequest, card: AgeCard, failure: String?) {
        model.record(
            HistoryKind.PRESENTED, who(request), null, listOf(card.name), listOf("年滿 ${request.minimumAge} 歲"),
            "年齡零知識證明（" + (when {
                request.nearby && request.qr -> "藍牙或動態 QR Code 直接傳給對方手機，不經伺服器"
                request.nearby -> "藍牙直接傳給對方手機，不經伺服器"
                request.lan -> "區網直接傳給對方手機，不經伺服器"
                else -> "Bonds 線上查驗"
            }) +
                "），用途：${request.purpose.ifEmpty { "未說明" }}", failure,
        )
    }

    private fun seconds(ms: Long) = (ms / 100) / 10.0

    companion object {
        val SEND_TIMEOUT = 90.seconds
        const val EXPIRED = "這個請求已過期（Bonds 的請求 5 分鐘內有效），請對方重新產生 QR Code。"
        const val NEARBY = "附近的查驗方"
        const val NO_LINK = "這支手機無法以藍牙周邊模式傳送，不能回應附近的年齡查驗；請對方改用查驗主機。"

        fun noCard(source: BondsCredentialSource): String = when (source) {
            BondsCredentialSource.SELF_ISSUED ->
                "對方要求以 Bonds 身分證卡（自然人憑證簽署）證明年齡。到「文件」開啟 MyData 的國民身分證資料 PDF 製作身分證卡後就能回應。"
            else -> "對方要求以政府皮夾卡片證明年齡，這支手機沒有含出生日期欄位的數位憑證皮夾卡片。"
        }
    }
}

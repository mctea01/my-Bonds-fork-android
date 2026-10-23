package diw.wallet.app

import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
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
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
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
 * Answers a Bonds web age request (BondsAgeRequest) with an OpenAC proof: the holder picks a card, the proof is
 * produced and checked on this device, then posted to the response address with the verdict shown. Only the two
 * proofs, the statement and the issuer DID leave the device; the history records the statement, never a value.
 */
class BondsAgeFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var job: Job? = null
    private val client by lazy { model.http.config { followRedirects = false } }

    fun start(text: String) {
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("讀取年齡證明請求")
        model.scope.launch {
            ui.value = try {
                val request = BondsAgeRequest.parse(text)
                val cards = cards(request.source)
                when {
                    !request.isFresh(Clock.System.now()) -> OfflineUi.Failed(EXPIRED)
                    cards.isEmpty() -> OfflineUi.Failed(noCard(request.source))
                    else -> OfflineUi.AgeChoose(request, cards)
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
                        ui.value = OfflineUi.AgeChoose(request, cards(request.source))
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
        model.scope.launch { ui.value = OfflineUi.AgeChoose(state.request, cards(state.request.source)) }
    }

    /** Stops whatever runs, when the screen is left. */
    fun stop() {
        (ui.value as? OfflineUi.AgeWorking)?.let { model.zk.cancel(it.jobId) }
        job?.cancel()
        job = null
    }

    /** Posts the proof and shows the verdict; returns the failure for the history, or null when accepted. */
    private suspend fun send(request: BondsAgeRequest, card: AgeCard, material: BondsAgeMaterial, proof: diw.wallet.core.zk.OpenAcAgeProof): String? {
        val now = Clock.System.now()
        if (!request.isFresh(now)) {
            ui.value = OfflineUi.AgeResult(request, card, false, "請求已過期", listOf(EXPIRED, "證明已產生但沒有送出。"), retry = false)
            return EXPIRED
        }
        val pkg = BondsAgePackage(request, proof.claimName, proof.claimFormat, material.issuerDid, proof.prepareProof, proof.showProof,
            proof.prepareMs, proof.showMs, now)
        ui.value = OfflineUi.AgeWorking(request, card, jobId(request), sending = true)
        val timing = "產生證明 ${seconds(proof.prepareMs + proof.showMs)} 秒"
        val (status, body) = try {
            withTimeout(SEND_TIMEOUT) {
                val response = client.post(request.responseUrl) {
                    contentType(ContentType.Application.Json)
                    accept(ContentType.Application.Json)
                    setBody(pkg.encode())
                }
                response.status to response.bodyAsText()
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            val reason = "無法把證明送到 ${request.responseHost}，請檢查網路後重試。"
            ui.value = OfflineUi.AgeResult(request, card, false, "沒有送出", listOf(reason), retry = true)
            return reason
        }
        val verdict = BondsAgeVerdict.parse(body)
        return when {
            verdict?.accepted == true -> {
                ui.value = OfflineUi.AgeResult(request, card, true, "${request.responseHost} 已接受證明",
                    listOfNotNull("查驗方確認你年滿 ${verdict.minimumAge ?: request.minimumAge} 歲，沒有收到出生日期或其他欄位。", timing,
                        verdict.verifyMs?.let { "查驗方驗證 ${seconds(it)} 秒" }), retry = false)
                null
            }
            verdict != null -> {
                val reason = verdict.reason?.takeIf { it.isNotBlank() } ?: verdict.status
                // A 5xx verdict is the verifier's own failure (its backend down), not a judgement of the proof.
                ui.value = if (status.value >= 500) OfflineUi.AgeResult(request, card, false, "${request.responseHost} 暫時無法驗證",
                    listOf("對方的說明：$reason", "證明已送達，是查驗方網站的問題；請對方稍後重新產生 QR Code 再試。", timing), retry = false)
                else OfflineUi.AgeResult(request, card, false, "${request.responseHost} 沒有接受證明", listOf("對方的說明：$reason", timing), retry = false)
                reason
            }
            status.isSuccess() -> {
                val reason = "${request.responseHost} 的回應無法讀取。"
                ui.value = OfflineUi.AgeResult(request, card, false, "結果不明", listOf(reason), retry = false)
                reason
            }
            else -> {
                val text = body.filter { !it.isISOControl() }.take(200).ifBlank { "HTTP ${status.value}" }
                ui.value = OfflineUi.AgeResult(request, card, false, "${request.responseHost} 沒有接受證明", listOf("對方的說明：$text"), retry = false)
                text
            }
        }
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
            HistoryKind.PRESENTED, request.responseHost, null, listOf(card.name), listOf("年滿 ${request.minimumAge} 歲"),
            "年齡零知識證明（Bonds 線上查驗），用途：${request.purpose.ifEmpty { "未說明" }}", failure,
        )
    }

    private fun seconds(ms: Long) = (ms / 100) / 10.0

    companion object {
        val SEND_TIMEOUT = 90.seconds
        const val EXPIRED = "這個請求已過期（Bonds 的請求 5 分鐘內有效），請對方重新產生 QR Code。"

        fun noCard(source: BondsCredentialSource): String = when (source) {
            BondsCredentialSource.SELF_ISSUED ->
                "對方要求以 Bonds 身分證卡（自然人憑證簽署）證明年齡。到「文件」開啟 MyData 的國民身分證資料 PDF 製作身分證卡後就能回應。"
            else -> "對方要求以政府皮夾卡片證明年齡，這支手機沒有含出生日期欄位的數位憑證皮夾卡片。"
        }
    }
}

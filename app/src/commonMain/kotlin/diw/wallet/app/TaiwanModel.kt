package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsFrameCollector
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.BondsReception
import diw.wallet.core.profile.bonds.BondsVerifiedPresentation
import diw.wallet.core.profile.twdiw.TwdiwCardService
import diw.wallet.core.profile.twdiw.TwdiwEntry
import diw.wallet.core.profile.twdiw.TwdiwOfflineService
import diw.wallet.core.profile.twdiw.TwdiwOfflineSession
import diw.wallet.core.profile.twdiw.TwdiwPlatform
import diw.wallet.core.profile.twdiw.TwdiwStaticTarget
import diw.wallet.core.profile.twdiw.TwdiwTrustEntry
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusDecision
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.multipaz.document.Document
import org.multipaz.revocation.RevocationCheckState
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** A TWDIW card that can answer a Bonds request, with its disclosable claims. */
data class BondsCard(
    val document: Document,
    val credential: W3cVcCredential,
    val name: String,
    val claims: List<Pair<String, String>>,
)

/** One organisation of the TWDIW trust list, with its checked decision once verified. */
data class TwdiwTrustRow(
    val entry: TwdiwTrustEntry,
    val decision: TrustDecision?,
    val anchor: String?,
    /** When the decision was checked (epoch milliseconds). */
    val checkedAt: Long? = null,
)

/** What the offline screen shows. */
sealed class OfflineUi {
    data class Working(val message: String) : OfflineUi()
    data class Failed(val message: String) : OfflineUi()

    /** TWDIW counter barcode (DWVP-05), valid until [expiresAt]. */
    data class Barcode(val serviceName: String, val image: ImageBitmap?, val expiresAt: Instant) : OfflineUi()

    /** Bonds request scanned: pick a card and what to disclose. */
    data class BondsChoose(val request: BondsPresentationRequest, val cards: List<BondsCard>) : OfflineUi()

    /** Bonds presentation shown as rotating BTWVP1 frames, optionally sent over BLE. */
    data class BondsFrames(
        val request: BondsPresentationRequest,
        val frames: List<String>,
        val presentationJws: String,
        val expiresAt: Instant,
        /** BLE state for the user, null when the link was not used. */
        val link: String? = null,
    ) : OfflineUi()

    /** Verifier side: the challenge is shown; frames are scanned until complete. */
    data class VerifierChallenge(
        val request: BondsPresentationRequest,
        val received: Int,
        val total: Int,
        val risk: RiskLevel = RiskLevel.MEDIUM,
    ) : OfflineUi()

    data class VerifierResult(
        val request: BondsPresentationRequest,
        val result: BondsVerifiedPresentation?,
        val issuerTrust: TrustDecision?,
        val error: String?,
        val risk: RiskLevel = RiskLevel.MEDIUM,
        /** The presented card's status, queried online when the phone has a connection. */
        val status: CredentialStatus? = null,
        val statusDecision: StatusDecision? = null,
    ) : OfflineUi()
}

/**
 * TWDIW platform services and the Bonds offline presentation behind the common screens: the card catalogue (Add
 * document), counter services (Use), static codes, the trust list (Settings), Bonds as holder (Use) and as
 * verifier (Verify). Their cards are ordinary documents in the one documents list.
 */
class TaiwanModel(private val model: WalletModel) {
    val offline = MutableStateFlow<OfflineUi>(OfflineUi.Working(""))
    val offlineServices = MutableStateFlow<List<TwdiwOfflineService>?>(null)
    val cardServices = MutableStateFlow<List<TwdiwCardService>?>(null)
    val servicesError = MutableStateFlow<String?>(null)
    val trustRows = MutableStateFlow<List<TwdiwTrustRow>?>(null)
    val trustError = MutableStateFlow<String?>(null)
    /** Automatic check of the trust list: (checked, total) while it runs, null when idle. */
    val trustProgress = MutableStateFlow<Pair<Int, Int>?>(null)

    private var verifierCollector: BondsFrameCollector? = null
    private var verifierRisk = RiskLevel.MEDIUM
    private var linkJob: Job? = null
    private var verifyAllJob: Job? = null

    /** TWDIW cards: issued under the TWDIW profile. */
    fun twdiwDocuments(docs: List<Document>): List<Document> = docs.filter { it.issuanceRecord?.profile == TWDIW }

    // ---------------------------------------------------------------- TWDIW services

    private var servicesJob: Job? = null

    /** Loads the counter services and the card catalogue; a load already running is not started again. */
    fun loadServices() {
        if (servicesJob?.isActive == true) return
        servicesJob = model.scope.launch {
            servicesError.value = null
            try {
                val s = model.twdiwServices
                offlineServices.value = s.offlineServices()
                cardServices.value = s.cardServices()
            } catch (e: Exception) {
                servicesError.value = "無法取得數位憑證皮夾的服務清單：" + model.describe(e)
            }
        }
    }

    /** Opens a card's application page; the issuer page ends with an offer deep link back into the wallet. */
    fun applyFor(service: TwdiwCardService) {
        val url = service.issuerServiceUrl
        if (url == null) {
            model.message.value = "此憑證沒有提供申請頁面"
            return
        }
        model.platform.openBrowser(url)
    }

    /** A static code: an issuer page (mode vc) or a verifier's request with optional custom fields (mode vp). */
    fun openStatic(code: TwdiwEntry.StaticQr) {
        model.scope.launch {
            try {
                when (val t = model.twdiwServices.resolveStatic(code)) {
                    is TwdiwStaticTarget.IssuerPage -> model.platform.openBrowser(t.url)
                    is TwdiwStaticTarget.Request -> model.startPresentation(t.entry.uri, TwdiwEntry.ENTRY_HINT, t.fields)
                }
            } catch (e: Exception) {
                model.message.value = "無法開啟此 QR Code：" + model.describe(e)
            }
        }
    }

    /** Counter pickup (e.g. 7-ELEVEN): present the card, then show the barcode the verifier module returns. */
    fun startPickup(service: TwdiwOfflineService) {
        offline.value = OfflineUi.Working("向 ${service.name} 建立取貨交易")
        model.screen.value = Screen.Offline
        model.scope.launch {
            try {
                val session = model.twdiwServices.startOffline(service)
                model.startPresentation(session.entry.uri, TwdiwEntry.ENTRY_HINT, session.fields, session)
            } catch (e: Exception) {
                offline.value = OfflineUi.Failed(model.describe(e))
            }
        }
    }

    fun startPickup711() {
        val service = offlineServices.value?.firstOrNull { it.vpUid == TwdiwPlatform.PICKUP_711_VP_UID }
        if (service == null) {
            model.message.value = "尚未取得 7-ELEVEN 取貨服務，請稍候或重新整理服務清單"
            loadServices()
            return
        }
        startPickup(service)
    }

    /** After the presentation: fetch the barcode signed with the presented card's (shared TWDIW) key. */
    fun fetchBarcode(session: TwdiwOfflineSession) {
        offline.value = OfflineUi.Working("取得取貨條碼")
        model.screen.value = Screen.Offline
        model.scope.launch {
            try {
                val holder = model.holderIdentities.find(HolderIdentities.TWDIW)
                    ?: throw ProtocolException("credential_unavailable", "找不到數位憑證皮夾的持有者金鑰")
                val barcode = try {
                    withContext(model.unlockProvider) { model.twdiwServices.barcode(session, holder) }
                } finally {
                    model.endOperation()
                }
                offline.value = OfflineUi.Barcode(session.service.name, model.platform.decodeImage(barcode.png), barcode.expiresAt)
                model.platform.keepScreenOn(true)
            } catch (e: Exception) {
                offline.value = OfflineUi.Failed(model.describe(e))
            }
        }
    }

    // ---------------------------------------------------------------- trust list

    /**
     * Loads the trust list and then checks every organisation on its own (self-signed DID document and Arbitrum
     * registration) without the user asking: those never checked or checked more than a day ago, or all of them
     * when [refresh] is set.
     */
    fun loadTrust(refresh: Boolean = false) = model.scope.launch {
        trustError.value = null
        try {
            val list = model.twdiwTrust
            val snaps = list.snapshots().associateBy { it.entry.did }
            trustRows.value = list.all(refresh).map { e ->
                val s = snaps[e.did]
                TwdiwTrustRow(e, s?.let { list.decisionFor(it) }, s?.anchor, s?.checkedAt)
            }.sortedBy { it.entry.displayName }
            verifyAll(force = refresh)
        } catch (e: Exception) {
            trustError.value = "無法取得信任清單：" + model.describe(e)
        }
    }

    /** Checks the organisations of the loaded list, three at a time, updating each row as its check ends. */
    fun verifyAll(force: Boolean) {
        if (verifyAllJob?.isActive == true) return
        val now = Clock.System.now().toEpochMilliseconds()
        val due = trustRows.value.orEmpty().filter { force || it.checkedAt == null || now - it.checkedAt > TRUST_RECHECK.inWholeMilliseconds }
        if (due.isEmpty()) return
        verifyAllJob = model.scope.launch {
            val gate = Semaphore(3)
            var done = 0
            trustProgress.value = 0 to due.size
            try {
                coroutineScope {
                    due.forEach { row ->
                        launch {
                            gate.withPermit { check(row) }
                            trustProgress.value = ++done to due.size
                        }
                    }
                }
            } finally {
                trustProgress.value = null
            }
        }
    }

    /** Checks one organisation now: its self-signed DID document and its Arbitrum registration. */
    fun verifyEntry(row: TwdiwTrustRow) = model.scope.launch {
        if (!check(row)) model.message.value = "無法連線查驗 ${row.entry.displayName}，請稍後再試"
    }

    private suspend fun check(row: TwdiwTrustRow): Boolean = try {
        val list = model.twdiwTrust
        val snap = list.recheck(row.entry.did)
        val updated = TwdiwTrustRow(row.entry, snap?.let { list.decisionFor(it) }, snap?.anchor, snap?.checkedAt)
        trustRows.value = trustRows.value?.map { if (it.entry.did == row.entry.did) updated else it }
        true
    } catch (_: Exception) {
        false
    }

    // ---------------------------------------------------------------- Bonds holder

    /** A Bonds challenge was scanned: list the TWDIW cards that can answer it. */
    fun startBonds(text: String) {
        model.screen.value = Screen.Offline
        model.scope.launch {
            try {
                val request = BondsPresentationRequest.parse(text)
                if (request.source == BondsCredentialSource.SELF_ISSUED) {
                    offline.value = OfflineUi.Failed("對方要求以自然人憑證自發的 Bonds 卡片（vc+moica），本錢包將在後續版本（P5 文件與自發卡）支援。")
                    return@launch
                }
                val cards = twdiwDocuments(model.documents.value).mapNotNull { doc ->
                    val cred = doc.getCertifiedCredentials().filterIsInstance<W3cVcCredential>()
                        .firstOrNull { it.encoding == W3cEncoding.SD_JWT && it.keyBound } ?: return@mapNotNull null
                    BondsCard(doc, cred, doc.displayName ?: "數位憑證", BondsOfflinePresentation.disclosableClaims(cred))
                }
                offline.value = if (cards.isEmpty()) OfflineUi.Failed("這支手機沒有可出示的政府皮夾卡片。先到「證件」加入卡片，就能出示給查驗方。")
                else OfflineUi.BondsChoose(request, cards)
            } catch (e: Exception) {
                offline.value = OfflineUi.Failed("無法讀取查驗方的 QR Code：" + model.describe(e))
            }
        }
    }

    /** Signs the presentation of [card] with [disclosing] and shows it as frames. */
    fun presentBonds(request: BondsPresentationRequest, card: BondsCard, disclosing: Set<String>) {
        offline.value = OfflineUi.Working("簽署出示資料")
        model.scope.launch {
            try {
                val key = card.credential.holderPublicKey()?.let { model.holderIdentities.findByPublicKey(it) }
                    ?: model.holderIdentities.find(HolderIdentities.TWDIW)
                    ?: throw ProtocolException("credential_unavailable", "找不到此憑證的持有者金鑰")
                val jws = try {
                    withContext(model.unlockProvider) {
                        BondsOfflinePresentation.present(request, card.credential, key, model.didResolver(), disclosing)
                    }
                } finally {
                    model.endOperation()
                }
                offline.value = OfflineUi.BondsFrames(request, BondsOfflinePresentation.qrFrames(jws), jws, Clock.System.now() + 5.minutes)
                model.platform.keepScreenOn(true)
                recordBonds(request, card, disclosing, null)
            } catch (e: Exception) {
                recordBonds(request, card, disclosing, model.describe(e))
                offline.value = OfflineUi.Failed(model.describe(e))
            }
        }
    }

    private fun recordBonds(request: BondsPresentationRequest, card: BondsCard, disclosing: Set<String>, failure: String?) {
        val record = card.document.issuanceRecord
        model.record(
            HistoryKind.PRESENTED, request.audience ?: "Bonds 查驗方", null, listOf(card.name),
            disclosing.map { model.claimLabel(listOf(it), null, record) }, "離線出示，用途：${request.purpose}", failure,
        )
    }

    /** Sends the shown presentation over the verifier's one-time BLE service as well. */
    fun sendOverLink(state: OfflineUi.BondsFrames) {
        val link = model.platform.bondsLink ?: return
        val uuid = state.request.linkServiceId ?: return
        linkJob?.cancel()
        linkJob = model.scope.launch {
            fun update(text: String) {
                val cur = offline.value as? OfflineUi.BondsFrames ?: return
                if (cur.presentationJws == state.presentationJws) offline.value = cur.copy(link = text)
            }
            try {
                link.unavailableReason()?.let { update("藍牙無法使用：$it"); return@launch }
                update("等待查驗方以藍牙連線")
                val ok = link.send(uuid, state.presentationJws) { update(it) }
                update(if (ok) "查驗方已收到" else "藍牙傳送未完成，請改用 QR Code")
            } catch (e: Exception) {
                update("藍牙傳送失敗：" + (e.message ?: ""))
            }
        }
    }

    // ---------------------------------------------------------------- Bonds verifier

    /**
     * Shows a fresh challenge for a Bonds holder to answer. [risk] is the risk of the purpose: it decides whether a
     * card whose status cannot be confirmed (offline, unreadable list) or whose issuer is not listed is accepted.
     */
    fun startVerifier(purpose: String, risk: RiskLevel = verifierRisk) {
        try {
            val request = BondsPresentationRequest.generate(purpose, BondsCredentialSource.TWDIW)
            verifierCollector = BondsFrameCollector()
            verifierRisk = risk
            offline.value = OfflineUi.VerifierChallenge(request, 0, 0, risk)
            model.screen.value = Screen.Offline
            model.platform.keepScreenOn(true)
        } catch (e: Exception) {
            model.message.value = model.describe(e)
        }
    }

    val verifying: Boolean get() = offline.value is OfflineUi.VerifierChallenge && model.screen.value == Screen.Offline

    /** A scanned BTWVP1 frame; verifies the presentation once all frames are in. */
    fun acceptVerifierFrame(text: String) {
        val state = offline.value as? OfflineUi.VerifierChallenge
        val collector = verifierCollector
        if (state == null || collector == null) {
            model.message.value = "這是出示給查驗方的畫面；要查驗對方，請先到「查驗」產生查驗挑戰"
            return
        }
        try {
            when (val r = collector.accept(text)) {
                is BondsReception.Accepted -> offline.value = state.copy(received = r.received, total = r.total)
                is BondsReception.Duplicate -> offline.value = state.copy(received = r.received, total = r.total)
                is BondsReception.Completed -> verify(state.request, r.payload.decodeToString())
            }
        } catch (e: Exception) {
            verifierCollector = BondsFrameCollector()
            model.message.value = "畫面讀取失敗，請重新掃描：" + (e.message ?: "")
            offline.value = state.copy(received = 0, total = 0)
        }
    }

    private fun verify(request: BondsPresentationRequest, jws: String) {
        offline.value = OfflineUi.Working("驗證出示資料")
        val risk = verifierRisk
        model.scope.launch {
            offline.value = try {
                val result = BondsOfflineVerifier(model.didResolver()).verify(jws, request)
                val trust = result.issuer?.let { runCatching { model.didTrust.decide(it, TrustRole.ISSUER) }.getOrNull() }
                offline.value = OfflineUi.Working("查詢證件狀態")
                val status = cardStatus(result)
                val decision = StatusPolicy.decide(status, risk)
                model.record(
                    HistoryKind.VERIFIED, result.moica?.cardholderName ?: "出示者 ${shortDid(result.holder)}", trust,
                    listOfNotNull(trust?.anchorName ?: result.issuer?.let { "發行端 ${shortDid(it)}" }),
                    result.claims.keys.map { model.claimLabel(listOf(it), null, null) },
                    verifierNote(request) + "；" + StatusTexts.summary(decision),
                )
                OfflineUi.VerifierResult(request, result, trust, null, risk, status, decision)
            } catch (e: Exception) {
                model.record(HistoryKind.VERIFIED, "出示者", null, note = verifierNote(request), failure = model.describe(e))
                OfflineUi.VerifierResult(request, null, null, model.describe(e), risk)
            }
            verifierCollector = null
        }
    }

    /**
     * The presented card's status from its credentialStatus, when the phone is online. Offline, or after
     * [STATUS_TIMEOUT], the status is unknown and the risk of the purpose decides.
     */
    private suspend fun cardStatus(result: BondsVerifiedPresentation): CredentialStatus {
        val vc = result.credential
            ?: return CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "Card carries no status reference", referenced = false)
        val checker = CredentialStatusChecker(model.http, model.trust, didTrust = model.didTrust)
        return withTimeoutOrNull(STATUS_TIMEOUT) { runCatching { checker.w3c.check(vc, result.issuer, bypassCache = true) }.getOrNull() }
            ?: CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "離線或狀態清單逾時未回應")
    }

    private fun verifierNote(request: BondsPresentationRequest) =
        "離線查驗，用途：${request.purpose}" + (request.audience?.let { "，以「$it」查驗" } ?: "")

    fun closeOffline() {
        linkJob?.cancel()
        linkJob = null
        verifierCollector = null
        model.platform.keepScreenOn(false)
    }

    companion object {
        const val TWDIW = "twdiw"
        const val MSVID = "msvid"
        private val TRUST_RECHECK = 1.days
        private val STATUS_TIMEOUT = 8.seconds

        /** A DID shortened for a list line: method and the last characters of the identifier. */
        fun shortDid(did: String): String = if (did.length <= 28) did else did.take(14) + "..." + did.takeLast(8)
    }
}

package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.oid4vci.JwtVcIssuerKeys
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerification
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsFrameCollector
import diw.wallet.core.profile.bonds.BondsOfflinePresentation
import diw.wallet.core.profile.bonds.BondsOfflineVerifier
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.MoicaSignedCredential
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
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
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
import kotlinx.io.bytestring.decodeToString
import org.multipaz.credential.Credential
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.document.Document
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import org.multipaz.revocation.RevocationCheckState
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** How a card is enveloped in a Bonds presentation. */
enum class BondsCardKind {
    /** W3C VC as SD-JWT (TWDIW cards and others like them). */
    W3C_SD_JWT,
    /** IETF SD-JWT VC bound by cnf to a key in a secure area. */
    SD_JWT_VC,
    /** W3C JWT VC, shown whole. */
    JWT_VC,
    /** vc+moica: the Bonds national ID card signed with the citizen certificate. */
    MOICA,
}

/**
 * A card that can answer a Bonds request, with its claims; [selective] when the holder picks which to show. A Bonds
 * national ID card lives in the document vault, not in the documents list, so it has no [document] or [credential].
 */
data class BondsCard(
    val document: Document?,
    val credential: Credential?,
    val kind: BondsCardKind,
    val name: String,
    val claims: List<Pair<String, String>>,
    /** The vc+moica card for [BondsCardKind.MOICA]. */
    val moica: MoicaSignedCredential? = null,
) {
    val selective: Boolean get() = kind != BondsCardKind.JWT_VC
}

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

    /** The counter service's verifier module is not an anchored organisation: the user may still go on after confirming. */
    data class Unlisted(val service: TwdiwOfflineService, val message: String) : OfflineUi()

    /** TWDIW counter barcode (DWVP-05), valid until [expiresAt]. */
    data class Barcode(val serviceName: String, val image: ImageBitmap?, val expiresAt: Instant) : OfflineUi()

    /** Bonds web age request scanned: pick the card to prove from. */
    data class AgeChoose(val request: BondsAgeRequest, val cards: List<AgeCard>, val known: Boolean = request.knownHost) : OfflineUi()

    /** The age proof [jobId] is being produced, or with [sending] posted to the verifier. */
    data class AgeWorking(val request: BondsAgeRequest, val card: AgeCard, val jobId: String, val sending: Boolean = false) : OfflineUi()

    /** The verifier's verdict, or why no proof was sent. */
    data class AgeResult(
        val request: BondsAgeRequest,
        val card: AgeCard,
        val accepted: Boolean,
        val title: String,
        val lines: List<String>,
        val retry: Boolean,
    ) : OfflineUi()

    /**
     * Verifier side of a Bonds age check: the request QR is shown while [host] waits for the proof. [relay]: the proof
     * is verified on this device; [note] says why not. [checking]: the proof has arrived and is being verified.
     */
    data class AgeVerifierWaiting(
        val request: BondsAgeRequest,
        val host: String,
        val relay: Boolean,
        val note: String?,
        val checking: Boolean = false,
    ) : OfflineUi()

    /** The age check's outcome: verified here ([verification]), the host's [remote] verdict, or why there is none. */
    data class AgeVerifierResult(
        val request: BondsAgeRequest,
        val host: String,
        val verification: BondsAgeVerification?,
        val remote: BondsAgeVerdict?,
        val error: String?,
    ) : OfflineUi()

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
    private var verifierSource = BondsCredentialSource.TWDIW

    /** A document the holder chose to present before scanning the verifier's challenge; listed first. */
    var preferredDocument: String? = null
    private var linkJob: Job? = null
    val age = BondsAgeFlow(model, offline)
    val ageVerifier = BondsAgeVerifierFlow(model, offline)
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
    fun startPickup(service: TwdiwOfflineService, allowUnlisted: Boolean = false) {
        offline.value = OfflineUi.Working("向 ${service.name} 建立取貨交易")
        model.screen.value = Screen.Offline
        model.scope.launch {
            try {
                val session = model.twdiwServices.startOffline(service, allowUnlisted)
                model.startPresentation(session.entry.uri, TwdiwEntry.ENTRY_HINT, session.fields, session)
            } catch (e: ProtocolException) {
                offline.value = if (e.code == "untrusted_verifier" && !allowUnlisted) OfflineUi.Unlisted(service, model.describe(e))
                else OfflineUi.Failed(model.describe(e))
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

    /**
     * A Bonds challenge was scanned: list the cards that can answer it. A Bonds verifier asks for TWDIW cards; this
     * wallet's own verifier may accept any key-bound card. The document chosen beforehand, if any, comes first.
     */
    /**
     * A Bonds web age request is answered online with an OpenAC proof posted to its response address. It shares the
     * offline challenge's keys but must never open the offline screen or advertise over Bluetooth for it.
     */
    /** A Bonds web age request: answered online with an OpenAC proof, never over the offline frames. */
    fun startBondsAge(text: String) = age.start(text)

    fun startBonds(text: String) {
        model.screen.value = Screen.Offline
        val preferred = preferredDocument
        preferredDocument = null
        model.scope.launch {
            try {
                val request = BondsPresentationRequest.parse(text)
                if (request.source == BondsCredentialSource.SELF_ISSUED) {
                    // vc+moica is the national ID card's structure only; document-derived credentials are SD-JWT VC.
                    val cards = model.files.nationalIdCards().map { (_, card) ->
                        BondsCard(null, null, BondsCardKind.MOICA, NATIONAL_ID_NAME, nationalIdClaims(card), card)
                    }
                    offline.value = if (cards.isNotEmpty()) OfflineUi.BondsChoose(request, cards)
                    else OfflineUi.Failed("對方要求以自然人憑證簽署的 Bonds 身分證卡（vc+moica）。到「文件」開啟 MyData 的國民身分證資料 PDF 製作身分證卡後就能出示；姓名一定會揭露。")
                    return@launch
                }
                val docs = if (request.source == BondsCredentialSource.TWDIW) twdiwDocuments(model.documents.value) else model.documents.value
                val cards = docs.mapNotNull { bondsCard(it, request.source) }.sortedBy { if (it.document?.identifier == preferred) 0 else 1 }
                offline.value = when {
                    cards.isNotEmpty() -> OfflineUi.BondsChoose(request, cards)
                    request.source == BondsCredentialSource.TWDIW -> OfflineUi.Failed("這個查驗方只接受政府皮夾卡片，這支手機沒有可出示的卡片。先到「證件」加入卡片，就能出示給查驗方。")
                    else -> OfflineUi.Failed("這支手機沒有可離線出示的證件。離線出示適用綁定金鑰的 SD-JWT VC 與 W3C 證件；行動駕照等 mdoc 證件請改用「感應出示」。")
                }
            } catch (e: Exception) {
                offline.value = OfflineUi.Failed("無法讀取查驗方的 QR Code：" + model.describe(e))
            }
        }
    }

    /** The card [doc] offers for a request from [source], or null when it has none that fits. */
    private suspend fun bondsCard(doc: Document, source: BondsCredentialSource): BondsCard? {
        val creds = doc.getCertifiedCredentials()
        val name = doc.displayName ?: "數位憑證"
        creds.filterIsInstance<W3cVcCredential>().firstOrNull { it.encoding == W3cEncoding.SD_JWT && it.keyBound }?.let {
            return BondsCard(doc, it, BondsCardKind.W3C_SD_JWT, name, BondsOfflinePresentation.disclosableClaims(it))
        }
        if (source != BondsCredentialSource.ANY) return null
        // Batch issuance: the least used copy, as for online presentations.
        creds.filterIsInstance<KeyBoundSdJwtVcCredential>().minByOrNull { it.usageCount }?.let {
            val compact = it.issuerProvidedData.decodeToString()
            return BondsCard(doc, it, BondsCardKind.SD_JWT_VC, name, BondsOfflinePresentation.disclosableClaims(compact))
        }
        creds.filterIsInstance<W3cVcCredential>().firstOrNull { it.encoding == W3cEncoding.JWT && it.keyBound }?.let { c ->
            val subject = runCatching { c.credentialJson().let { vc -> vc["credentialSubject"] as? kotlinx.serialization.json.JsonObject } }.getOrNull()
            val claims = subject?.filterKeys { it != "id" }?.map { (k, v) -> k to ((v as? kotlinx.serialization.json.JsonPrimitive)?.content ?: v.toString()) }.orEmpty()
            return BondsCard(doc, c, BondsCardKind.JWT_VC, name, claims)
        }
        return null
    }

    /** Signs the presentation of [card] with [disclosing] and shows it as frames. */
    fun presentBonds(request: BondsPresentationRequest, card: BondsCard, disclosing: Set<String>) {
        offline.value = OfflineUi.Working("簽署出示資料")
        model.scope.launch {
            val shown = if (card.selective) disclosing else card.claims.map { it.first }.toSet()
            try {
                val jws = try {
                    withContext(model.unlockProvider) { sign(request, card, disclosing) }
                } finally {
                    model.endOperation()
                }
                card.credential?.increaseUsageCount()
                offline.value = OfflineUi.BondsFrames(request, BondsOfflinePresentation.qrFrames(jws), jws, Clock.System.now() + 5.minutes)
                model.platform.keepScreenOn(true)
                recordBonds(request, card, shown, null)
            } catch (e: Exception) {
                recordBonds(request, card, shown, model.describe(e))
                offline.value = OfflineUi.Failed(model.describe(e))
            }
        }
    }

    private suspend fun sign(request: BondsPresentationRequest, card: BondsCard, disclosing: Set<String>): String = when (card.kind) {
        BondsCardKind.W3C_SD_JWT -> {
            val cred = card.credential as W3cVcCredential
            val key = cred.holderPublicKey()?.let { model.holderIdentities.findByPublicKey(it) }
                ?: cred.holderKey()
                ?: model.holderIdentities.find(HolderIdentities.TWDIW)
                ?: throw ProtocolException("credential_unavailable", "找不到此憑證的持有者金鑰")
            BondsOfflinePresentation.present(request, cred, key, model.didResolver(), disclosing)
        }
        BondsCardKind.SD_JWT_VC -> {
            val cred = card.credential as KeyBoundSdJwtVcCredential
            val info = cred.secureArea.getKeyInfo(cred.alias)
            BondsOfflinePresentation.presentSdJwtVc(
                request, cred.issuerProvidedData.decodeToString(),
                AsymmetricKey.AnonymousSecureAreaBased(alias = cred.alias, secureArea = cred.secureArea, keyInfo = info, algorithm = Algorithm.ES256), info.publicKey, disclosing,
            )
        }
        BondsCardKind.MOICA -> {
            val holder = model.holderIdentities.find(HolderIdentities.BONDS_SELF_ISSUED)
                ?: throw ProtocolException("credential_unavailable", "找不到自然人憑證卡片的持有者金鑰")
            BondsOfflinePresentation.presentMoica(request, card.moica!!, holder, disclosing)
        }
        BondsCardKind.JWT_VC -> {
            val cred = card.credential as W3cVcCredential
            val key = cred.holderKey() ?: throw ProtocolException("credential_unavailable", "找不到此憑證的持有者金鑰")
            BondsOfflinePresentation.presentJwtVc(request, cred.raw, key.signingKey("ES256"), key.publicKey, cred.holderDid, model.didResolver())
        }
    }

    /** The key a W3C card is bound to, from its own secure area. */
    private suspend fun W3cVcCredential.holderKey(): HolderKey? {
        val area = secureArea ?: return null
        val a = alias ?: return null
        return HolderKey(area, area.getKeyInfo(a), sharedKey, holderDid)
    }

    private fun recordBonds(request: BondsPresentationRequest, card: BondsCard, disclosing: Set<String>, failure: String?) {
        val record = card.document?.issuanceRecord
        model.record(
            HistoryKind.PRESENTED, request.audience ?: "離線查驗方", null, listOf(card.name),
            disclosing.map { model.claimLabel(it.split('.'), null, record) }, "離線出示，用途：${request.purpose}", failure,
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
    fun startVerifier(purpose: String, risk: RiskLevel = verifierRisk, source: BondsCredentialSource = verifierSource) {
        try {
            val request = BondsPresentationRequest.generate(purpose, source)
            verifierSource = source
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
                val metadata = JwtVcIssuerKeys(model.http, model.environmentPolicy.insecureLoopbackAllowed)
                val result = BondsOfflineVerifier(
                    model.didResolver(),
                    { iss, kid ->
                        withTimeoutOrNull(STATUS_TIMEOUT) { metadata.resolve(iss, kid) }
                            ?: throw ProtocolException("invalid_credential", "無法取得發行端金鑰（需要網路）")
                    },
                    documentTrust = model.files.trustSource,
                ).verify(jws, request)
                val trust = issuerTrust(result)
                offline.value = OfflineUi.Working("查詢證件狀態")
                val status = cardStatus(result)
                val decision = StatusPolicy.decide(status, risk)
                model.record(
                    HistoryKind.VERIFIED, result.moica?.cardholderName ?: "出示者 ${shortDid(result.holder)}", trust,
                    listOfNotNull(trust?.anchorName ?: result.issuer?.let { "發行端 ${shortDid(it)}" }),
                    result.claims.keys.map { model.claimLabel(it.split('.'), null, null) },
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
        val checker = CredentialStatusChecker(model.http, model.trust, didTrust = model.didTrust)
        val unknown = CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "離線或狀態清單逾時未回應")
        result.revocationStatus?.let { ref ->
            return withTimeoutOrNull(STATUS_TIMEOUT) { runCatching { checker.check(ref, result.issuerChain, bypassCache = true) }.getOrNull() } ?: unknown
        }
        val vc = result.credential?.takeIf { it["credentialStatus"] != null }
            ?: return CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "Card carries no status reference", referenced = false)
        return withTimeoutOrNull(STATUS_TIMEOUT) { runCatching { checker.w3c.check(vc, result.issuer, bypassCache = true) }.getOrNull() } ?: unknown
    }

    /** The card issuer's trust: its certificate chain, its DID, or for metadata keys an unanchored https issuer. */
    private suspend fun issuerTrust(result: BondsVerifiedPresentation): TrustDecision? {
        result.issuerChain?.let { return model.trust.decide(TrustRole.ISSUER, it) }
        val iss = result.issuer ?: return null
        if (iss.startsWith("did:")) return runCatching { model.didTrust.decideOrDefault(iss, TrustRole.ISSUER, "Issuer $iss is in no trust list") }.getOrNull()
        return TrustDecision(
            tier = TrustTier.T3, environment = null, official = false, anchorName = null,
            labels = setOf(TrustLabel.UNKNOWN_ANCHOR),
            reasons = listOf("Issuer key comes from JWT VC issuer metadata at $iss, not from an anchor"),
        )
    }

    private fun verifierNote(request: BondsPresentationRequest) =
        "離線查驗，用途：${request.purpose}" + (request.audience?.let { "，以「$it」查驗" } ?: "")

    fun closeOffline() {
        age.stop()
        ageVerifier.stop()
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

        const val NATIONAL_ID_NAME = "國民身分證（自然人憑證簽署）"

        /** Claims of a national ID card in Bonds' display order. */
        fun nationalIdClaims(card: MoicaSignedCredential): List<Pair<String, String>> =
            BondsOfflinePresentation.disclosableClaims(card).sortedBy { (name, _) ->
                BondsNationalId.claimOrder.indexOf(name).let { if (it < 0) Int.MAX_VALUE else it }
            }
    }
}

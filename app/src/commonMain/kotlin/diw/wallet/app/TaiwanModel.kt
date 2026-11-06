package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import androidx.compose.ui.graphics.ImageBitmap
import diw.wallet.app.legal.Integration
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.oid4vci.JwtVcIssuerKeys
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.bonds.AnimatedQrCollector
import diw.wallet.core.profile.bonds.AnimatedQrTransport
import diw.wallet.core.profile.bonds.BondsLanLink
import diw.wallet.core.profile.bonds.LanInterface
import diw.wallet.core.profile.bonds.networks
import diw.wallet.core.profile.bonds.postFirstFrom
import diw.wallet.core.profile.bonds.BondsLanPresentation
import diw.wallet.core.profile.bonds.MAX_LAN_URLS
import diw.wallet.core.profile.bonds.postFirst
import diw.wallet.core.jose.PlatformCrypto
import org.multipaz.util.toBase64Url
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerification
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsFrameCollector
import diw.wallet.core.profile.bonds.BondsLinkTransport
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
import kotlinx.coroutines.CancellationException
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

    /** The counter service's verifier module is T4 (unlisted, off the platform, or contradicted): the user may still go on after confirming. */
    data class Unlisted(val service: TwdiwOfflineService, val message: String) : OfflineUi()

    /** TWDIW counter barcode (DWVP-05), valid until [expiresAt]. */
    data class Barcode(val serviceName: String, val image: ImageBitmap?, val expiresAt: Instant) : OfflineUi()

    /** Bonds web age request scanned: pick the card to prove from. */
    data class AgeChoose(val request: BondsAgeRequest, val cards: List<AgeCard>, val known: Boolean = request.knownHost) : OfflineUi()

    /**
     * The age proof [jobId] is being produced, or with [sending] sent to the verifier; [link] is the Bluetooth progress
     * and [qr] the animated QR shown alongside it when the verifier can scan one.
     */
    data class AgeWorking(
        val request: BondsAgeRequest,
        val card: AgeCard,
        val jobId: String,
        val sending: Boolean = false,
        val link: String? = null,
        val qr: AnimatedQrTransport.Encoder? = null,
    ) : OfflineUi()

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
     * Verifier side of a Bonds age check: the request QR is shown while [host] waits for the proof, or for a nearby
     * request this device listens over Bluetooth ([link] is its progress) and reads the holder's animated QR
     * ([scanned]). [relay]: the proof is verified on this device; [note] says why not. [checking]: the proof has
     * arrived and is being verified.
     */
    data class AgeVerifierWaiting(
        val request: BondsAgeRequest,
        val host: String,
        val relay: Boolean,
        val note: String?,
        val checking: Boolean = false,
        val link: String? = null,
        /** Progress of the holder's animated QR, when scanned. */
        val scanned: String? = null,
        /** Technical details, shown folded. */
        val details: List<String> = emptyList(),
        /** Runs through an age host, so the other party's server can be scanned to use instead. */
        val peerable: Boolean = false,
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

    /**
     * Bonds presentation shown as rotating BTWVP1 frames, or as an animated fountain QR ([fountain]) when the
     * challenge asks for it; optionally sent over BLE, and sent over the local network when the challenge has an address.
     */
    data class BondsFrames(
        val request: BondsPresentationRequest,
        val frames: List<String>,
        val presentationJws: String,
        val expiresAt: Instant,
        /** BLE state for the user, null when the link was not used. */
        val link: String? = null,
        val fountain: AnimatedQrTransport.Encoder? = null,
        /** Local network state for the user, null when the challenge has no address. */
        val lan: String? = null,
        /** Technical details, shown folded. */
        val details: List<String> = emptyList(),
        /**
         * Whether the QR code is on screen: hidden while the presentation goes over the local network or Bluetooth
         * and after it arrived there, shown again when that route fails or the user asks for it.
         */
        val showQr: Boolean = true,
    ) : OfflineUi()

    /**
     * Verifier side: the challenge is shown; frames (BTWVP1 or fountain) are scanned until complete, or the
     * presentation arrives over Bluetooth ([link]) or the local network ([lan]).
     */
    data class VerifierChallenge(
        val request: BondsPresentationRequest,
        val received: Int,
        val total: Int,
        val risk: RiskLevel = RiskLevel.MEDIUM,
        val link: String? = null,
        val lan: String? = null,
        /** Technical details, shown folded. */
        val details: List<String> = emptyList(),
    ) : OfflineUi()

    /**
     * zkTLS request scanned: who asks ([verifier], [trust]), which page and fields; the user types the page's inputs.
     * [inline]: the page came with the request (test environment only). [error] is an input problem. For a page with
     * a picture code, [captcha] is the session this device opened on the site (fetching while [preparing]).
     */
    data class ZkTlsConsent(
        val session: diw.wallet.core.zktls.ZkTlsSessionRequest.Verified,
        val profile: diw.wallet.core.zktls.ZkTlsProfile,
        val verifier: String,
        val trust: TrustDecision,
        val inline: Boolean,
        val error: String? = null,
        val captcha: diw.wallet.core.zktls.ZkTlsPrepare.Session? = null,
        val preparing: Boolean = false,
        /** The file a kept result becomes evidence of, when this query was started from that file. */
        val forFile: String? = null,
        /** The verifier host's status address for a session this device opened there, to read why a proof failed. */
        val hostState: String? = null,
        /** Why the holder may not reach the verifier through the routes its server policy allows, and what to do. */
        val routeHint: String? = null,
    ) : OfflineUi()

    /**
     * The holder starts a web query: which page, and whether a verifier host takes part ([host], a zkTLS proof with
     * its receipt) or this device reads the page alone (a device record). [fileId] is the file it is evidence of.
     */
    data class ZkTlsSelfPick(
        val fileId: String?,
        val pages: List<diw.wallet.core.zktls.ZkTlsProfile>,
        val testPages: Set<String>,
        val host: String?,
        val note: String?,
    ) : OfflineUi()

    /** Querying [profile] on this device alone: the inputs, and the picture code where the page has one. */
    data class ZkTlsSelf(
        val profile: diw.wallet.core.zktls.ZkTlsProfile,
        val fileId: String?,
        val error: String? = null,
        val captcha: diw.wallet.core.zktls.ZkTlsPrepare.Session? = null,
        val preparing: Boolean = false,
        val working: Boolean = false,
    ) : OfflineUi()

    /** What this device read alone ([outcome]) and the record kept from it, or why there is none. */
    data class ZkTlsSelfResult(
        val state: ZkTlsSelf,
        val outcome: diw.wallet.core.zktls.ZkTlsOutcome?,
        val serverTrust: TrustDecision?,
        val fetched: diw.wallet.core.zktls.ZkTlsFetched?,
        val kept: ZkTlsKeep.Kept?,
        val error: String?,
    ) : OfflineUi()

    /** The zkTLS proof [jobId] is running. */
    data class ZkTlsProving(val consent: ZkTlsConsent, val jobId: String) : OfflineUi()

    /** What the verifier received ([proved], read with its rules), or why nothing was sent. */
    data class ZkTlsHolderResult(
        val consent: ZkTlsConsent,
        val proved: diw.wallet.core.zktls.ZkTlsProved?,
        val serverTrust: TrustDecision?,
        val error: String?,
        val retry: Boolean,
        /** The result kept in the documents list, when the holder chose to keep it. */
        val kept: ZkTlsKeep.Kept? = null,
        /** Why keeping failed; the proof itself stands. */
        val keepError: String? = null,
    ) : OfflineUi()

    /** Verifier setup: the pages this device can ask for; [testPages] came from the test server. */
    data class ZkTlsVerifierSetup(
        val pages: List<diw.wallet.core.zktls.ZkTlsProfile>,
        val testPages: Set<String>,
        val note: String?,
    ) : OfflineUi()

    /** The request QR, waiting for the holder; [local]: the proof is checked here, else by [where]. */
    data class ZkTlsVerifierWaiting(
        val request: diw.wallet.core.zktls.ZkTlsSessionRequest,
        val link: String,
        val profile: diw.wallet.core.zktls.ZkTlsProfile,
        val where: String,
        val local: Boolean,
        val note: String? = null,
        val step: String? = null,
        /** Technical details, shown folded. */
        val details: List<String> = emptyList(),
    ) : OfflineUi()

    /** The zkTLS check's outcome; [serverTrust] only when the transcript was checked here. */
    data class ZkTlsVerifierResult(
        val profile: diw.wallet.core.zktls.ZkTlsProfile,
        val request: diw.wallet.core.zktls.ZkTlsSessionRequest,
        val outcome: diw.wallet.core.zktls.ZkTlsOutcome?,
        val serverTrust: TrustDecision?,
        val local: Boolean,
        val where: String,
        val error: String?,
        /** The holder asked for, and was given, a signed receipt (a web-proof credential). */
        val receipt: Boolean = false,
    ) : OfflineUi()

    /** zkPassport verifier setup; [test]: the test environment, where test passports may be accepted. */
    data class ZkPassportSetup(val domain: String, val test: Boolean, val note: String?) : OfflineUi()

    /** A zkPassport request in progress: [url] is the request link once the bridge is connected. */
    data class ZkPassportWaiting(
        val request: diw.wallet.core.zkpassport.ZkPassportRequest,
        val url: String?,
        val state: diw.wallet.core.zkpassport.ZkPassportState,
    ) : OfflineUi()

    /** The zkPassport check's outcome, or why there is none ([error]). */
    data class ZkPassportVerified(
        val request: diw.wallet.core.zkpassport.ZkPassportRequest,
        val result: diw.wallet.core.zkpassport.ZkPassportResult?,
        val error: String?,
    ) : OfflineUi()

    /** Answering a zkPassport request (Z3): the bridge to the requester is opening. */
    data class ZkPassportAnswerConnecting(val incoming: diw.wallet.core.zkpassport.ZkPassportIncoming) : OfflineUi()

    /**
     * What the requester asks for and the stored passports to answer with. [origin] is what the bridge reports for
     * the requester; [unsupported] says why this wallet cannot answer, so only declining is offered.
     */
    data class ZkPassportAnswerConsent(
        val incoming: diw.wallet.core.zkpassport.ZkPassportIncoming,
        val origin: String,
        val originMatches: Boolean,
        val passports: List<StoredFile>,
        val unsupported: String?,
    ) : OfflineUi()

    /** The proofs are being made on this device; [progress] is null until the prover reports. */
    data class ZkPassportAnswerProving(
        val incoming: diw.wallet.core.zkpassport.ZkPassportIncoming,
        val progress: diw.wallet.core.zkpassport.ZkPassportAnswerProgress?,
    ) : OfflineUi()

    /** The answer's end: [sent] when the proofs reached the requester; neither sent nor [error] means declined. */
    data class ZkPassportAnswerDone(
        val incoming: diw.wallet.core.zkpassport.ZkPassportIncoming,
        val sent: Boolean,
        val error: String?,
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
    private var verifierFountain: AnimatedQrCollector? = null
    private var verifierRisk = RiskLevel.MEDIUM
    private var verifierSource = BondsCredentialSource.TWDIW

    /** A document the holder chose to present before scanning the verifier's challenge; listed first. */
    var preferredDocument: String? = null
    private var linkJob: Job? = null
    private var lanJob: Job? = null
    private var verifierLinkJob: Job? = null
    private var verifierLanJob: Job? = null
    val age = BondsAgeFlow(model, offline)
    val ageVerifier = BondsAgeVerifierFlow(model, offline)
    val zkTls = ZkTlsFlow(model, offline)
    val zkPassport = ZkPassportFlow(model, offline)
    private var verifyAllJob: Job? = null

    /** TWDIW cards: issued under the TWDIW profile. */
    fun twdiwDocuments(docs: List<Document>): List<Document> = docs.filter { it.issuanceRecord?.profile == TWDIW }

    // ---------------------------------------------------------------- TWDIW services

    private var servicesJob: Job? = null

    /** Loads the counter services and the card catalogue; a load already running is not started again. */
    fun loadServices() {
        if (!model.legal.enabled(Integration.TWDIW)) return
        if (servicesJob?.isActive == true) return
        servicesJob = model.scope.launch {
            servicesError.value = null
            try {
                val s = model.twdiwServices
                offlineServices.value = s.offlineServices()
                cardServices.value = s.cardServices()
            } catch (e: Exception) {
                servicesError.value = tr(Res.string.tw_services_failed) + model.describe(e)
            }
        }
    }

    /** Opens a card's application page; the issuer page ends with an offer deep link back into the wallet. */
    fun applyFor(service: TwdiwCardService) {
        val url = service.issuerServiceUrl
        if (url == null) {
            model.message.value = tr(Res.string.tw_no_apply_page)
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
                model.message.value = tr(Res.string.tw_qr_unopenable) + model.describe(e)
            }
        }
    }

    /** Counter pickup (e.g. 7-ELEVEN): present the card, then show the barcode the verifier module returns. */
    fun startPickup(service: TwdiwOfflineService, allowUnlisted: Boolean = false) {
        if (!model.legal.enabled(Integration.TWDIW)) {
            model.message.value = model.legal.disabledMessage(Integration.TWDIW)
            return
        }
        offline.value = OfflineUi.Working(tr(Res.string.tw_creating_pickup, service.name))
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
            model.message.value = tr(Res.string.tw_no_pickup_service)
            loadServices()
            return
        }
        startPickup(service)
    }

    /** After the presentation: fetch the barcode signed with the presented card's (shared TWDIW) key. */
    fun fetchBarcode(session: TwdiwOfflineSession) {
        offline.value = OfflineUi.Working(tr(Res.string.tw_getting_pickup_code))
        model.screen.value = Screen.Offline
        model.scope.launch {
            try {
                val holder = model.holderIdentities.find(HolderIdentities.TWDIW)
                    ?: throw ProtocolException("credential_unavailable", tr(Res.string.tw_no_wallet_key))
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
        if (!model.legal.enabled(Integration.TWDIW)) return@launch
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
            trustError.value = tr(Res.string.tw_trust_list_failed) + model.describe(e)
        }
    }

    /** Checks the organisations of the loaded list, three at a time, updating each row as its check ends. */
    fun verifyAll(force: Boolean) {
        if (!model.legal.enabled(Integration.TWDIW)) return
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
        if (!check(row)) model.message.value = tr(Res.string.tw_check_unreachable, row.entry.displayName)
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
                    else OfflineUi.Failed(tr(Res.string.tw_needs_bonds_id))
                    return@launch
                }
                val docs = if (request.source == BondsCredentialSource.TWDIW) twdiwDocuments(model.documents.value) else model.documents.value
                val cards = docs.mapNotNull { bondsCard(it, request.source) }.sortedBy { if (it.document?.identifier == preferred) 0 else 1 }
                offline.value = when {
                    cards.isNotEmpty() -> OfflineUi.BondsChoose(request, cards)
                    request.source == BondsCredentialSource.TWDIW -> OfflineUi.Failed(tr(Res.string.tw_only_gov_cards))
                    else -> OfflineUi.Failed(tr(Res.string.tw_no_offline_cards))
                }
            } catch (e: Exception) {
                offline.value = OfflineUi.Failed(tr(Res.string.tw_verifier_qr_unreadable) + model.describe(e))
            }
        }
    }

    /** The card [doc] offers for a request from [source], or null when it has none that fits. */
    private suspend fun bondsCard(doc: Document, source: BondsCredentialSource): BondsCard? {
        val creds = doc.getCertifiedCredentials()
        val name = doc.displayName ?: tr(Res.string.tw_card_fallback)
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
        offline.value = OfflineUi.Working(tr(Res.string.tw_signing_presentation))
        model.scope.launch {
            val shown = if (card.selective) disclosing else card.claims.map { it.first }.toSet()
            try {
                val jws = try {
                    withContext(model.unlockProvider) { sign(request, card, disclosing) }
                } finally {
                    model.endOperation()
                }
                card.credential?.increaseUsageCount()
                // A verifier that reads the fountain QR (this wallet) gets it instead of the BTWVP1 frames Bonds reads.
                val fountain = if (request.qr) AnimatedQrTransport.Encoder(jws.encodeToByteArray()) else null
                val frames = if (fountain == null) BondsOfflinePresentation.qrFrames(jws) else emptyList()
                // Over the local network the QR stays hidden unless that route fails or the user asks for it.
                val viaLan = request.lanUrls.isNotEmpty() && model.platform.bondsLan != null
                val state = OfflineUi.BondsFrames(request, frames, jws, Clock.System.now() + 5.minutes, fountain = fountain, showQr = !viaLan,
                    details = LanDetails.presentation(request) + request.lanUrls.map { tr(Res.string.tw_verifier_address) + LanDetails.hostPort(it) })
                offline.value = state
                model.platform.keepScreenOn(true)
                recordBonds(request, card, shown, null)
                sendOverLan(state)
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
                ?: throw ProtocolException("credential_unavailable", tr(Res.string.tw_no_holder_key))
            BondsOfflinePresentation.present(request, cred, key, model.didResolver(), disclosing)
        }
        BondsCardKind.SD_JWT_VC -> {
            val cred = card.credential as KeyBoundSdJwtVcCredential
            val info = cred.secureArea.getKeyInfo(cred.alias)
            BondsOfflinePresentation.presentSdJwtVc(
                request, cred.issuerProvidedData.decodeToString(),
                AsymmetricKey.AnonymousSecureAreaBased(alias = cred.alias, secureArea = cred.secureArea, keyInfo = info, algorithm = Algorithm.ES256), info.ecPublicKey, disclosing,
            )
        }
        BondsCardKind.MOICA -> {
            val holder = model.holderIdentities.find(HolderIdentities.BONDS_SELF_ISSUED)
                ?: throw ProtocolException("credential_unavailable", tr(Res.string.tw_no_moica_key))
            BondsOfflinePresentation.presentMoica(request, card.moica!!, holder, disclosing)
        }
        BondsCardKind.JWT_VC -> {
            val cred = card.credential as W3cVcCredential
            val key = cred.holderKey() ?: throw ProtocolException("credential_unavailable", tr(Res.string.tw_no_holder_key))
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
            HistoryKind.PRESENTED, request.audience ?: tr(Res.string.tw_offline_verifier), null, listOf(card.name),
            disclosing.map { model.claimLabel(it.split('.'), null, record) }, tr(Res.string.tw_offline_presented, request.purpose), failure,
        )
    }

    /** Puts the presentation's QR code on screen, for a verifier that scans instead. */
    fun showFramesQr() {
        val cur = offline.value as? OfflineUi.BondsFrames ?: return
        offline.value = cur.copy(showQr = true)
    }

    /** Sends the shown presentation over the verifier's one-time BLE service as well. */
    fun sendOverLink(state: OfflineUi.BondsFrames) {
        val link = model.platform.bondsLink ?: return
        val uuid = state.request.linkServiceId ?: return
        linkJob?.cancel()
        linkJob = model.scope.launch {
            fun update(text: String, showQr: Boolean? = null) {
                val cur = offline.value as? OfflineUi.BondsFrames ?: return
                if (cur.presentationJws == state.presentationJws) offline.value = cur.copy(link = text, showQr = showQr ?: cur.showQr)
            }
            try {
                link.unavailableReason()?.let { update(tr(Res.string.tw_ble_unavailable, it), showQr = true); return@launch }
                update(tr(Res.string.tw_ble_waiting), showQr = false)
                val ok = link.send(uuid, state.presentationJws) { update(it) }
                update(if (ok) tr(Res.string.tw_verifier_received) else tr(Res.string.tw_ble_incomplete), showQr = !ok)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                update(tr(Res.string.tw_ble_failed) + (e.message ?: ""), showQr = true)
            }
        }
    }

    /** Posts the shown presentation, sealed to the verifier's key, to the challenge's address on this phone's network. */
    private fun sendOverLan(state: OfflineUi.BondsFrames) {
        val lan = model.platform.bondsLan ?: return
        val urls = state.request.lanUrls.takeIf { it.isNotEmpty() } ?: return
        lanJob?.cancel()
        lanJob = model.scope.launch {
            fun update(text: String, showQr: Boolean, reached: String? = null) {
                val cur = offline.value as? OfflineUi.BondsFrames ?: return
                if (cur.presentationJws != state.presentationJws) return
                offline.value = cur.copy(lan = text, showQr = showQr, details = cur.details + listOfNotNull(reached?.let { tr(Res.string.tw_delivery_address) + LanDetails.hostPort(it) }))
            }
            try {
                update(tr(Res.string.tw_lan_sending), showQr = false)
                val (status, text, reached) = lan.postFirstFrom(urls, BondsLanPresentation.seal(state.presentationJws, state.request), LAN_SEND_TIMEOUT)
                val refusal = BondsLanPresentation.refusal(status, text)
                update(if (refusal == null) tr(Res.string.tw_lan_delivered) else tr(Res.string.tw_lan_refused, refusal), showQr = refusal != null, reached)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                update(tr(Res.string.tw_lan_not_delivered, model.describe(e)), showQr = true)
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
            stopVerifierTransports()
            val plain = BondsPresentationRequest.generate(purpose, source, qr = true)
            verifierSource = source
            verifierRisk = risk
            model.screen.value = Screen.Offline
            model.platform.keepScreenOn(true)
            val lan = model.platform.bondsLan
            val interfaces = lan?.localInterfaces()?.take(MAX_LAN_URLS).orEmpty()
            if (lan == null || interfaces.isEmpty()) {
                showChallenge(plain, lan?.let { tr(Res.string.tw_lan_no_network) })
                return
            }
            offline.value = OfflineUi.Working(tr(Res.string.tw_preparing_challenge))
            listenOnLan(lan, interfaces, purpose, source, plain)
        } catch (e: Exception) {
            model.message.value = model.describe(e)
        }
    }

    private fun showChallenge(request: BondsPresentationRequest, lan: String?, details: List<String> = LanDetails.presentation(request)) {
        verifierCollector = BondsFrameCollector()
        verifierFountain = AnimatedQrCollector(BondsLinkTransport.MAX_PAYLOAD)
        offline.value = OfflineUi.VerifierChallenge(request, 0, 0, verifierRisk, lan = lan, details = details)
        listenOnLink(request)
    }

    /**
     * Listens on this device's Wi-Fi and hotspot [addresses] and shows a challenge naming them with a one-time key; the
     * holder posts the sealed presentation there. Something that is not a presentation for this challenge (another
     * device on the network) is refused without ending the check. Without a listening socket the challenge is
     * shown without an address ([fallback]).
     */
    private fun listenOnLan(lan: BondsLanLink, interfaces: List<LanInterface>, purpose: String, source: BondsCredentialSource, fallback: BondsPresentationRequest) {
        val addresses = interfaces.map { it.address }
        verifierLanJob = model.scope.launch {
            var request: BondsPresentationRequest? = null
            var presentation: String? = null
            fun active(r: BondsPresentationRequest) = (offline.value as? OfflineUi.VerifierChallenge)?.request == r
            try {
                val key = BondsLanPresentation.newKey()
                withTimeoutOrNull(LAN_LISTEN) {
                    lan.serve(addresses, "/vp/" + PlatformCrypto.randomBytes(16).toBase64Url(), BondsLanPresentation.MAX_BODY, onListening = { urls ->
                        val r = BondsPresentationRequest.generate(
                            purpose, source, lanUrls = urls, lanKey = BondsLanPresentation.keyText(key.publicKey), qr = true,
                        )
                        request = r
                        showChallenge(r, tr(Res.string.tw_lan_also, interfaces.networks()), LanDetails.presentation(r, LanDetails.listening(urls, interfaces)))
                    }) { body ->
                        val r = request!!
                        if (!active(r)) return@serve BondsLanPresentation.refused(tr(Res.string.tw_check_ended)) to true
                        try {
                            presentation = BondsLanPresentation.open(body, key, r)
                            BondsLanPresentation.received() to true
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            (offline.value as? OfflineUi.VerifierChallenge)?.takeIf { it.request == r }?.let {
                                offline.value = it.copy(lan = tr(Res.string.tw_lan_bad_data, model.describe(e)))
                            }
                            BondsLanPresentation.refused(tr(Res.string.tw_not_this_challenge)) to false
                        }
                    }
                }
                val r = request ?: return@launch
                val jws = presentation
                if (jws != null && active(r)) verify(r, jws)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val r = request
                if (r == null) {
                    // The socket could not be opened: the camera and Bluetooth still work.
                    if (offline.value is OfflineUi.Working) showChallenge(fallback, tr(Res.string.tw_lan_receive_failed, model.describe(e)))
                } else {
                    (offline.value as? OfflineUi.VerifierChallenge)?.takeIf { it.request == r }?.let {
                        offline.value = it.copy(lan = tr(Res.string.tw_lan_interrupted, model.describe(e)))
                    }
                }
            }
        }
    }

    /** Stops every way a verifier challenge is being answered. */
    private fun stopVerifierTransports() {
        verifierLinkJob?.cancel()
        verifierLinkJob = null
        verifierLanJob?.cancel()
        verifierLanJob = null
        verifierCollector = null
        verifierFountain = null
    }

    /**
     * Receives the presentation over the challenge's one-time BLE service too, as a Bonds verifier does: a holder (the
     * Bonds App or this wallet) that scanned the challenge advertises it and sends the frames, so no QR has to be scanned back.
     */
    private fun listenOnLink(request: BondsPresentationRequest) {
        val central = model.platform.bondsLinkCentral ?: return
        val uuid = request.linkServiceId ?: return
        verifierLinkJob?.cancel()
        verifierLinkJob = model.scope.launch {
            fun update(text: String) {
                (offline.value as? OfflineUi.VerifierChallenge)?.takeIf { it.request == request }?.let { offline.value = it.copy(link = text) }
            }
            try {
                central.unavailableReason()?.let { update(tr(Res.string.tw_ble_unavailable_scan, it)); return@launch }
                update(tr(Res.string.tw_ble_also))
                val jws = central.receive(uuid, BondsLinkTransport.MAX_PAYLOAD, ::update, null).decodeToString()
                if ((offline.value as? OfflineUi.VerifierChallenge)?.request == request) {
                    verifierCollector = null
                    verify(request, jws)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                update(tr(Res.string.tw_ble_receive_failed, model.describe(e)))
            }
        }
    }

    val verifying: Boolean get() = offline.value is OfflineUi.VerifierChallenge && model.screen.value == Screen.Offline

    /** A scanned BTWVP1 or fountain (DIWQ1) frame; verifies the presentation once all frames are in. */
    fun acceptVerifierFrame(text: String) {
        val state = offline.value as? OfflineUi.VerifierChallenge
        val fountain = AnimatedQrTransport.isFrame(text)
        val collector: ((String) -> BondsReception)? = if (fountain) verifierFountain?.let { it::accept } else verifierCollector?.let { it::accept }
        if (state == null || collector == null) {
            model.message.value = tr(Res.string.tw_wrong_screen)
            return
        }
        try {
            when (val r = collector(text)) {
                is BondsReception.Accepted -> offline.value = state.copy(received = r.received, total = r.total)
                is BondsReception.Duplicate -> offline.value = state.copy(received = r.received, total = r.total)
                is BondsReception.Completed -> verify(state.request, r.payload.decodeToString())
            }
        } catch (e: Exception) {
            if (fountain) verifierFountain = AnimatedQrCollector(BondsLinkTransport.MAX_PAYLOAD) else verifierCollector = BondsFrameCollector()
            model.message.value = tr(Res.string.tw_screen_unreadable) + (e.message ?: "")
            offline.value = state.copy(received = 0, total = 0)
        }
    }

    private fun verify(request: BondsPresentationRequest, jws: String) {
        // Whichever transport delivered first wins; the others stop (this may be called from one of their jobs).
        stopVerifierTransports()
        offline.value = OfflineUi.Working(tr(Res.string.tw_verifying_presentation))
        val risk = verifierRisk
        model.scope.launch {
            offline.value = try {
                val metadata = JwtVcIssuerKeys(model.http, model.environmentPolicy.insecureLoopbackAllowed)
                val result = BondsOfflineVerifier(
                    model.didResolver(),
                    { iss, kid ->
                        withTimeoutOrNull(STATUS_TIMEOUT) { metadata.resolve(iss, kid) }
                            ?: throw ProtocolException("invalid_credential", tr(Res.string.tw_issuer_key_offline))
                    },
                    documentTrust = model.files.trustSource,
                    zkPdf = model.zkPdfContext,
                ).verify(jws, request)
                val trust = issuerTrust(result)
                offline.value = OfflineUi.Working(tr(Res.string.tw_checking_status))
                val status = cardStatus(result)
                val decision = StatusPolicy.decide(status, risk)
                model.record(
                    HistoryKind.VERIFIED, result.moica?.cardholderName ?: tr(Res.string.tw_holder_did, shortDid(result.holder)), trust,
                    listOfNotNull(trust?.anchorName ?: result.issuer?.let { tr(Res.string.tw_issuer_did, shortDid(it)) }),
                    result.claims.keys.map { model.claimLabel(it.split('.'), null, null) },
                    verifierNote(request) + tr(Res.string.sep_semicolon) + StatusTexts.summary(decision),
                )
                OfflineUi.VerifierResult(request, result, trust, null, risk, status, decision)
            } catch (e: Exception) {
                model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = verifierNote(request), failure = model.describe(e))
                OfflineUi.VerifierResult(request, null, null, model.describe(e), risk)
            }
        }
    }

    /**
     * The presented card's status from its credentialStatus, when the phone is online. Offline, or after
     * [STATUS_TIMEOUT], the status is unknown and the risk of the purpose decides.
     */
    private suspend fun cardStatus(result: BondsVerifiedPresentation): CredentialStatus {
        val checker = CredentialStatusChecker(model.http, model.trust, didTrust = model.didTrust)
        val unknown = CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), tr(Res.string.tw_status_timeout))
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
        tr(Res.string.tw_offline_verified, request.purpose) + (request.audience?.let { tr(Res.string.tw_verified_as, it) } ?: "")

    fun closeOffline() {
        model.server.clearPeer()
        age.stop()
        ageVerifier.stop()
        zkTls.stop()
        zkPassport.stop()
        linkJob?.cancel()
        linkJob = null
        lanJob?.cancel()
        lanJob = null
        stopVerifierTransports()
        model.platform.keepScreenOn(false)
    }

    companion object {
        const val TWDIW = "twdiw"
        const val MSVID = "msvid"
        private val TRUST_RECHECK = 1.days
        private val STATUS_TIMEOUT = 8.seconds
        private val LAN_SEND_TIMEOUT = 30.seconds
        /** A challenge left on screen stops listening on the network after this. */
        private val LAN_LISTEN = 15.minutes

        /** A DID shortened for a list line: method and the last characters of the identifier. */
        fun shortDid(did: String): String = if (did.length <= 28) did else did.take(14) + "..." + did.takeLast(8)

        val NATIONAL_ID_NAME: String get() = tr(Res.string.tw_national_id_name)

        /** Claims of a national ID card in Bonds' display order. */
        fun nationalIdClaims(card: MoicaSignedCredential): List<Pair<String, String>> =
            BondsOfflinePresentation.disclosableClaims(card).sortedBy { (name, _) ->
                BondsNationalId.claimOrder.indexOf(name).let { if (it < 0) Int.MAX_VALUE else it }
            }
    }
}

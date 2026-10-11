package diw.wallet.app

import diw.wallet.core.compat.Draft11Dialect
import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.compat.EudiDialect
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.credential.ClaimLabels
import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.credential.ClaimSensitivity
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.CredentialDomains
import diw.wallet.core.oid4vci.IssuanceResult
import diw.wallet.core.oid4vci.IssuanceSession
import diw.wallet.core.oid4vci.KeyRequest
import diw.wallet.core.oid4vci.Oid4vciClient
import diw.wallet.core.oid4vci.PublicClientWalletProvider
import diw.wallet.core.oid4vci.RemoteWalletProvider
import diw.wallet.core.oid4vci.WalletProvider
import diw.wallet.core.oid4vci.pick
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.PreparedExtended
import diw.wallet.core.oid4vp.PreparedPresentation
import diw.wallet.core.oid4vp.PreparedRequest
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.compat.MsVerifiedIdPresentationDialect
import diw.wallet.core.oid4vp.compat.TwdiwCustomField
import diw.wallet.core.oid4vp.compat.TwdiwPresentationDialect
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.BondsQrTransport
import diw.wallet.core.profile.msvid.LinkedDomains
import diw.wallet.core.profile.twdiw.TwdiwEntry
import diw.wallet.core.profile.twdiw.TwdiwEntryParser
import diw.wallet.core.profile.twdiw.TwdiwOfflineSession
import diw.wallet.core.profile.twdiw.TwdiwPlatform
import diw.wallet.core.profile.twdiw.TwdiwServices
import diw.wallet.core.profile.twdiw.TwdiwTrustList
import diw.wallet.core.profile.twdiw.TwdiwUserAgent
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.StoredAnchor
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.UserDidTrust
import diw.wallet.core.trust.UserTrustedDid
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.w3c.addDiwCredentialImplementations
import diw.wallet.core.x509.displaySubject
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.readRawBytes
import io.ktor.http.isSuccess
import androidx.compose.ui.graphics.ImageBitmap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.X509Cert
import org.multipaz.asn1.OID
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.presentment.CredentialSelection
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64Url

@Serializable
data class WalletSettings(
    val testEnvironment: Boolean = false,
    val allowLoopbackHttp: Boolean = false,
    val testServerUrl: String = "http://10.0.2.2:8080",
    val useWalletProvider: Boolean = true,
    val clientId: String = "diw-wallet",
    val requireUserAuth: Boolean = true,
    val instanceKeyAlias: String? = null,
    /**
     * client_id this wallet presents to TWDIW issuers. The official wallet's moda_dw is what they accept; the
     * settings screen says that it is the official wallet's identifier.
     */
    val twdiwClientId: String = TwdiwDialect.DEFAULT_CLIENT_ID,
    /** User-Agent sent to wallet.gov.tw hosts only (their Cloudflare front rejects HTTP library defaults). */
    val twdiwUserAgent: String = TwdiwPlatform.DEFAULT_USER_AGENT,
    /** TWDIW platform front end; any other address is used only in the test environment (UAT or a local mock). */
    val twdiwFrontendUrl: String = TwdiwPlatform.PRODUCTION_FRONTEND,
    /** Show technical details (formats, keys, signatures, validity) expanded by default. */
    val showDetails: Boolean = false,
    /** Query document statuses in the background when they are older than the document's risk allows. */
    val autoStatus: Boolean = true,
    /**
     * NFC engagement with static handover (the reader picks from the wallet's offer) instead of negotiated handover;
     * for readers that only read a static handover select message.
     */
    val nfcStaticHandover: Boolean = false,
)

/**
 * Tabs of the home screen. The layout follows the EUDI wallet (documents, history) and Bonds (documents, use):
 * every credential, whatever its issuer or profile, lives in the one documents list, and every holder action is
 * in Use. Verify is the wallet acting as a verifier (the offline check works; the rest is laid out for later).
 * Files is the area for signed files and official documents, laid out for a later phase.
 */
enum class HomeTab { DOCUMENTS, FILES, USE, VERIFY, HISTORY }

sealed class Screen {
    /** The tabbed home screen; [WalletModel.tab] is the selected tab. */
    data object Home : Screen()
    data object Settings : Screen()
    data object Issuance : Screen()
    data object Presentation : Screen()
    /** [from] is where the Back button returns to. */
    data class DocumentDetail(val documentId: String, val from: Screen = Home) : Screen()
    data class Certificate(val chain: List<X509Cert>, val index: Int, val from: Screen) : Screen()
    /** Documents that can be requested: the cards the TWDIW platform lists, or any issuer address. */
    data object AddDocument : Screen()
    /** Issuers and verifiers on the TWDIW trust list, opened from the settings. */
    data object TrustList : Screen()
    /** X.509 trust anchors of every environment and the DIDs the user trusts, opened from the settings. */
    data object TrustAnchors : Screen()
    /** A code shown at a counter or to a verifier (TWDIW pickup barcode, Bonds frames, Bonds verification). */
    data object Offline : Screen()
    data object MsIssuance : Screen()
    /** In-person presentation by NFC tap or QR code (ISO/IEC 18013-5). */
    data object Proximity : Screen()
}

sealed class IssuanceUi {
    data object Loading : IssuanceUi()
    data class Review(
        val session: IssuanceSession,
        val configurations: List<CredentialConfiguration>,
        val issuerName: String,
        val trust: TrustDecision,
        val preAuthorized: Boolean,
        /** Offered or listed configurations the wallet cannot request, with the reason. */
        val unsupported: List<Pair<String, String>> = emptyList(),
        /** Wallet-initiated: the user picks from everything the issuer lists. */
        val walletInitiated: Boolean = false,
    ) : IssuanceUi()
    data class WaitingForBrowser(val session: IssuanceSession) : IssuanceUi()
    data class Working(val message: String) : IssuanceUi()
    data class Done(val results: List<IssuanceResult>, val failures: List<Pair<String, String>> = emptyList()) : IssuanceUi()
    data class Failed(val message: String) : IssuanceUi()
}

/** A claim the user is about to share, grouped by document. */
data class ConsentItem(
    val documentName: String,
    val claims: List<String>,
    val documentTrust: TrustDecision?,
    val documentId: String? = null,
    /** The most sensitive of [claims] (identifiers and portraits high, names and birth dates medium). */
    val sensitivity: RiskLevel = RiskLevel.LOW,
)

sealed class PresentationUi {
    data object Loading : PresentationUi()
    data class Consent(
        val prepared: PreparedRequest,
        /** Credential choice for an OpenID4VP 1.0 request; null for requests the wallet's own engine matched. */
        val selection: CredentialSelection?,
        val items: List<ConsentItem>,
        /** Fields a TWDIW verifier asks the holder to fill in, sent with the presentation. */
        val fields: List<TwdiwCustomField> = emptyList(),
        /** A TWDIW counter presentation: its barcode is fetched after the response. */
        val offline: TwdiwOfflineSession? = null,
        /** Risk of the request: the most sensitive field asked for, raised for a verifier that is not on an official list. */
        val risk: RiskLevel = RiskLevel.LOW,
    ) : PresentationUi() {
        val request: ValidatedAuthorizationRequest get() = prepared.request
    }
    data class Working(val message: String) : PresentationUi()
    data class Done(val outcome: PresentationOutcome) : PresentationUi()
    data class Failed(val message: String) : PresentationUi()
}

/** A request for the App PIN, answered by the PIN dialog. */
class PinRequest(val reason: String, val result: CompletableDeferred<String?>)

/**
 * Shared wallet state and flows for Android and desktop. Protocol and trust logic lives in core;
 * this class wires it to storage, keys and the UI.
 */
class WalletModel(val platform: PlatformServices) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    val screen = MutableStateFlow<Screen>(Screen.Home)
    val tab = MutableStateFlow(HomeTab.DOCUMENTS)
    /** Interactions with issuers and verifiers, newest first. */
    val history = MutableStateFlow<List<HistoryEntry>>(emptyList())
    val documents = MutableStateFlow<List<Document>>(emptyList())
    val issuance = MutableStateFlow<IssuanceUi>(IssuanceUi.Loading)
    val presentation = MutableStateFlow<PresentationUi>(PresentationUi.Loading)
    val settingsFlow = MutableStateFlow(WalletSettings())
    val pinRequest = MutableStateFlow<PinRequest?>(null)
    val message = MutableStateFlow<String?>(null)
    val ready = MutableStateFlow(false)
    /** Document statuses, kept current in the background. */
    val status = StatusMonitor(this)
    val statuses get() = status.statuses
    /** Stored X.509 anchors (null until loaded) and the DIDs the user trusts, for the trust anchors screen. */
    val anchors = MutableStateFlow<List<StoredAnchor>?>(null)
    val trustedDids = MutableStateFlow<List<UserTrustedDid>>(emptyList())

    lateinit var storage: Storage
        private set
    lateinit var documentStore: DocumentStore
        private set
    lateinit var trust: TrustRegistry
        private set
    lateinit var backends: List<KeyBackend>
        private set
    val documentTypes = DocumentTypeRepository().apply {
        addDocumentType(DrivingLicense.getDocumentType())
        addDocumentType(EUPersonalID.getDocumentType())
    }
    lateinit var source: SimplePresentmentSource
        private set
    val http: HttpClient by lazy {
        platform.httpClient().config { install(TwdiwUserAgent) { userAgent = { settings.twdiwUserAgent } } }
    }
    lateinit var holderIdentities: HolderIdentities
        private set
    private lateinit var historyLog: HistoryLog
    private val historyLock = Mutex()

    /** TWDIW production platform, or in the test environment the configured front end (marked TEST). */
    val twdiwPlatform: TwdiwPlatform
        get() {
            val url = settings.twdiwFrontendUrl.trim().trimEnd('/')
            return if (!settings.testEnvironment || url.isEmpty() || url == TwdiwPlatform.PRODUCTION_FRONTEND) TwdiwPlatform.PRODUCTION
            else TwdiwPlatform(frontendUrl = url, test = true)
        }
    private var twdiwTrustCache: Pair<TwdiwPlatform, TwdiwTrustList>? = null
    val twdiwTrust: TwdiwTrustList
        get() {
            val p = twdiwPlatform
            twdiwTrustCache?.takeIf { it.first == p }?.let { return it.second }
            return TwdiwTrustList(http, p, storage = storage).also { twdiwTrustCache = p to it }
        }
    val linkedDomains: LinkedDomains by lazy { LinkedDomains(http, DidResolver(http)) }
    /** DIDs the user trusts themselves, outside any national list. */
    val userDids: UserDidTrust by lazy { UserDidTrust(storage) }
    /** Trust for parties identified by a DID: the TWDIW trust list first, then Linked Domains, then the user's own list. */
    val didTrust: DidTrust get() = DidTrust(listOf(twdiwTrust, linkedDomains, userDids))
    val twdiwServices: TwdiwServices get() = TwdiwServices(http, twdiwTrust, twdiwPlatform)
    /** One instance, so custom field values attached before a response reach the response. */
    val twdiwPresentation = TwdiwPresentationDialect { did, host -> twdiwTrust.hostRegistered(did, host) }
    private val msPresentation = MsVerifiedIdPresentationDialect()
    fun didResolver() = DidResolver(http, environmentPolicy.insecureLoopbackAllowed)

    val taiwan = TaiwanModel(this)
    val ms = MsIssuanceModel(this)
    val proximity = ProximityModel(this)

    private var issuanceSession: IssuanceSession? = null
    private var dcApiResult: CompletableDeferred<JsonObject?>? = null
    /** Error data for the DC API caller once the user leaves a failed request; null cancels the flow instead. */
    private var dcApiError: JsonObject? = null

    /** The user's languages (BCP 47, most preferred first) with English as the last fallback. */
    val locales: List<String> by lazy {
        (androidx.compose.ui.text.intl.LocaleList.current.localeList.map { it.toLanguageTag() } + "en").distinct()
    }
    /** Claim names in the user's language; names learned from issuer metadata are cached in storage. */
    val claimLabels by lazy { ClaimLabels(locales) }

    val settings: WalletSettings get() = settingsFlow.value
    val environmentPolicy: EnvironmentPolicy
        get() = EnvironmentPolicy(
            testEnvironmentEnabled = settings.testEnvironment,
            allowInsecureLoopbackHttp = settings.allowLoopbackHttp,
        )

    val unlockProvider by lazy { platform.keyUnlockProvider { operationPin("使用軟體金鑰需要 App PIN") } }

    suspend fun init() {
        storage = platform.openStorage()
        settingsFlow.value = loadSettings()
        loadLearnedLabels()
        backends = platform.keyBackends(storage) { reason -> operationPin(reason) }
        val repo = SecureAreaRepository.Builder().apply { backends.map { it.secureArea }.distinct().forEach { add(it) } }.build()
        documentStore = buildDocumentStore(storage, repo) { addDiwCredentialImplementations(repo) }
        holderIdentities = HolderIdentities(storage, repo)
        trust = TrustRegistry(storage, environmentPolicy)
        source = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypes,
            domainsMdocSignature = listOf(CredentialDomains.MDOC),
            domainsKeyBoundSdJwt = listOf(CredentialDomains.SD_JWT),
            domainsKeylessSdJwt = listOf(CredentialDomains.SD_JWT_KEYLESS),
        )
        historyLog = HistoryLog(storage)
        history.value = historyLog.load()
        status.load()
        documents.value = documentStore.listDocuments()
        ready.value = true
        status.refreshDue()
    }

    // ---------------------------------------------------------------- settings

    private suspend fun loadSettings(): WalletSettings {
        val t = storage.getTable(settingsTable)
        val raw = t.get("settings") ?: return WalletSettings()
        return runCatching { DiwJson.decodeFromString(WalletSettings.serializer(), raw.decodeToString()) }.getOrDefault(WalletSettings())
    }

    private suspend fun loadLearnedLabels() {
        val raw = storage.getTable(settingsTable).get("claim-labels") ?: return
        runCatching { DiwJson.parseToJsonElement(raw.decodeToString()).jsonObject }.getOrNull()?.forEach { (k, v) ->
            (v as? JsonPrimitive)?.content?.let { claimLabels.learned[k] = it }
        }
    }

    /** Claim name in the user's language: the issuer's own name, a cached or built-in translation, then [typeName]. */
    fun claimLabel(path: List<String>, typeName: String?, record: IssuanceRecord?): String =
        claimLabels.label(path, record?.claimNames.orEmpty(), typeName?.takeIf { it != path.joinToString(".") })

    /** Caches the claim names an issuer gives, for credentials whose issuer gives none. */
    private suspend fun learnLabels(configurations: Collection<CredentialConfiguration>) {
        if (!claimLabels.learn(configurations)) return
        val t = storage.getTable(settingsTable)
        val bytes = JsonObject(claimLabels.learned.mapValues { JsonPrimitive(it.value) }).toString().encodeToByteString()
        if (t.get("claim-labels") == null) t.insert("claim-labels", bytes) else t.update("claim-labels", bytes)
    }

    fun updateSettings(transform: (WalletSettings) -> WalletSettings) = scope.launch {
        val s = transform(settings)
        settingsFlow.value = s
        trust.policy = environmentPolicy
        val t = storage.getTable(settingsTable)
        val bytes = DiwJson.encodeToString(WalletSettings.serializer(), s).encodeToByteString()
        if (t.get("settings") == null) t.insert("settings", bytes) else t.update("settings", bytes)
    }

    /** Imports the TEST anchors published by the DIW test servers (issuer IACA, verifier root, wallet provider root). */
    fun importTestAnchors() = scope.launch {
        if (!settings.testEnvironment) {
            message.value = "請先開啟測試環境"
            return@launch
        }
        try {
            val base = settings.testServerUrl.trimEnd('/')
            if (!isAcceptableEndpoint(base, environmentPolicy.insecureLoopbackAllowed)) {
                message.value = "測試伺服器網址需為 https；本機或區網的 http 位址請先開啟「允許本機與區網 HTTP」"
                return@launch
            }
            val pairs = listOf(
                Triple(TrustRole.ISSUER, "iaca.pem", "DIW TEST IACA"),
                Triple(TrustRole.STATUS_LIST, "iaca.pem", "DIW TEST IACA"),
                Triple(TrustRole.VERIFIER, "verifier-root.pem", "DIW TEST Verifier Root"),
                Triple(TrustRole.WALLET_PROVIDER, "wallet-provider-root.pem", "DIW TEST Wallet Provider"),
            )
            // A Multipaz OpenID4VCI server has no /pki; its IACA is served per credential configuration.
            if (!http.get("$base/pki/iaca.pem").status.isSuccess()) {
                val n = addMultipazIssuerAnchors(base)
                message.value = "已從 Multipaz 發行端匯入 $n 個測試信任錨點（僅測試環境有效）"
                return@launch
            }
            var added = 0
            for ((role, file, name) in pairs) {
                val resp = http.get("$base/pki/$file")
                if (!resp.status.isSuccess()) throw ProtocolException("anchor_fetch", "$file HTTP ${resp.status.value}")
                val cert = X509Cert.fromPem(resp.bodyAsText())
                if (trust.addAnchor(role, TrustEnvironment.TEST, cert, name, official = false, source = base)) added++
            }
            message.value = "已匯入 $added 個測試信任錨點（僅測試環境有效）"
        } catch (e: Exception) {
            message.value = "匯入失敗：${e.message}"
        }
    }

    /**
     * Imports the EUDI reference implementation CAs (they sign the EUDI test issuers' credentials and the
     * verifier.eudiw.dev request certificates) as TEST anchors.
     */
    fun importEudiTestAnchors() = scope.launch {
        if (!settings.testEnvironment) {
            message.value = "請先開啟測試環境"
            return@launch
        }
        try {
            var added = 0
            for (name in listOf("pidissuerca02_eu", "pidissuerca02_ut")) {
                val resp = http.get("$EUDI_ANCHORS/$name.pem")
                if (!resp.status.isSuccess()) throw ProtocolException("anchor_fetch", "$name HTTP ${resp.status.value}")
                val cert = X509Cert.fromPem(resp.bodyAsText())
                for (role in listOf(TrustRole.ISSUER, TrustRole.VERIFIER, TrustRole.STATUS_LIST)) {
                    if (trust.addAnchor(role, TrustEnvironment.TEST, cert, "EUDI 參考實作 $name", official = false, source = EUDI_ANCHORS)) added++
                }
            }
            message.value = "已匯入 $added 個 EUDI 測試信任錨點（僅測試環境有效）"
        } catch (e: Exception) {
            message.value = "匯入失敗：${e.message}"
        }
    }

    /** Imports the IACA certificates of the public Multipaz test issuer as TEST anchors. */
    fun importMultipazTestAnchors() = scope.launch {
        if (!settings.testEnvironment) {
            message.value = "請先開啟測試環境"
            return@launch
        }
        try {
            val n = addMultipazIssuerAnchors(MULTIPAZ_ISSUER)
            message.value = "已匯入 $n 個 Multipaz 測試信任錨點（僅測試環境有效）"
        } catch (e: Exception) {
            message.value = "匯入失敗：${e.message}"
        }
    }

    /**
     * Reads the credential issuer metadata at [base] (or [base]/issuer) and adds the certificate each configuration's
     * signing_certificate endpoint returns (the root of its signing chain) as ISSUER and STATUS_LIST TEST anchors.
     */
    private suspend fun addMultipazIssuerAnchors(base: String): Int {
        val root = base.trimEnd('/')
        val (issuer, meta) = listOf(root, "$root/issuer").firstNotNullOfOrNull { candidate ->
            val r = http.get("$candidate/.well-known/openid-credential-issuer")
            if (!r.status.isSuccess()) null
            else runCatching { DiwJson.parseToJsonElement(r.bodyAsText()) as JsonObject }.getOrNull()?.let { candidate to it }
        } ?: throw ProtocolException("anchor_fetch", "$root 不是 DIW 測試伺服器（無 /pki/iaca.pem），也不是 Multipaz 發行端")
        val configs = (meta["credential_configurations_supported"] as? JsonObject)?.keys.orEmpty()
        val certs = configs.mapNotNull { id ->
            val r = http.get("$issuer/signing_certificate?credential_id=$id")
            if (r.status.isSuccess()) runCatching { X509Cert.fromPem(r.bodyAsText()) }.getOrNull() else null
        }.distinctBy { it.encoded }
        if (certs.isEmpty()) throw ProtocolException("anchor_fetch", "$issuer 沒有提供 signing_certificate")
        var added = 0
        for (cert in certs) {
            val name = "Multipaz " + (cert.subject.components[OID.COMMON_NAME.oid]?.value ?: issuer)
            for (role in listOf(TrustRole.ISSUER, TrustRole.STATUS_LIST)) {
                if (trust.addAnchor(role, TrustEnvironment.TEST, cert, name, official = false, source = issuer)) added++
            }
        }
        return added
    }

    // ---------------------------------------------------------------- PIN

    suspend fun requestPin(reason: String): String? {
        val req = PinRequest(reason, CompletableDeferred())
        pinRequest.value = req
        return try { req.result.await() } finally { pinRequest.value = null }
    }

    private var pinCache: String? = null

    /**
     * App PIN for software keys, asked once per user operation (one issuance batch or one presentation)
     * instead of once per key; [endOperation] forgets it.
     */
    private suspend fun operationPin(reason: String): String? =
        pinCache ?: requestPin(reason)?.also { pinCache = it }

    fun endOperation() {
        pinCache = null
    }

    // ---------------------------------------------------------------- documents

    /** Shows the home screen on [t]. */
    fun showTab(t: HomeTab) {
        tab.value = t
        screen.value = Screen.Home
    }

    /**
     * Goes back one screen, as the Back button does. On the home screen another tab returns to the documents tab;
     * false on the documents tab, where the platform handles it.
     */
    fun back(): Boolean {
        when (val s = screen.value) {
            Screen.Home -> {
                if (tab.value == HomeTab.DOCUMENTS) return false
                tab.value = HomeTab.DOCUMENTS
            }
            is Screen.DocumentDetail -> screen.value = s.from
            is Screen.Certificate -> screen.value = s.from
            Screen.Issuance -> {
                cancelBrowserWait()
                screen.value = Screen.Home
            }
            Screen.Presentation -> {
                leaveDcApi()
                screen.value = Screen.Home
            }
            Screen.Settings -> screen.value = Screen.Home
            Screen.AddDocument -> screen.value = Screen.Home
            Screen.TrustList -> screen.value = Screen.Settings
            Screen.TrustAnchors -> screen.value = Screen.Settings
            Screen.Offline -> {
                taiwan.closeOffline()
                screen.value = Screen.Home
            }
            Screen.MsIssuance -> {
                ms.cancel()
                screen.value = Screen.Home
            }
            Screen.Proximity -> {
                proximity.close()
                showTab(HomeTab.USE)
            }
        }
        return true
    }

    fun refreshDocuments() = scope.launch {
        documents.value = documentStore.listDocuments()
    }

    fun deleteDocument(doc: Document) = scope.launch {
        documentStore.deleteDocument(doc.identifier)
        status.forget(doc.identifier)
        refreshDocuments()
        platform.registerDigitalCredentials(this@WalletModel)
        showTab(HomeTab.DOCUMENTS)
    }

    // ---------------------------------------------------------------- history

    /** Adds an entry to the history log. Claim values are never recorded, only their names. */
    fun record(
        kind: HistoryKind,
        party: String,
        trust: TrustDecision?,
        documents: List<String> = emptyList(),
        claims: List<String> = emptyList(),
        note: String? = null,
        failure: String? = null,
        status: String? = null,
    ) {
        val entry = HistoryEntry(
            id = PlatformCrypto.randomBytes(9).toBase64Url(),
            epochSeconds = kotlin.time.Clock.System.now().epochSeconds,
            kind = kind,
            party = party,
            tier = trust?.tier?.name,
            test = trust?.environment == TrustEnvironment.TEST,
            documents = documents,
            claims = claims.distinct(),
            note = note,
            failure = failure,
            status = status,
        )
        scope.launch {
            historyLock.withLock {
                val list = (listOf(entry) + history.value).take(HistoryLog.MAX)
                history.value = list
                runCatching { historyLog.save(list) }
            }
        }
    }

    fun clearHistory() = scope.launch {
        historyLock.withLock {
            history.value = emptyList()
            runCatching { historyLog.save(emptyList()) }
        }
    }

    // ---------------------------------------------------------------- card art

    /** Decoded card logos by URI; SVG and unreachable logos stay absent and the card shows its category icon. */
    val cardArt = MutableStateFlow<Map<String, ImageBitmap>>(emptyMap())
    private val artRequested = mutableSetOf<String>()

    fun loadCardArt(uri: String) {
        if (uri in cardArt.value || !artRequested.add(uri)) return
        scope.launch {
            val image = runCatching { fetchArt(uri) }.getOrNull()?.let { platform.decodeImage(it) } ?: return@launch
            cardArt.value = cardArt.value + (uri to image)
        }
    }

    /** Logo bytes from a data: URI or an https URL, cached in storage so cards render offline. */
    private suspend fun fetchArt(uri: String): ByteArray? {
        if (uri.startsWith("data:image/")) return uri.substringAfter("base64,", "").ifEmpty { null }?.fromBase64()
        if (!isAcceptableEndpoint(uri, environmentPolicy.insecureLoopbackAllowed)) return null
        val key = PlatformCrypto.sha256(uri.encodeToByteArray()).toBase64Url()
        val t = storage.getTable(artTable)
        t.get(key)?.let { return it.toByteArray() }
        val resp = http.get(uri)
        if (!resp.status.isSuccess()) return null
        val bytes = resp.readRawBytes()
        if (bytes.size > MAX_ART_BYTES || platform.decodeImage(bytes) == null) return null
        t.insert(key, ByteString(bytes))
        return bytes
    }

    /** Queries [doc]'s status now. */
    fun checkStatus(doc: Document) = status.refresh(doc)

    // ---------------------------------------------------------------- entry

    /**
     * Dispatches any wallet URI: credential offers, presentation requests, the OID4VCI redirect, TWDIW entry
     * points (deep links, relay pages, static codes), Bonds challenges and Microsoft Verified ID requests.
     */
    fun handleUri(uri: String) {
        val u = uri.trim()
        val scheme = u.substringBefore(':').lowercase()
        if (ms.isLoginRedirect(u)) {
            ms.completeLogin(u)
            return
        }
        if (u.startsWith(platform.oid4vciRedirectUri)) {
            completeAuthorization(u)
            return
        }
        if (BondsPresentationRequest.looksLike(u)) {
            taiwan.startBonds(u)
            return
        }
        if (BondsQrTransport.isFrame(u)) {
            taiwan.acceptVerifierFrame(u)
            return
        }
        when (val entry = TwdiwEntryParser.parse(u)) {
            is TwdiwEntry.Offer -> return startIssuance(entry.uri, TwdiwEntry.ENTRY_HINT)
            is TwdiwEntry.Presentation -> return startPresentation(entry.uri, TwdiwEntry.ENTRY_HINT)
            is TwdiwEntry.StaticQr -> return taiwan.openStatic(entry)
            null -> {}
        }
        when {
            scheme == "openid-vc" -> startVerifiedId(u)
            scheme in setOf("openid-credential-offer", "haip-vci") || "credential_offer" in u -> startIssuance(u)
            scheme in setOf("openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp", "openid", "siopv2") ||
                ("client_id=" in u && scheme == "https") -> startPresentation(u)
            // A bare issuer address: list what it issues and let the user pick (wallet-initiated issuance).
            scheme == "https" || scheme == "http" -> startFromIssuer(u)
            '.' in u && ' ' !in u && ':' !in u -> startFromIssuer("https://$u")
            else -> message.value = "無法辨識的連結"
        }
    }

    /** openid-vc: a Verified ID issuance request (prompt=create) or a presentation request. */
    private fun startVerifiedId(uri: String) {
        presentation.value = PresentationUi.Loading
        screen.value = Screen.Presentation
        scope.launch {
            try {
                if (ms.start(uri)) return@launch
                val h = holder()
                presentation.value = consentFor(h.prepare(h.resolveUri(uri, MsVerifiedIdPresentationDialect.ENTRY_HINT)))
            } catch (e: Exception) {
                presentation.value = PresentationUi.Failed(describe(e))
            }
        }
    }

    // ---------------------------------------------------------------- issuance

    private fun oid4vci(): Oid4vciClient = Oid4vciClient(
        http, trust, environmentPolicy, walletProvider(), documentStore,
        locales = locales,
        dialects = issuanceDialects(),
        holderIdentities = holderIdentities,
        didTrust = didTrust,
    )

    /**
     * Always on: each dialect only takes sessions it owns (TWDIW hosts or entry, draft 11/13 metadata); the EUDI
     * dialect only answers an authorization response iss below the authorization server's own issuer.
     */
    private fun issuanceDialects() = environmentPolicy.insecureLoopbackAllowed.let { loopback ->
        listOf(TwdiwDialect(http, loopback) { settings.twdiwClientId }, Draft13Dialect(http, loopback), Draft11Dialect(), EudiDialect())
    }

    private var cachedProvider: WalletProvider? = null

    private fun walletProvider(): WalletProvider {
        val s = settings
        if (!(s.testEnvironment && s.useWalletProvider)) return PublicClientWalletProvider(s.clientId)
        cachedProvider?.let { return it }
        return object : WalletProvider {
            override val clientId: String = s.clientId
            private var remote: RemoteWalletProvider? = null
            private suspend fun get(): RemoteWalletProvider = remote ?: run {
                val (key, att) = instanceKey()
                RemoteWalletProvider(http, s.testServerUrl.trimEnd('/') + "/wallet-provider", s.clientId, key, att, environmentPolicy.insecureLoopbackAllowed)
            }.also { remote = it }
            override suspend fun walletAttestation() = get().walletAttestation()
            override suspend fun keyAttestation(keys: List<org.multipaz.securearea.KeyAttestation>, nonce: String?, userAuthentication: Boolean) =
                get().keyAttestation(keys, nonce, userAuthentication)
        }.also { cachedProvider = it }
    }

    /** Wallet instance key: no user authentication, attested by the platform where possible. */
    private suspend fun instanceKey(): Pair<AsymmetricKey, org.multipaz.securearea.KeyAttestation?> {
        val backend = backends.firstOrNull { it.protection.hardware } ?: backends.first()
        val alias = settings.instanceKeyAlias
        val info = if (alias != null) runCatching { backend.secureArea.getKeyInfo(alias) }.getOrNull() else null
        val keyInfo = info ?: run {
            val created = backend.secureArea.createKey(null, backend.settings(ByteString(PlatformCrypto.randomBytes(16)), false))
            updateSettings { it.copy(instanceKeyAlias = created.alias) }
            created
        }
        return AsymmetricKey.AnonymousSecureAreaBased(keyInfo.alias, backend.secureArea, keyInfo, algorithm = org.multipaz.crypto.Algorithm.ES256) to keyInfo.attestation
    }

    fun startIssuance(uri: String, entryHint: String? = null) {
        issuance.value = IssuanceUi.Loading
        screen.value = Screen.Issuance
        scope.launch {
            try {
                val c = oid4vci()
                val session = c.startFromOffer(uri, entryHint)
                issuanceSession = session
                learnLabels(session.issuer.configurations.values)
                val issuerName = session.issuer.display.pick(locales)?.name ?: session.issuer.credentialIssuer
                issuance.value = IssuanceUi.Review(
                    session = session,
                    configurations = session.offeredConfigurations,
                    issuerName = issuerName,
                    trust = session.issuer.trust,
                    preAuthorized = session.offer?.preAuthorized != null,
                    unsupported = session.offer?.credentialConfigurationIds.orEmpty()
                        .filter { it !in session.issuer.configurations }
                        .map { it to (session.issuer.unsupported[it] ?: "發行端資訊未列出此設定") },
                )
            } catch (e: Exception) {
                issuance.value = IssuanceUi.Failed(describe(e))
            }
        }
    }

    /** Wallet-initiated issuance from a credential issuer URL: fetch its metadata and list every configuration. */
    fun startFromIssuer(url: String) {
        issuance.value = IssuanceUi.Loading
        screen.value = Screen.Issuance
        scope.launch {
            try {
                val c = oid4vci()
                val base = url.substringBefore('?').substringBefore('#')
                val root = base.trimEnd('/')
                // A bare host often serves its issuer under a path (Multipaz /issuer, walt.id /draft13, others /openid4vci).
                val hostOnly = root.substringAfter("://").substringBefore('/') == root.substringAfter("://")
                val candidates = (listOf(base, root) + if (hostOnly) ISSUER_PATHS.map { root + it } else emptyList()).distinct()
                var last: Exception? = null
                val session = candidates.firstNotNullOfOrNull { candidate ->
                    try { c.startWalletInitiated(candidate, emptyList()) } catch (e: Exception) { last = e; null }
                } ?: throw last ?: ProtocolException("invalid_issuer_metadata", "No issuer metadata at $url")
                issuanceSession = session
                val issuer = session.issuer
                learnLabels(issuer.configurations.values)
                if (session.authServer.authorizationEndpoint == null) {
                    throw ProtocolException("unsupported_grant", "此發行端只接受由它產生的領卡連結（預授權碼），請從發行端網頁取得 QR Code 或連結")
                }
                issuance.value = IssuanceUi.Review(
                    session = session,
                    configurations = issuer.configurations.values.sortedBy { it.display.pick(locales)?.name ?: it.id },
                    issuerName = issuer.display.pick(locales)?.name ?: issuer.credentialIssuer,
                    trust = issuer.trust,
                    preAuthorized = false,
                    unsupported = issuer.unsupported.toList(),
                    walletInitiated = true,
                )
            } catch (e: Exception) {
                issuance.value = IssuanceUi.Failed(describe(e))
            }
        }
    }

    /** User accepted the offer. [txCode] is the PIN from the issuer when the offer asks for one; [selected] are the chosen configuration ids. */
    fun acceptOffer(review: IssuanceUi.Review, txCode: String?, selected: List<String> = review.configurations.map { it.id }) = scope.launch {
        val c = oid4vci()
        try {
            if (selected.isEmpty()) throw ProtocolException("invalid_request", "請至少選擇一種憑證")
            review.session.select(selected)
            if (review.preAuthorized) {
                issuance.value = IssuanceUi.Working("向發行端取得授權")
                try {
                    c.authorizePreAuthorized(review.session, txCode)
                } catch (e: Exception) {
                    recordIssuanceFailure(review.session, describe(e))
                    throw e
                }
                issueAll(c, review.session)
            } else {
                val url = c.beginAuthorizationCode(review.session, platform.oid4vciRedirectUri)
                if (!Oid4vciClient.isSafeAuthorizationUrl(url, environmentPolicy.insecureLoopbackAllowed)) {
                    throw ProtocolException("invalid_request", "授權頁面網址不安全")
                }
                issuance.value = IssuanceUi.WaitingForBrowser(review.session)
                platform.openBrowser(url)
            }
        } catch (e: Exception) {
            issuance.value = IssuanceUi.Failed(describe(e))
        }
    }

    private var leftForBrowser = false

    /** The app went to the background (on Android: the login page opened in a browser tab). */
    fun onAppPaused() {
        if (issuance.value is IssuanceUi.WaitingForBrowser) leftForBrowser = true
    }

    /**
     * The app came back. If the browser was closed, or the issuer showed an error page, no redirect arrives;
     * after a short grace period for a redirect that is on its way, the wait ends instead of spinning forever.
     */
    fun onAppResumed() {
        if (ready.value) status.refreshDue()
        if (!leftForBrowser) return
        leftForBrowser = false
        val waiting = issuance.value as? IssuanceUi.WaitingForBrowser ?: return
        scope.launch {
            kotlinx.coroutines.delay(2500)
            if (issuance.value === waiting) {
                issuance.value = IssuanceUi.Failed("登入或授權沒有完成：瀏覽器已關閉，或發行端在網頁上回報錯誤。可以重新掃描或輸入領卡連結再試一次。")
            }
        }
    }

    /** User gave up waiting for the browser. */
    fun cancelBrowserWait() {
        if (issuance.value is IssuanceUi.WaitingForBrowser) issuance.value = IssuanceUi.Failed("已取消登入")
        issuanceSession = null
    }

    private fun completeAuthorization(redirect: String) {
        val session = issuanceSession ?: run { message.value = "沒有進行中的發證流程"; return }
        screen.value = Screen.Issuance
        scope.launch {
            val c = oid4vci()
            try {
                issuance.value = IssuanceUi.Working("完成授權")
                c.completeAuthorizationCode(session, redirect)
            } catch (e: Exception) {
                recordIssuanceFailure(session, describe(e))
                issuance.value = IssuanceUi.Failed(describe(e))
                return@launch
            }
            try {
                issueAll(c, session)
            } catch (e: Exception) {
                issuance.value = IssuanceUi.Failed(describe(e))
            }
        }
    }

    /** Issues every selected configuration; one failing configuration does not stop the others. */
    private suspend fun issueAll(c: Oid4vciClient, session: IssuanceSession) {
        val results = mutableListOf<IssuanceResult>()
        val failures = mutableListOf<Pair<String, String>>()
        try {
            withContext(unlockProvider) {
                for (config in session.selectedConfigurations) {
                    val name = config.display.pick(locales)?.name ?: config.id
                    issuance.value = IssuanceUi.Working("領取 $name")
                    try {
                        var r = c.issue(session, config.id, keyRequest())
                        var polls = 0
                        while (r is IssuanceResult.Deferred && polls < 10) {
                            kotlinx.coroutines.delay(r.intervalSeconds.coerceIn(1, 30) * 1000)
                            r = c.pollDeferred(session, r)
                            polls++
                        }
                        if (r is IssuanceResult.Issued) r.notificationId?.let { runCatching { c.notify(session, it, "credential_accepted") } }
                        results += r
                    } catch (e: Exception) {
                        failures += name to describe(e)
                    }
                }
            }
        } finally {
            endOperation()
        }
        refreshDocuments()
        platform.registerDigitalCredentials(this)
        results.filterIsInstance<IssuanceResult.Issued>().forEach { status.refresh(it.document) }
        val issuerName = issuerName(session)
        results.forEach { r ->
            record(
                HistoryKind.ISSUED, issuerName, (r as? IssuanceResult.Issued)?.trust ?: session.issuer.trust,
                documents = listOf(r.document.displayName ?: "證件"),
                note = if (r is IssuanceResult.Deferred) "發行端尚未完成（延遲發證）" else null,
            )
        }
        failures.forEach { (name, reason) -> record(HistoryKind.ISSUED, issuerName, session.issuer.trust, listOf(name), failure = reason) }
        issuance.value = if (results.isEmpty() && failures.size == 1) IssuanceUi.Failed(failures.single().second)
        else IssuanceUi.Done(results, failures)
    }

    private fun issuerName(session: IssuanceSession) = session.issuer.display.pick(locales)?.name ?: session.issuer.credentialIssuer

    /** Authorization failed after the user accepted: the documents they asked for are recorded as not received. */
    private fun recordIssuanceFailure(session: IssuanceSession, reason: String) {
        val names = session.selectedConfigurations.map { it.display.pick(locales)?.name ?: it.id }
        record(HistoryKind.ISSUED, issuerName(session), session.issuer.trust, names, failure = reason)
    }

    fun keyRequest(): KeyRequest {
        val backend = backends.first()
        val userAuth = settings.requireUserAuth || !backend.protection.hardware
        return KeyRequest(
            secureArea = backend.secureArea,
            createKeySettings = { challenge -> backend.settings(challenge, userAuth) },
            count = 3,
            userAuthentication = userAuth,
            keyStorage = backend.protection.wire,
        )
    }

    // ---------------------------------------------------------------- presentation

    fun holder() = Oid4vpHolder(
        http, trust, source, environmentPolicy, PresentationPolicy(),
        holderIdentities = holderIdentities,
        didTrust = didTrust,
        dialects = listOf(twdiwPresentation, msPresentation),
    )

    fun startPresentation(uri: String, entryHint: String? = null, fields: List<TwdiwCustomField> = emptyList(), offline: TwdiwOfflineSession? = null) {
        presentation.value = PresentationUi.Loading
        screen.value = Screen.Presentation
        scope.launch {
            try {
                val h = holder()
                val request = h.resolveUri(uri, entryHint)
                offline?.let { twdiwServices.checkOfflineRequest(it, request) }
                presentation.value = consentFor(h.prepare(request), fields, offline)
            } catch (e: Exception) {
                presentation.value = PresentationUi.Failed(describe(e))
            }
        }
    }

    /**
     * Digital Credentials API entry (Android Credential Manager). Completes with the response data (an OpenID4VP error
     * included), or null to cancel the flow. A failed request stays on screen until the user leaves it, so the reason
     * can be read instead of the caller only seeing a cancelled request.
     */
    suspend fun presentDcApi(protocol: String, data: JsonObject, origin: String): JsonObject? {
        val done = startDcApi()
        try {
            val h = holder()
            presentation.value = consentFor(h.prepare(h.resolveDcApi(protocol, data, origin)))
        } catch (e: Exception) {
            dcApiError = Oid4vpHolder.dcApiError(data, e)
            presentation.value = PresentationUi.Failed(describe(e))
        }
        return done.await()
    }

    /** Shows why a DC API request cannot be handled at all; completes with null (cancel) when the user leaves. */
    suspend fun failDcApi(reason: String): JsonObject? {
        val done = startDcApi()
        presentation.value = PresentationUi.Failed(reason)
        return done.await()
    }

    private fun startDcApi(): CompletableDeferred<JsonObject?> {
        dcApiError = null
        presentation.value = PresentationUi.Loading
        screen.value = Screen.Presentation
        return CompletableDeferred<JsonObject?>().also { dcApiResult = it }
    }

    private suspend fun consentFor(
        prepared: PreparedRequest,
        fields: List<TwdiwCustomField> = emptyList(),
        offline: TwdiwOfflineSession? = null,
    ): PresentationUi.Consent {
        val consent = when (prepared) {
            is PreparedPresentation -> {
                val selection = prepared.queryResult.select(emptyList())
                val items = selection.matches.map { m ->
                    val doc = m.credential.document
                    ConsentItem(
                        documentName = doc.displayName ?: "憑證",
                        claims = m.claims.values.map { claimLabel(ClaimReader.pathOf(it), it.displayName, doc.issuanceRecord) },
                        documentTrust = null,
                        documentId = doc.identifier,
                        sensitivity = ClaimSensitivity.ofAll(m.claims.values.map { ClaimReader.pathOf(it) }),
                    )
                }
                PresentationUi.Consent(prepared, selection, items, fields, offline)
            }
            is PreparedExtended -> {
                val items = prepared.lines.map { line ->
                    val record = line.document.issuanceRecord
                    ConsentItem(
                        line.documentName, line.claims.map { claimLabels.label(it.split('.'), record?.claimNames.orEmpty(), null) }, null,
                        documentId = line.document.identifier,
                        sensitivity = ClaimSensitivity.ofAll(line.claims.map { it.split('.') }),
                    )
                }
                PresentationUi.Consent(prepared, null, items, fields, offline)
            }
        }
        val risk = requestRisk(consent.items, consent.request.verifier.trust.tier)
        // A status older than the request's risk allows is queried again while the user reads the request.
        status.refreshFor(consent.items.mapNotNull { it.documentId }, risk)
        return consent.copy(risk = risk)
    }

    /** [values] are the holder's entries for the request's custom fields, by field name. */
    fun approve(consent: PresentationUi.Consent, values: Map<String, String> = emptyMap()) = scope.launch {
        presentation.value = PresentationUi.Working("產生並送出回應")
        try {
            if (consent.fields.isNotEmpty()) {
                twdiwPresentation.attachCustomData(consent.request.nonce, consent.fields.map { it.copy(value = values[it.ename].orEmpty()) })
            }
            val outcome = try {
                withContext(unlockProvider) {
                    when (val p = consent.prepared) {
                        is PreparedExtended -> holder().respond(p)
                        is PreparedPresentation -> holder().respond(p, consent.selection ?: p.queryResult.select(emptyList()))
                    }
                }
            } finally {
                endOperation()
            }
            when (outcome) {
                is PresentationOutcome.DcApi -> {
                    dcApiResult?.complete(outcome.data)
                    dcApiResult = null
                }
                is PresentationOutcome.Posted -> outcome.redirectUri?.let { platform.openRedirect(it) }
                is PresentationOutcome.Redirect -> platform.openRedirect(outcome.url)
            }
            refreshDocuments()
            recordPresentation(HistoryKind.PRESENTED, consent)
            val offline = consent.offline
            if (offline != null) {
                presentation.value = PresentationUi.Done(outcome)
                taiwan.fetchBarcode(offline)
            } else {
                presentation.value = PresentationUi.Done(outcome)
            }
        } catch (e: Exception) {
            recordPresentation(HistoryKind.PRESENTED, consent, describe(e))
            presentation.value = PresentationUi.Failed(describe(e))
        }
    }

    private fun recordPresentation(kind: HistoryKind, consent: PresentationUi.Consent, failure: String? = null) {
        val v = consent.request.verifier
        val note = consent.offline?.service?.name ?: if (consent.request.responseMode.dcApi) "經由瀏覽器或 App（Digital Credentials API）" else null
        record(kind, v.displayName, v.trust, consent.items.map { it.documentName }, consent.items.flatMap { it.claims }, note, failure)
    }

    fun decline(consent: PresentationUi.Consent) = scope.launch {
        // Over the DC API the refusal (access_denied) goes back to the caller; otherwise it is posted to an authenticated Verifier.
        val outcome = runCatching { holder().decline(consent.request) }.getOrNull()
        recordPresentation(HistoryKind.DECLINED, consent)
        dcApiResult?.complete((outcome as? PresentationOutcome.DcApi)?.data)
        dcApiResult = null
        presentation.value = PresentationUi.Failed("已拒絕分享")
    }

    /** Ends a pending DC API request when the user leaves the presentation: a reportable failure goes to the caller, anything else cancels. */
    fun leaveDcApi() {
        dcApiResult?.complete(dcApiError)
        dcApiResult = null
        dcApiError = null
    }

    // ---------------------------------------------------------------- trust anchors

    fun loadAnchors() = scope.launch {
        anchors.value = trust.allAnchors().sortedWith(compareBy({ it.environment.ordinal }, { it.metadata.displayName }))
        trustedDids.value = userDids.all().sortedBy { it.name }
    }

    /**
     * Imports the certificates in [input] (PEM text, or an https address serving PEM) as the user's own anchors for
     * [roles]. They are trusted in production use, marked as the user's (T3, never official).
     */
    fun importAnchor(input: String, name: String, roles: Set<TrustRole>) = scope.launch {
        try {
            if (roles.isEmpty()) throw ProtocolException("invalid_request", "請至少選擇一種用途")
            val text = input.trim()
            val source = if (text.startsWith("https://") || text.startsWith("http://")) text else "pasted"
            val pem = if (source != "pasted") {
                if (!isAcceptableEndpoint(text, environmentPolicy.insecureLoopbackAllowed)) throw ProtocolException("invalid_request", "憑證網址需為 https")
                val resp = http.get(text)
                if (!resp.status.isSuccess()) throw ProtocolException("anchor_fetch", "HTTP ${resp.status.value}")
                resp.bodyAsText()
            } else text
            val certs = PEM_CERT.findAll(pem).map { X509Cert.fromPem(it.value) }.toList()
            if (certs.isEmpty()) throw ProtocolException("invalid_request", "找不到 PEM 格式的憑證（-----BEGIN CERTIFICATE-----）")
            val now = kotlin.time.Clock.System.now()
            var added = 0
            for (cert in certs) {
                if (cert.validityNotAfter < now) throw ProtocolException("invalid_request", "憑證已於 ${cert.validityNotAfter} 過期")
                val cn = cert.subject.components[OID.COMMON_NAME.oid]?.value ?: cert.displaySubject()
                val label = name.trim().ifEmpty { cn }.let { if (certs.size > 1 && name.isNotBlank()) "$it（$cn）" else it }
                for (role in roles) if (trust.addAnchor(role, TrustEnvironment.USER, cert, label, official = false, source = source)) added++
            }
            message.value = if (added == 0) "這些憑證已經是信任錨點" else "已加入 $added 個信任錨點（使用者自訂，信任等級 T3）"
            loadAnchors()
        } catch (e: Exception) {
            message.value = "匯入失敗：" + describe(e)
        }
    }

    fun removeAnchor(anchor: StoredAnchor) = scope.launch {
        if (anchor.environment == TrustEnvironment.PRODUCTION) return@launch
        trust.removeAnchor(anchor)
        loadAnchors()
    }

    /** Trusts [did] for [roles] as the user's own anchor. */
    fun trustDid(did: String, name: String, roles: Set<TrustRole>) = scope.launch {
        try {
            if (roles.isEmpty()) throw ProtocolException("invalid_request", "請至少選擇一種用途")
            val d = did.trim()
            // The DID must resolve, so a typo is caught now rather than at the next issuance.
            didResolver().resolveKey(d, null)
            userDids.put(d, name, roles, kotlin.time.Clock.System.now().epochSeconds)
            message.value = "已信任 ${name.trim().ifEmpty { d }}"
            loadAnchors()
        } catch (e: Exception) {
            message.value = "無法加入：" + describe(e)
        }
    }

    fun untrustDid(did: String) = scope.launch {
        userDids.remove(did)
        loadAnchors()
    }

    // ---------------------------------------------------------------- helpers

    fun describe(e: Throwable): String = when (e) {
        is diw.wallet.core.oid4vp.RequestValidationException -> "請求驗證失敗（${e.code}）：${e.message}"
        is ProtocolException -> "協定錯誤（${e.code}）：${e.message}" + hint(e)
        // Platform errors wrap the reason (e.g. Android Keystore "Error creating key"), so the causes are shown too.
        else -> generateSequence(e) { it.cause }.take(4).mapNotNull { it.message ?: it::class.simpleName }.distinct()
            .joinToString("：").ifEmpty { "未知錯誤" }
    }

    /** A next step for failures with a known cause. */
    private fun hint(e: ProtocolException): String {
        val m = e.message ?: return ""
        return when {
            "No test found with alias" in m -> "\n這是 OpenID 認證測試套件：需先在套件網頁啟動測試模組，等它顯示等待錢包時再掃描或貼上它給的連結。"
            "1010" in m || ("403" in m && "wallet.gov.tw" in m) -> "\n數位憑證皮夾的伺服器拒絕了連線，可在設定調整送往 wallet.gov.tw 的 User-Agent 後再試。"
            e.code == "untrusted_verifier" -> "\n對方不在數位憑證皮夾的信任清單或未在區塊鏈上註冊，為保護資料已停止。"
            else -> ""
        }
    }

    companion object {
        /** One spec per table name and process: storage rejects a second spec object for the same table. */
        private val settingsTable = StorageTableSpec(name = "DiwSettings", supportPartitions = false, supportExpiration = false)
        private val artTable = StorageTableSpec(name = "DiwCardArt", supportPartitions = false, supportExpiration = false)
        const val MAX_ART_BYTES = 1024 * 1024
        val ISSUER_PATHS = listOf("/issuer", "/draft13", "/openid4vci", "/oid4vci", "/v1")
        const val MULTIPAZ_ISSUER = "https://issuer.multipaz.org/issuer"
        const val EUDI_ANCHORS = "https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/main/resources-logic/src/main/res/raw"

        fun tierTitle(t: TrustTier): String = when (t) {
            TrustTier.T1 -> "T1 官方已驗證"
            TrustTier.T2 -> "T2 已驗證身分"
            TrustTier.T3 -> "T3 可驗證但非官方"
            TrustTier.T4 -> "T4 無法驗證"
        }

        fun randomId() = PlatformCrypto.randomBytes(9).toBase64Url()

        private val PEM_CERT = Regex("-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\\s]+-----END CERTIFICATE-----")

        /** Risk a verifier adds to a request: none when officially listed, high when its identity cannot be verified. */
        fun verifierRisk(tier: TrustTier): RiskLevel = when (tier) {
            TrustTier.T1 -> RiskLevel.LOW
            TrustTier.T2, TrustTier.T3 -> RiskLevel.MEDIUM
            TrustTier.T4 -> RiskLevel.HIGH
        }

        fun requestRisk(items: List<ConsentItem>, verifierTier: TrustTier): RiskLevel =
            items.fold(verifierRisk(verifierTier)) { acc, i -> RiskLevel.max(acc, i.sensitivity) }
    }
}

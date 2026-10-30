package diw.wallet.app

import diw.wallet.core.compat.Draft11Dialect
import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.compat.EudiDialect
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.did.DidResolver
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.federation.FederationAnchor
import diw.wallet.core.federation.FederationAnchors
import diw.wallet.core.federation.FederationResolver
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.jwkThumbprint
import diw.wallet.core.jose.publicJwk
import diw.wallet.core.credential.CardImages
import diw.wallet.core.util.QrDecoder
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.Paint
import androidx.compose.ui.unit.IntSize
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
import diw.wallet.core.oid4vci.IssuerRoutedWalletProvider
import diw.wallet.core.oid4vci.MultipazTestWalletProvider
import diw.wallet.core.oid4vci.RemoteWalletProvider
import diw.wallet.core.oid4vci.WalletProvider
import diw.wallet.core.oid4vci.pick
import diw.wallet.core.oid4vp.ConsentTerms
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.PreparedExtended
import diw.wallet.core.oid4vp.PreparedDerived
import diw.wallet.core.oid4vp.PreparedMoica
import diw.wallet.core.oid4vp.PreparedPresentation
import diw.wallet.core.oid4vp.PreparedRequest
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.compat.MsVerifiedIdPresentationDialect
import diw.wallet.core.oid4vp.compat.TwdiwCustomField
import diw.wallet.core.oid4vp.compat.TwdiwPresentationDialect
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.profile.bonds.BondsNationalId
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.HeldMoicaCard
import diw.wallet.core.document.derived.DerivedCredentials
import diw.wallet.core.profile.bonds.AnimatedQrTransport
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
import diw.wallet.core.trust.BuiltInPublicRoots
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.StoredAnchor
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustListKind
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.trust.UserDidTrust
import diw.wallet.core.trust.UserTrustedDid
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.w3c.addDiwCredentialImplementations
import diw.wallet.core.x509.displaySubject
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.readRawBytes
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import diw.wallet.app.ui.DocumentCategory
import diw.wallet.app.ui.categoryOf
import diw.wallet.app.ui.parseColor
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
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
import diw.wallet.core.oid4vp.WalletTransactionTypes
import diw.wallet.core.document.sign.CscService
import diw.wallet.core.document.sign.SigningException
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.presentment.CredentialQueryResult
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
    /**
     * Production server (diw-wallet-server) for the relay, the zkTLS verifier host and the Bonds-compatible age host;
     * empty uses the test server in the test environment.
     */
    val zkVerifierUrl: String = "",
    /** Access token for [zkVerifierUrl]'s zkTLS host, sent only to that address (settings are stored encrypted). */
    val serverToken: String = "",
    /** SHA-256 of the signing root the user trusted for [zkVerifierUrl]; a different root needs a new confirmation. */
    val serverRootSha256: String = "",
    /** The web verifier DID of [zkVerifierUrl] the user trusted with it, so a changed DID needs a new confirmation. */
    val serverVerifierDid: String = "",
    val useWalletProvider: Boolean = true,
    /** Use the Multipaz TestApp public test identity with issuer.multipaz.org (test environment only, off by default). */
    val multipazTestIdentity: Boolean = false,
    val clientId: String = "diw-wallet",
    /** Registered HTTPS wallet backend, separate from the local test provider. */
    val walletProviderUrl: String? = null,
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
    /** Trust chains to the platform's certificate store (public web PKI) as T3. */
    val systemTrustStore: Boolean = true,
    /** Trust chains to the built-in mainland China CAs (Mozilla and Microsoft program roots, SM2 roots) as T3. */
    val mainlandChinaRoots: Boolean = true,
    /** Trust document signers and time-stamp authorities on the Adobe Approved Trust List (T2). */
    val aatlTrustList: Boolean = true,
    /** Trust qualified CAs and time-stamp services on the EU trusted lists (T2). */
    val eutlTrustList: Boolean = true,
    /** Time-stamp authority for signatures and stored files (see TsaServices). */
    val tsaId: String = "digicert",
    /** Time-stamp every file when it is stored (only its SHA-256 is sent). */
    val timestampOnSave: Boolean = false,
    /** Keep the time-stamp authority's revocation data (OCSP first, else CRL) with every time stamp. */
    val timestampRevocation: Boolean = true,
    /** Baseline level the signing screen starts with for every form (SignatureLevel name; the key predates CAdES and XAdES levels). */
    val padesLevel: String = "B_T",
    /**
     * National ID number the holder saved for MyData (Bonds MyDataAutofillProfile): filled into MyData sign-in pages
     * and tried on MyData PDFs. Saved only when the holder asks.
     */
    val myDataIdNumber: String? = null,
    /** Birth date (yyyyMMdd) saved with [myDataIdNumber] for MyData sign-in pages. */
    val myDataBirthDate: String? = null,
    /**
     * Developer option: sign with the mobile citizen certificate through an SP account typed in on the signing screen
     * (kept in memory only) instead of the account built into this build.
     */
    val manualMobileMoicaSp: Boolean = false,
    /** Remote signing services (CSC API) the user added; the built-in ones are in CscServices. */
    val cscServices: List<CscService> = emptyList(),
)

/**
 * Tabs of the home screen. The layout follows the EUDI wallet (documents, history) and Bonds (documents, use):
 * every credential, whatever its issuer or profile, lives in the one documents list, and every holder action is
 * in Use. Verify is the wallet acting as a verifier (the offline check works; the rest is laid out for later).
 * Files is the area for signed files and official documents, laid out for a later phase.
 */
enum class HomeTab { DOCUMENTS, FILES, USE, VERIFY, HISTORY }

/** The groups of the settings screen, each on its own page. */
enum class SettingsSection(val title: String) {
    SECURITY("安全與隱私"),
    CREDENTIALS("證件與出示"),
    DOCUMENTS("文件與簽章"),
    TRUST("信任"),
    INTEROP("互通"),
    DEVELOPER("開發者與測試"),
    GENERAL("顯示"),
    ABOUT("關於"),
}

sealed class Screen {
    /** The tabbed home screen; [WalletModel.tab] is the selected tab. */
    data object Home : Screen()
    data object Settings : Screen()
    /** One group of the settings, opened from the settings list. */
    data class SettingsPage(val section: SettingsSection) : Screen()
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
    /** The user's own trust: imported roots and intermediates and trusted DIDs, opened from the trust settings. */
    data object CustomTrust : Screen()
    /** Zero-knowledge proofs: device tier, engines and circuit assets, opened from the security settings. */
    data object ZkSettings : Screen()
    /** A code shown at a counter or to a verifier (TWDIW pickup barcode, Bonds frames, Bonds verification). */
    data object Offline : Screen()
    data object MsIssuance : Screen()
    /** In-person presentation by NFC tap or QR code (ISO/IEC 18013-5). */
    data object Proximity : Screen()
    /** In-person verification: the wallet reads another wallet's mdoc by NFC (ISO/IEC 18013-5 reader). */
    data object Reader : Screen()
    /** A stored file with its signature report. */
    data class FileDetail(val fileId: String) : Screen()
    data class FileSign(val fileId: String) : Screen()
    data class FileDerive(val fileId: String) : Screen()
    /** The certificate laid out by its issuer's renderer, or offline by the wallet ([offline]). */
    data class OpenCertRender(val fileId: String, val offline: Boolean = false) : Screen()
    /** Making a Bonds national ID card from the MyData national ID PDF [fileId]. */
    data class NationalIdCreate(val fileId: String) : Screen()
    /** The Bonds national ID card made from the vault file [fileId]. */
    data class NationalId(val fileId: String, val from: Screen = Home) : Screen()
    /** The sites that issue documents (MyData and others), opened from the files tab. */
    data object DocumentSources : Screen()
    /** A document source site opened inside the app. */
    data class Portal(val sourceId: String) : Screen()
    /**
     * Confirming which files go into the container of the official document [mainId]: [only] the files that just came
     * in, or null for every file outside a container; [next] are further documents of the same import.
     */
    data class OfficialBundle(val mainId: String, val only: List<String>?, val next: List<String> = emptyList()) : Screen()
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
        /** The web page or app that asked to save the credential through the Digital Credentials API. */
        val requestedBy: String? = null,
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
    /** The whole credential is disclosed (it cannot disclose part of itself); [claims] then lists all it holds. */
    val whole: Boolean = false,
    /** The claims that set [sensitivity] when it is medium or high, to say why a request is sensitive. */
    val notable: List<String> = emptyList(),
    /** Other held documents that can answer this part of the request instead (the holder may change the credential). */
    val alternatives: List<String> = emptyList(),
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
        /** The verifier_info entries (registration certificates and other attestations) as checked before asking. */
        val attestations: List<diw.wallet.core.oid4vp.VerifierAttestation> = emptyList(),
        /** Recipient, occasion, purpose and terms page the request states (TWDIW 知情同意書). */
        val terms: ConsentTerms? = null,
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
    /** Last registration with the platform Digital Credentials API; null where the platform has none. */
    val dcApiRegistration = MutableStateFlow<DcApiRegistration?>(null)
    val ready = MutableStateFlow(false)
    /** Document statuses, kept current in the background. */
    val status = StatusMonitor(this)
    val statuses get() = status.statuses
    /** The production server and the trust in its signing root. */
    val server = ServerModel(this)
    /** Stored X.509 anchors (null until loaded) and the DIDs the user trusts, for the trust anchors screen. */
    val anchors = MutableStateFlow<List<StoredAnchor>?>(null)
    val trustedDids = MutableStateFlow<List<UserTrustedDid>>(emptyList())
    /** Intermediate certificates the user imported; the built-in ones are listed from BuiltInPublicRoots. */
    val intermediates = MutableStateFlow<List<diw.wallet.core.trust.StoredIntermediate>>(emptyList())
    /** OpenID Federation Trust Anchors the user added, and one fetched but not yet confirmed. */
    val federationAnchorList = MutableStateFlow<List<FederationAnchor>>(emptyList())
    val pendingFederationAnchor = MutableStateFlow<PendingFederationAnchor?>(null)

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
        WalletTransactionTypes.all.forEach { addTransactionType(it) }
    }
    lateinit var source: SimplePresentmentSource
        private set
    val http: HttpClient by lazy {
        platform.httpClient().config { install(TwdiwUserAgent) { userAgent = { settings.twdiwUserAgent } } }
    }
    /** Time stamps, OCSP, CRLs and issuer certificates, over http where their publishers use it. */
    val signedDataHttp: diw.wallet.core.document.sign.SignedDataHttp by lazy { platform.signedDataHttp(http) }
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
    private val trustListCache = mutableMapOf<TwdiwPlatform, TwdiwTrustList>()

    /** The trust list served by [platform]; one instance per platform, so its caches are kept. */
    fun twdiwTrustFor(platform: TwdiwPlatform): TwdiwTrustList =
        trustListCache.getOrPut(platform) { TwdiwTrustList(http, platform, storage = storage) }

    /** The official TWDIW trust list (production), whatever the test settings. */
    val twdiwTrust: TwdiwTrustList get() = twdiwTrustFor(TwdiwPlatform.PRODUCTION)

    /**
     * TWDIW trust lists consulted for every DID: production, the official sandbox (UAT, always on and marked TEST),
     * and a custom test platform when one is set. Test lists only ever give TEST decisions, so they need no switch.
     */
    val twdiwTrustLists: List<TwdiwTrustList>
        get() = listOf(TwdiwPlatform.PRODUCTION, TwdiwPlatform.UAT, twdiwPlatform).distinctBy { it.frontendUrl }.map { twdiwTrustFor(it) }
    val linkedDomains: LinkedDomains by lazy { LinkedDomains(http, DidResolver(http)) }
    /** DIDs the user trusts themselves, outside any national list. */
    val userDids: UserDidTrust by lazy { UserDidTrust(storage) }
    val federationAnchors: FederationAnchors by lazy { FederationAnchors(storage) }
    /**
     * Trust for parties identified by a DID: the TWDIW trust list first, then the DIDs the user trusts, then Linked
     * Domains. The user's own decision comes before Linked Domains, so a link that cannot be fetched or verified does
     * not override a DID the user chose to trust.
     */
    val didTrust: DidTrust get() = DidTrust(twdiwTrustLists + listOf(userDids, linkedDomains))
    val twdiwServices: TwdiwServices get() = TwdiwServices(http, twdiwTrustFor(twdiwPlatform), twdiwPlatform)
    /** One instance, so custom field values attached before a response reach the response. */
    val twdiwPresentation = TwdiwPresentationDialect { did, host ->
        twdiwTrustLists.firstNotNullOfOrNull { runCatching { it.hostRegistered(did, host) }.getOrNull() }
    }
    private val msPresentation = MsVerifiedIdPresentationDialect()
    fun didResolver() = DidResolver(http, environmentPolicy.insecureLoopbackAllowed)

    val taiwan = TaiwanModel(this)
    val ms = MsIssuanceModel(this)
    val proximity = ProximityModel(this)
    val reader = ReaderModel(this)
    val files = FilesModel(this)
    val csc = CscModel(this)
    val trustLists = TrustListsModel(this)
    val zk = ZkModel(scope, platform.zk)
    val zkTemplates = ZkTemplatesModel(this)

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
            systemStoreEnabled = settings.systemTrustStore,
            mainlandChinaRootsEnabled = settings.mainlandChinaRoots,
            trustLists = buildSet {
                if (settings.aatlTrustList) add(TrustListKind.AATL)
                if (settings.eutlTrustList) add(TrustListKind.EUTL)
            },
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
        // Chains that leave out an intermediate certificate are completed from their AIA caIssuers links.
        trust.issuerFetcher = { url -> files.trustSource.fetchIssuerCertificates(url).firstOrNull() }
        // The Taiwan GPKI anchors in operation (identity, T2) and the Multipaz test issuers and readers (TEST, T3) are
        // trusted without an import.
        runCatching { trust.seedBuiltInAnchors() }
        trustLists.load()
        zkTemplates.load()
        source = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypes,
            // The same Longfellow ZK system the proximity path uses, so an online OpenID4VP request that asks for a ZKP
            // is answered with one instead of failing because no ZK system was registered on this source.
            zkSystemRepository = proximity.longfellow.repository,
            domainsMdocSignature = listOf(CredentialDomains.MDOC),
            domainsKeyBoundSdJwt = listOf(CredentialDomains.SD_JWT),
            domainsKeylessSdJwt = listOf(CredentialDomains.SD_JWT_KEYLESS),
        )
        historyLog = HistoryLog(storage)
        history.value = historyLog.load()
        status.load()
        files.load()
        documents.value = documentStore.listDocuments()
        files.reconcileDerived(documents.value.map { it.identifier }.toSet())
        ready.value = true
        status.refreshDue()
        trustLists.refreshDue()
        zkTemplates.refreshDue()
        refreshMdocTrustLists(quiet = true)
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
        val old = settings
        val s = transform(old)
        settingsFlow.value = s
        trust.policy = environmentPolicy
        if (s.aatlTrustList != old.aatlTrustList || s.eutlTrustList != old.eutlTrustList) trustLists.refreshDue()
        val t = storage.getTable(settingsTable)
        val bytes = DiwJson.encodeToString(WalletSettings.serializer(), s).encodeToByteString()
        if (t.get("settings") == null) t.insert("settings", bytes) else t.update("settings", bytes)
        // Held credentials keep the trust judged at issuance: with the public CAs switched on or off, those that had no
        // anchor or that rest on a public CA are judged again, as after importing or removing an anchor.
        if (s.systemTrustStore != old.systemTrustStore || s.mainlandChinaRoots != old.mainlandChinaRoots) {
            status.reevaluateIssuers("變更公開憑證機構設定", affected = { it.anchorName == null || it.trustEnvironment == TrustEnvironment.SYSTEM })
        }
    }

    /** Imports the TEST anchors published by the DIW test servers (issuer IACA, verifier root, wallet provider root). */
    fun importTestAnchors() = scope.launch {
        if (!settings.testEnvironment) {
            message.value = "請先開啟「使用自訂測試伺服器」並設定網址"
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
                message.value = "已從 Multipaz 發行端匯入 $n 個測試信任錨點（結果標示為測試）"
                return@launch
            }
            var added = 0
            for ((role, file, name) in pairs) {
                val resp = http.get("$base/pki/$file")
                if (!resp.status.isSuccess()) throw ProtocolException("anchor_fetch", "$file HTTP ${resp.status.value}")
                val cert = X509Cert.fromPem(resp.bodyAsText())
                if (trust.addAnchor(role, TrustEnvironment.TEST, cert, name, official = false, source = base)) added++
            }
            message.value = "已匯入 $added 個測試信任錨點（結果標示為測試）"
        } catch (e: Exception) {
            message.value = "匯入失敗：${e.message}"
        }
    }

    /**
     * Imports the EUDI reference implementation CAs (they sign the EUDI test issuers' credentials and the
     * verifier.eudiw.dev request certificates) as TEST anchors.
     */
    fun importEudiTestAnchors() = scope.launch {
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
            message.value = "已匯入 $added 個 EUDI 測試信任錨點（結果標示為測試）"
        } catch (e: Exception) {
            message.value = "匯入失敗：${e.message}"
        }
    }

    /**
     * Imports the roots of the public Multipaz test issuers as TEST anchors, fetched online so a re-keyed root is
     * picked up here without a new build: issuer.multipaz.org and utopia.multipaz.org are two separate registry roots
     * (the Utopia registry rotates its key), so both are fetched and one failing does not stop the other.
     */
    fun importMultipazTestAnchors() = scope.launch {
        var added = 0
        val failures = mutableListOf<String>()
        for ((label, base) in listOf("issuer" to MULTIPAZ_ISSUER, "utopia" to UTOPIA_ISSUER)) {
            try { added += addMultipazIssuerAnchors(base) } catch (e: Exception) { failures += "$label：${e.message}" }
        }
        message.value = if (failures.isEmpty()) "已匯入 $added 個 Multipaz 測試信任錨點（issuer 與 utopia，結果標示為測試）"
            else "已匯入 $added 個 Multipaz 測試信任錨點，部分失敗：${failures.joinToString("；")}"
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
            is Screen.SettingsPage -> screen.value = Screen.Settings
            Screen.AddDocument -> screen.value = Screen.Home
            Screen.TrustList -> screen.value = Screen.SettingsPage(SettingsSection.TRUST)
            Screen.TrustAnchors -> screen.value = Screen.SettingsPage(SettingsSection.TRUST)
            Screen.CustomTrust -> screen.value = Screen.SettingsPage(SettingsSection.TRUST)
            Screen.ZkSettings -> screen.value = Screen.SettingsPage(SettingsSection.SECURITY)
            Screen.Offline -> {
                val file = taiwan.zkTls.queryFile
                taiwan.closeOffline()
                screen.value = file?.let { Screen.FileDetail(it) } ?: Screen.Home
            }
            Screen.MsIssuance -> {
                ms.cancel()
                screen.value = Screen.Home
            }
            Screen.Proximity -> {
                proximity.close()
                showTab(HomeTab.USE)
            }
            Screen.Reader -> {
                reader.close()
                showTab(HomeTab.VERIFY)
            }
            is Screen.FileDetail -> showTab(HomeTab.FILES)
            is Screen.FileSign -> screen.value = Screen.FileDetail(s.fileId)
            is Screen.FileDerive -> screen.value = Screen.FileDetail(s.fileId)
            is Screen.OpenCertRender -> screen.value = Screen.FileDetail(s.fileId)
            is Screen.NationalIdCreate -> screen.value = Screen.FileDetail(s.fileId)
            is Screen.NationalId -> if (s.from is Screen.FileDetail) screen.value = s.from else showTab(HomeTab.DOCUMENTS)
            Screen.DocumentSources -> showTab(HomeTab.FILES)
            is Screen.Portal -> screen.value = Screen.DocumentSources
            is Screen.OfficialBundle -> screen.value = Screen.FileDetail(s.mainId)
        }
        return true
    }

    /** Registers the stored credentials with the system credential picker again, whether or not they changed. */
    fun reregisterDigitalCredentials() = scope.launch { platform.registerDigitalCredentials(this@WalletModel, force = true) }

    fun refreshDocuments() = scope.launch {
        documents.value = documentStore.listDocuments()
    }

    fun deleteDocument(doc: Document) = scope.launch {
        documentStore.deleteDocument(doc.identifier)
        status.forget(doc.identifier)
        // A file whose derived credential this was no longer shows it as derived.
        files.forgetDerived(doc.identifier)
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

    /**
     * Decoded card logos and card faces by URI; SVG and unreachable images stay absent and the card shows its colours
     * and category icon.
     */
    val cardArt = MutableStateFlow<Map<String, ImageBitmap>>(emptyMap())
    private val artRequested = mutableSetOf<String>()

    fun loadCardArt(uri: String) {
        if (uri in cardArt.value || !artRequested.add(uri)) return
        scope.launch {
            val image = runCatching { fetchArt(uri) }.getOrNull()?.let { platform.decodeImage(it) } ?: return@launch
            cardArt.value = cardArt.value + (uri to image)
        }
    }

    /**
     * Gives every stored credential without card art one: its name, issuer, colours, logo and, for a credential
     * derived from a document, the document's first page or a portrait claim. The system credential picker (Digital
     * Credentials API) lists credentials with this image.
     */
    suspend fun ensureCardArt() {
        refreshCardFaces()
        var changed = false
        for (doc in documentStore.listDocuments()) {
            if (doc.cardArt != null) continue
            val png = try {
                platform.renderCardArt(cardArtSpec(doc))
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                null
            } ?: continue
            doc.edit { cardArt = ByteString(png) }
            changed = true
        }
        if (changed) documents.value = documentStore.listDocuments()
    }

    /**
     * Reads the display metadata once for OpenID4VCI credentials stored before card faces were kept, so cards such as
     * TWDIW ones get the card face (background_image) their issuer publishes. A credential whose card face changes
     * loses its generated card art, which [ensureCardArt] then draws again.
     */
    suspend fun refreshCardFaces() = cardFaceLock.withLock {
        var changed = false
        for (doc in documentStore.listDocuments()) {
            val record = doc.issuanceRecord ?: continue
            if (record.displayCheckedAt != null || record.pendingTransactionId != null) continue
            if (!record.credentialIssuer.startsWith("https://") || record.profile == TaiwanModel.MSVID) continue
            val display = try {
                oid4vci().credentialDisplay(record.credentialIssuer, record.configurationId, record.profile)
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                // Offline or the issuer is gone: try again on a later start.
                continue
            }
            val updated = record.copy(
                backgroundImageUri = display?.backgroundImageUri ?: record.backgroundImageUri,
                logoUri = record.logoUri ?: display?.logoUri,
                backgroundColor = record.backgroundColor ?: display?.backgroundColor,
                textColor = record.textColor ?: display?.textColor,
                displayDescription = record.displayDescription ?: display?.description,
                displayCheckedAt = kotlin.time.Clock.System.now().epochSeconds,
            )
            val faceChanged = updated.backgroundImageUri != record.backgroundImageUri
            doc.edit {
                appData = updated.encode()
                if (faceChanged) cardArt = null
            }
            changed = true
        }
        if (changed) documents.value = documentStore.listDocuments()
    }

    private val cardFaceLock = Mutex()

    private suspend fun cardArtSpec(doc: Document): CardArtSpec {
        val record = doc.issuanceRecord
        val derived = files.files.value.firstOrNull { it.derivedDocumentId == doc.identifier }
        val background = parseColor(record?.backgroundColor) ?: when {
            derived != null -> Color(0xFF334155)
            else -> when (categoryOf(record)) {
                DocumentCategory.IDENTITY -> Color(0xFF1E3A8A)
                DocumentCategory.GOVERNMENT -> Color(0xFF0F766E)
                DocumentCategory.ORGANIZATION -> Color(0xFF6D28D9)
                DocumentCategory.OTHER -> Color(0xFF4F46E5)
            }
        }
        val foreground = parseColor(record?.textColor)
            ?: if (0.299 * background.red + 0.587 * background.green + 0.114 * background.blue > 0.6) Color.Black else Color.White
        val logo = record?.logoUri?.let { uri -> runCatching { fetchArt(uri) }.getOrNull() }?.let { platform.decodeImage(it) }
        val face = record?.backgroundImageUri?.let { uri -> runCatching { fetchArt(uri) }.getOrNull() }?.let { platform.decodeImage(it) }
        val picture = derived?.let { files.firstPage(it) } ?: runCatching {
            doc.getCertifiedCredentials().firstOrNull()?.let { c -> ClaimReader.read(c, documentTypes).firstNotNullOfOrNull { it.picture } }
        }.getOrNull()?.let { platform.decodeImage(it) }
        return CardArtSpec(
            title = doc.displayName ?: "證件",
            issuer = doc.typeDisplayName ?: record?.anchorName ?: record?.credentialIssuer ?: "",
            background = background.toArgb(),
            foreground = foreground.toArgb(),
            logo = logo,
            picture = picture,
            face = face,
            badge = if (record?.isTestEnvironment == true) "測試" else null,
        )
    }

    /**
     * Logo or card face bytes from a data: URI or an https URL, cached in storage so cards render offline. A body that
     * carries a data URI as text (TWDIW card faces) is decoded to the image.
     */
    private suspend fun fetchArt(uri: String): ByteArray? {
        if (uri.startsWith("data:", ignoreCase = true)) return CardImages.fromDataUri(uri)
        if (!isAcceptableEndpoint(uri, environmentPolicy.insecureLoopbackAllowed)) return null
        val key = PlatformCrypto.sha256(uri.encodeToByteArray()).toBase64Url()
        val t = storage.getTable(artTable)
        t.get(key)?.let { return it.toByteArray() }
        val resp = http.get(uri)
        if (!resp.status.isSuccess()) return null
        val body = resp.readRawBytes()
        val bytes = (if (body.size <= CardImages.MAX_IMAGE_BYTES && platform.decodeImage(body) != null) body else CardImages.fromBody(body))
            ?.takeIf { platform.decodeImage(it) != null } ?: return null
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
    /**
     * Reads a QR Code from a picture the user picks, such as a screenshot of an issuer page or a saved code. With
     * several codes the most central one is taken; when there is none a message says so and the result is null.
     */
    suspend fun qrFromImage(): String? {
        val picked = try {
            platform.pickImage()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message.value = "無法讀取圖片：" + describe(e)
            return null
        } ?: return null
        val text = withContext(Dispatchers.Default) { qrTextsIn(picked.bytes) }.firstOrNull()
        if (text == null) message.value = "「${picked.name}」中找不到 QR Code，請選擇清楚、完整含有 QR Code 的圖片"
        return text
    }

    /** QR Code texts in an image file, the most central first; empty when it is not a picture or holds no code. */
    fun qrTextsIn(bytes: ByteArray): List<String> {
        val decoded = platform.decodeImage(bytes) ?: return emptyList()
        // Camera photos are scaled down: a code stays readable and the pixel buffer stays small on phones.
        val scale = minOf(1f, MAX_QR_IMAGE_SIDE.toFloat() / maxOf(decoded.width, decoded.height))
        val image = if (scale >= 1f) decoded else {
            val w = (decoded.width * scale).toInt().coerceAtLeast(1)
            val h = (decoded.height * scale).toInt().coerceAtLeast(1)
            ImageBitmap(w, h).also { target ->
                androidx.compose.ui.graphics.Canvas(target).drawImageRect(
                    decoded, dstSize = IntSize(w, h), paint = Paint().apply { filterQuality = FilterQuality.Medium },
                )
            }
        }
        val pixels = IntArray(image.width * image.height)
        image.readPixels(pixels)
        return QrDecoder.decode(image.width, image.height, pixels)
    }

    fun handleUri(uri: String) {
        val u = uri.trim()
        val scheme = u.substringBefore(':').lowercase()
        if (ms.isLoginRedirect(u)) {
            ms.completeLogin(u)
            return
        }
        if (csc.handleRedirect(u)) return
        if (u.startsWith(platform.oid4vciRedirectUri)) {
            completeAuthorization(u)
            return
        }
        // The mobile citizen certificate app returns here after signing; the signing screen is polling already.
        platform.mobileMoicaReturnUrl?.let { if (u.startsWith(it)) return }
        if (ZkTlsSessionRequest.looksLike(u)) {
            taiwan.zkTls.start(u)
            return
        }
        if (BondsAgeRequest.looksLike(u)) {
            taiwan.startBondsAge(u)
            return
        }
        if (BondsPresentationRequest.looksLike(u)) {
            taiwan.startBonds(u)
            return
        }
        // A document chosen for an offline presentation only applies to the next challenge.
        taiwan.preferredDocument = null
        if (BondsQrTransport.isFrame(u)) {
            taiwan.acceptVerifierFrame(u)
            return
        }
        if (AnimatedQrTransport.isFrame(u)) {
            // The same fountain frames answer a presentation challenge or a nearby age check, whichever is on screen.
            if (taiwan.offline.value is OfflineUi.VerifierChallenge) taiwan.acceptVerifierFrame(u)
            else taiwan.ageVerifier.acceptFrame(u).progress?.let { message.value = it }
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
        listOf(
            TwdiwDialect(http, loopback, clientId = { settings.twdiwClientId }, registeredIssuerTrust = { url ->
                twdiwTrustLists.firstNotNullOfOrNull { runCatching { it.issuerDecision(url) }.getOrNull() }
            }),
            Draft13Dialect(http, loopback), Draft11Dialect(), EudiDialect(),
        )
    }

    private var cachedProvider: Pair<String, WalletProvider>? = null
    private val multipazTestProvider by lazy { MultipazTestWalletProvider() }

    private fun walletProvider(): WalletProvider {
        val base = baseWalletProvider()
        val s = settings
        if (!(s.testEnvironment && s.multipazTestIdentity)) return base
        return IssuerRoutedWalletProvider(base) { ci, asIssuer ->
            multipazTestProvider.takeIf { MultipazTestWalletProvider.appliesTo(ci, asIssuer) }
        }
    }

    private fun baseWalletProvider(): WalletProvider {
        val s = settings
        val configuredUrl = s.walletProviderUrl?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }
        val localTestProvider = configuredUrl == null && s.testEnvironment && s.useWalletProvider
        if (configuredUrl == null && !localTestProvider) return PublicClientWalletProvider(s.clientId)

        val baseUrl = configuredUrl ?: (s.testServerUrl.trimEnd('/') + "/wallet-provider")
        if (configuredUrl != null && !baseUrl.startsWith("https://")) {
            throw ProtocolException("wallet_provider_error", "A registered wallet backend must use HTTPS")
        }
        val cacheKey = "$baseUrl|${s.clientId}|$localTestProvider"
        cachedProvider?.takeIf { it.first == cacheKey }?.let { return it.second }
        return object : WalletProvider {
            override val clientId: String = s.clientId
            private var remote: RemoteWalletProvider? = null
            private suspend fun get(): RemoteWalletProvider = remote ?: run {
                val (key, attestation) = instanceKey()
                RemoteWalletProvider(
                    http, baseUrl, s.clientId, key, attestation,
                    allowInsecureLoopback = localTestProvider && environmentPolicy.insecureLoopbackAllowed,
                )
            }.also { remote = it }
            override suspend fun walletAttestation() = get().walletAttestation()
            override suspend fun clientAssertion(audience: String) = get().clientAssertion(audience)
            override suspend fun keyAttestation(
                keys: List<org.multipaz.securearea.KeyAttestation>,
                nonce: String?,
                userAuthentication: Boolean,
            ) = get().keyAttestation(keys, nonce, userAuthentication)
        }.also { cachedProvider = cacheKey to it }
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

    fun startIssuance(uri: String, entryHint: String? = null, requestedBy: String? = null) {
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
                    requestedBy = requestedBy,
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
        moicaCards = { heldMoicaCards() },
        moicaHolder = { holderIdentities.find(HolderIdentities.BONDS_SELF_ISSUED) },
        derivedSources = { files.holderDerivedSources() },
        derivedHolders = { files.holderHints() },
        federationAnchors = { activeFederationAnchors() },
    )

    /** Test anchors take part only while the test environment is on, like test X.509 anchors. */
    private suspend fun activeFederationAnchors(): List<FederationAnchor> =
        federationAnchors.all().filter { it.trustEnvironment != TrustEnvironment.TEST || settings.testEnvironment }

    /** Bonds self-issued cards (vc+moica) for an online request: the national ID cards only. */
    private fun heldMoicaCards(): List<HeldMoicaCard> =
        files.nationalIdCards().map { (f, card) -> HeldMoicaCard(f.id, TaiwanModel.NATIONAL_ID_NAME, card) }

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
                endAuthorizationPresentation(null, "無法處理身分驗證要求：" + describe(e))
            }
        }
    }

    private var authorizationPresentation: CompletableDeferred<String>? = null

    /**
     * Answers a presentation request that is a step of another flow (a remote signing service asking for the PID
     * before it signs) on the usual consent screen, then returns to the screen it came from. Returns the address the
     * verifier sends the wallet to next; fails when the holder declines or the request cannot be answered.
     */
    suspend fun presentForAuthorization(uri: String): String {
        val back = screen.value
        val done = CompletableDeferred<String>()
        authorizationPresentation?.completeExceptionally(SigningException("已有另一個身分驗證進行中"))
        authorizationPresentation = done
        startPresentation(uri)
        try {
            return done.await()
        } finally {
            if (authorizationPresentation === done) authorizationPresentation = null
            screen.value = back
        }
    }

    private fun endAuthorizationPresentation(redirect: String?, failure: String): Boolean {
        val d = authorizationPresentation ?: return false
        authorizationPresentation = null
        if (redirect != null) d.complete(redirect) else d.completeExceptionally(SigningException(failure))
        return true
    }

    /**
     * Digital Credentials API entry (Android Credential Manager). Completes with the response data (an OpenID4VP error
     * included), or null to cancel the flow. A failed request stays on screen until the user leaves it, so the reason
     * can be read instead of the caller only seeing a cancelled request.
     */
    suspend fun presentDcApi(
        protocol: String,
        data: JsonObject,
        origin: String,
        selectedDocumentIds: List<String> = emptyList(),
    ): JsonObject? {
        val done = startDcApi()
        try {
            val h = holder()
            val preselected = resolveSelectedDocuments(selectedDocumentIds)
            presentation.value = consentFor(h.prepare(h.resolveDcApi(protocol, data, origin)), preselected = preselected)
        } catch (e: Exception) {
            dcApiError = Oid4vpHolder.dcApiError(data, e)
            presentation.value = PresentationUi.Failed(describe(e))
        }
        return done.await()
    }

    /**
     * The held documents the system selector chose, by their Credential Manager ids (each a document identifier). A
     * chosen credential that no longer exists is an explicit failure: the request is never answered from another
     * credential the holder did not pick.
     */
    suspend fun resolveSelectedDocuments(ids: List<String>): List<Document> = ids.map { id ->
        documentStore.lookupDocument(id) ?: throw ProtocolException("access_denied", "選取的證件已不存在")
    }

    /**
     * Digital Credentials API issuance (navigator.credentials.create, protocol openid4vci-v1 or openid4vci1.0): [data]
     * is the credential offer, or an object carrying credential_offer or credential_offer_uri. The offer goes through
     * the usual review and issuance screens; returns true when the user leaves them with a credential saved.
     */
    suspend fun receiveDcApi(data: JsonObject, origin: String): Boolean {
        startIssuance(dcApiOfferUri(data), requestedBy = origin)
        screen.first { it != Screen.Issuance }
        return (issuance.value as? IssuanceUi.Done)?.results?.isNotEmpty() == true
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
        chosen: CredentialSelection? = null,
        checkedAttestations: List<diw.wallet.core.oid4vp.VerifierAttestation>? = null,
        preselected: List<Document> = emptyList(),
    ): PresentationUi.Consent {
        val consent = when (prepared) {
            is PreparedPresentation -> {
                val selection = chosen ?: prepared.queryResult.select(preselected)
                // Multipaz silently falls back to the first match when the preselected documents cannot be honoured, so
                // the honoured set is checked here: a credential the holder picked that does not satisfy the request is
                // an explicit failure rather than a different credential being disclosed.
                if (chosen == null && preselected.isNotEmpty()) {
                    val honoured = selection.matches.map { it.credential.document.identifier }.toSet()
                    if (preselected.any { it.identifier !in honoured }) {
                        throw ProtocolException("access_denied", "選取的證件無法符合此請求")
                    }
                }
                val alternatives = standardAlternatives(prepared.queryResult, selection)
                val items = selection.matches.mapIndexed { i, m ->
                    val doc = m.credential.document
                    val paths = m.claims.values.map { ClaimReader.pathOf(it) }
                    val labels = m.claims.values.map { claimLabel(ClaimReader.pathOf(it), it.displayName, doc.issuanceRecord) }
                    val sensitivity = ClaimSensitivity.ofAll(paths)
                    ConsentItem(
                        documentName = doc.displayName ?: "憑證",
                        claims = labels,
                        documentTrust = null,
                        documentId = doc.identifier,
                        sensitivity = sensitivity,
                        notable = notable(paths, labels, sensitivity),
                        alternatives = alternatives[i].map { it.identifier },
                    )
                }
                PresentationUi.Consent(prepared, selection, items, fields, offline)
            }
            is PreparedExtended -> {
                val items = prepared.lines.mapIndexed { i, line ->
                    val d = lineDisclosure(line.document, line.claims)
                    ConsentItem(
                        line.documentName, d.labels, null,
                        documentId = line.document.identifier,
                        sensitivity = d.sensitivity,
                        whole = d.whole,
                        notable = d.notable,
                        alternatives = prepared.prepared.alternatives(i).map { it.document.identifier },
                    )
                }
                PresentationUi.Consent(prepared, null, items, fields, offline)
            }
            is PreparedMoica -> {
                val items = prepared.matches.map { m ->
                    val paths = m.claims.map { listOf("credentialSubject", it) }
                    val labels = m.claims.map { BondsNationalId.claimLabels[it] ?: DerivedCredentials.claimLabels[it] ?: it }
                    val sensitivity = ClaimSensitivity.ofAll(paths)
                    ConsentItem(m.card.name, labels.ifEmpty { listOf("卡片簽章與自然人憑證（不含欄位）") }, null,
                        sensitivity = sensitivity, notable = notable(paths, labels, sensitivity))
                }
                PresentationUi.Consent(prepared, null, items, fields, offline)
            }
            is PreparedDerived -> {
                val plan = prepared.plan
                val paths = plan.requested.map { listOf(it) }
                val labels = plan.requested.map { c -> (plan.type.claimLabels[c] ?: c) + "：" + answerText(plan.answers[c]) }
                val sensitivity = ClaimSensitivity.ofAll(paths)
                val item = ConsentItem(
                    "${plan.type.title}（出示時由 ${plan.source.name} 產生，持有人從文件衍生）",
                    listOf("查驗方的問題：" + plan.rule.question) + labels,
                    null,
                    sensitivity = sensitivity,
                    notable = notable(paths, labels, sensitivity),
                )
                PresentationUi.Consent(prepared, null, listOf(item), fields, offline)
            }
        }
        // The Digital Credentials API only registers mdoc and SD-JWT VC documents, which are answered as a
        // PreparedPresentation; a preselected document reaching any other path cannot be the credential the holder
        // picked, so the request is refused rather than answered from a credential they did not choose.
        if (chosen == null && preselected.isNotEmpty() && prepared !is PreparedPresentation) {
            val honoured = consent.items.mapNotNull { it.documentId }.toSet()
            if (preselected.any { it.identifier !in honoured }) {
                throw ProtocolException("access_denied", "選取的證件無法符合此請求")
            }
        }
        val attestations = checkedAttestations ?: if (consent.request.verifierInfo.isEmpty()) emptyList() else {
            diw.wallet.core.oid4vp.VerifierInfoChecker(trust, diw.wallet.core.status.CredentialStatusChecker(http, trust, didTrust = didTrust))
                .check(consent.request)
        }
        // A failed attestation (wrong party, revoked, beyond its registration) makes the request high risk.
        val attestationRisk = if (attestations.any { it.verdict == diw.wallet.core.oid4vp.AttestationVerdict.INVALID || !it.outsideRegistration.isNullOrEmpty() }) RiskLevel.HIGH else RiskLevel.LOW
        val risk = RiskLevel.max(requestRisk(consent.items, consent.request.verifier.trust.tier), attestationRisk)
        // A status older than the request's risk allows is queried again while the user reads the request.
        status.refreshFor(consent.items.mapNotNull { it.documentId }, risk)
        return consent.copy(risk = risk, attestations = attestations, terms = holder().consentTerms(consent.request))
    }

    /**
     * Other documents each selected match of an OpenID4VP 1.0 request could come from: the matches of the same credential
     * set member, less documents already presented on another line.
     */
    private fun standardAlternatives(result: CredentialQueryResult, selection: CredentialSelection): List<List<Document>> {
        val members = result.credentialSets.flatMap { it.options }.flatMap { it.members }
        return selection.matches.mapIndexed { i, m ->
            val others = selection.matches.filterIndexed { j, _ -> j != i }.map { it.credential.document.identifier }.toSet()
            val member = members.firstOrNull { mem -> mem.matches.any { it.credential.identifier == m.credential.identifier } }
            member?.matches.orEmpty().map { it.credential.document }
                .filter { it.identifier != m.credential.document.identifier && it.identifier !in others }
                .distinctBy { it.identifier }
        }
    }

    /**
     * The holder changes the credential that answers line [index] of [consent] to the held document [documentId], one
     * of the line's alternatives. The verifier checks already made are kept; the claims and risk are recomputed.
     */
    fun changeCredential(consent: PresentationUi.Consent, index: Int, documentId: String) = scope.launch {
        try {
            val next = when (val p = consent.prepared) {
                is PreparedExtended -> {
                    val alternative = p.prepared.alternatives(index).firstOrNull { it.document.identifier == documentId } ?: return@launch
                    consentFor(holder().replace(p, index, alternative), consent.fields, consent.offline, checkedAttestations = consent.attestations)
                }
                is PreparedPresentation -> {
                    val current = consent.selection ?: p.queryResult.select(emptyList())
                    val doc = standardAlternatives(p.queryResult, current).getOrNull(index)?.firstOrNull { it.identifier == documentId } ?: return@launch
                    val docs = current.matches.map { it.credential.document }.toMutableList().also { it[index] = doc }
                    consentFor(p, consent.fields, consent.offline, p.queryResult.select(docs), consent.attestations)
                }
                else -> return@launch
            }
            if (presentation.value === consent) presentation.value = next
        } catch (e: Exception) {
            message.value = "無法更改憑證：" + describe(e)
        }
    }

    /** What a presentation line discloses: field labels, their sensitivity, and whether it is the whole credential. */
    private class LineDisclosure(val labels: List<String>, val sensitivity: RiskLevel, val notable: List<String>, val whole: Boolean)

    /**
     * A line of an extended presentation. A whole credential ("*", a Presentation Exchange descriptor without fields,
     * or a JWT VC, which cannot disclose part of itself) discloses every claim it holds: those are listed, and the
     * sensitivity is never below the document's own risk.
     */
    private suspend fun lineDisclosure(document: Document, claims: List<String>): LineDisclosure {
        val record = document.issuanceRecord
        val whole = claims.any { it == "*" || it.isEmpty() }
        val paths = if (!whole) claims.map { it.split('.') } else runCatching {
            document.getCertifiedCredentials().firstOrNull()?.let { ClaimReader.read(it, documentTypes).map { c -> c.path } }
        }.getOrNull().orEmpty()
        val labels = paths.map { claimLabels.label(it, record?.claimNames.orEmpty(), null) }
        val fields = ClaimSensitivity.ofAll(paths)
        val sensitivity = if (whole) RiskLevel.max(fields, StatusMonitor.riskOf(record)) else fields
        return LineDisclosure(labels.ifEmpty { listOf("整張證件") }, sensitivity, notable(paths, labels, fields), whole)
    }

    /** A derived answer as the holder reads it: predicates as yes or no. */
    private fun answerText(v: String?): String = when (v) {
        "true" -> "是"
        "false" -> "否"
        null -> "無"
        else -> v
    }

    /** Labels of the fields as sensitive as [top], when that is medium or high. */
    private fun notable(paths: List<List<String>>, labels: List<String>, top: RiskLevel): List<String> {
        if (top == RiskLevel.LOW) return emptyList()
        return paths.zip(labels).filter { (p, _) -> ClaimSensitivity.of(p) == top }.map { it.second }.distinct()
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
                        is PreparedMoica -> holder().respond(p)
                        is PreparedDerived -> holder().respond(p)
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
                is PresentationOutcome.Posted -> if (!endAuthorizationPresentation(outcome.redirectUri, "簽章服務沒有提供下一步的位址")) {
                    outcome.redirectUri?.let { platform.openRedirect(it) }
                }
                is PresentationOutcome.Redirect -> if (!endAuthorizationPresentation(outcome.url, "")) platform.openRedirect(outcome.url)
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
            endAuthorizationPresentation(null, "身分驗證失敗：" + describe(e))
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
        endAuthorizationPresentation(null, "已拒絕分享身分資料，簽署已取消")
    }

    /** Ends a pending DC API request when the user leaves the presentation: a reportable failure goes to the caller, anything else cancels. */
    fun leaveDcApi() {
        endAuthorizationPresentation(null, "已離開身分驗證畫面，簽署已取消")
        dcApiResult?.complete(dcApiError)
        dcApiResult = null
        dcApiError = null
    }

    /** Imported mdoc VICAL (issuers) and RICAL (readers), expired ones included. */
    val mdocLists = MutableStateFlow<List<diw.wallet.core.trust.StoredSignedList>>(emptyList())

    private suspend fun fetchSignedList(url: String): ByteArray {
        if (!isAcceptableEndpoint(url, false)) throw ProtocolException("invalid_request", "簽署清單只接受 HTTPS 來源")
        val reply = http.get(url)
        if (!reply.status.isSuccess()) throw ProtocolException("trust_list_download", "下載失敗：HTTP ${reply.status.value}")
        return reply.readRawBytes()
    }

    /**
     * Imports an issuer VICAL or reader RICAL from [url]. The list must be signed under a root the user imported
     * for the list-publisher role; its CAs then count as the user's own trust (T2, never official).
     */
    fun importMdocTrustList(kind: String, url: String, name: String) = scope.launch {
        try {
            val summary = trust.importSignedMdocTrustList(kind, fetchSignedList(url), name, url)
            message.value = "已驗證並匯入簽署清單：$summary（使用者信任，T2，不標示官方）"
            loadAnchors()
            status.reevaluateIssuers("匯入 mdoc 簽署清單", affected = { true }, accept = { true })
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message.value = "簽署清單匯入失敗：" + describe(e)
        }
    }

    /**
     * Fetches the lists whose announced next update or expiry has passed. [quiet] (at start) reports only changes
     * and failures, not that nothing was due.
     */
    fun refreshMdocTrustLists(quiet: Boolean = false) = scope.launch {
        try {
            if (quiet && mdocLists.value.isEmpty() && trust.mdocTrustLists().isEmpty()) return@launch
            val result = trust.refreshDueMdocTrustLists { url -> fetchSignedList(url) }
            loadAnchors()
            if (result.refreshed > 0) status.reevaluateIssuers("更新 mdoc 簽署清單", affected = { true }, accept = { true })
            if (result.failures.isNotEmpty()) {
                message.value = "部分簽署清單更新失敗：" + result.failures.joinToString("；")
            } else if (!quiet || result.refreshed > 0) {
                message.value = "簽署清單更新完成：${result.refreshed} 份新版本"
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            message.value = "簽署清單更新失敗：" + describe(e)
        }
    }

    fun removeMdocTrustList(list: diw.wallet.core.trust.StoredSignedList) = scope.launch {
        trust.removeMdocTrustList(list)
        loadAnchors()
        status.reevaluateIssuers("移除 mdoc 簽署清單「${list.name}」", affected = { true })
    }

    // ---------------------------------------------------------------- trust anchors

    fun loadAnchors() = scope.launch {
        anchors.value = trust.allAnchors().sortedWith(compareBy({ it.environment.ordinal }, { it.metadata.displayName }))
        trustedDids.value = userDids.all().sortedBy { it.name }
        intermediates.value = trust.intermediates().sortedBy { it.name }
        mdocLists.value = trust.mdocTrustLists().sortedBy { it.name }
        federationAnchorList.value = federationAnchors.all().sortedBy { it.name }
    }

    /**
     * Imports the certificates in [input] (PEM text, or an https address serving PEM): a self-issued root becomes the
     * user's own anchor for [roles] (T2, never official); an intermediate CA certificate joins the intermediates that
     * complete chains (it never sets a tier); an end-entity certificate is refused.
     */
    fun importAnchor(input: String, name: String, roles: Set<TrustRole>) = scope.launch {
        try {
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
            certs.firstOrNull { !TrustRegistry.isRoot(it) && !TrustRegistry.isIntermediate(it) }?.let {
                throw ProtocolException("invalid_request", "「${commonName(it)}」不是憑證機構的憑證，不能當作根憑證或中繼憑證")
            }
            if (certs.any { TrustRegistry.isRoot(it) } && roles.isEmpty()) throw ProtocolException("invalid_request", "根憑證請至少選擇一種用途")
            var roots = 0
            var middle = 0
            for (cert in certs) {
                if (cert.validityNotAfter < now) throw ProtocolException("invalid_request", "「${commonName(cert)}」已於 ${cert.validityNotAfter} 過期")
                val cn = commonName(cert)
                val label = name.trim().ifEmpty { cn }.let { if (certs.size > 1 && name.isNotBlank()) "$it（$cn）" else it }
                if (TrustRegistry.isRoot(cert)) {
                    for (role in roles) if (trust.addAnchor(role, TrustEnvironment.USER, cert, label, official = false, source = source)) roots++
                } else if (trust.addIntermediate(cert, label, source)) middle++
            }
            message.value = when {
                roots == 0 && middle == 0 -> "這些憑證已經匯入過"
                else -> listOfNotNull(
                    if (roots > 0) "已加入 $roots 個信任錨點（使用者匯入，信任等級 T2）" else null,
                    if (middle > 0) "已加入 $middle 張中繼憑證（只用來補足憑證鏈）" else null,
                ).joinToString("；")
            }
            loadAnchors()
            // Documents whose issuer had no anchor may chain to the new root, or through the new intermediate.
            if (roots > 0 || middle > 0) status.reevaluateIssuers("加入信任錨點或中繼憑證", affected = { it.anchorName == null }, accept = { it.environment != null })
        } catch (e: Exception) {
            message.value = "匯入失敗：" + describe(e)
        }
    }

    /**
     * Trusts [der], a self-issued root shown in a document's chain, as the user's own anchor for document signatures
     * and time stamps, after the user confirmed it. The document is checked again with the new anchor.
     */
    fun trustRootCertificate(der: ByteArray, onDone: () -> Unit = {}) = scope.launch {
        try {
            val cert = X509Cert(kotlinx.io.bytestring.ByteString(der))
            if (!TrustRegistry.isRoot(cert)) throw ProtocolException("invalid_request", "這張憑證不是根憑證")
            if (cert.validityNotAfter < kotlin.time.Clock.System.now()) throw ProtocolException("invalid_request", "根憑證已過期")
            val name = BuiltInPublicRoots.importableRoots.firstOrNull { it.certificate == cert }?.name ?: commonName(cert)
            var added = 0
            for (role in listOf(TrustRole.DOCUMENT, TrustRole.TSA)) {
                if (trust.addAnchor(role, TrustEnvironment.USER, cert, name, official = false, source = "document")) added++
            }
            message.value = if (added == 0) "「$name」已經是信任錨點" else "已信任「$name」（文件簽章與時間戳記，信任等級 T2）"
            loadAnchors()
            status.reevaluateIssuers("信任根憑證「$name」", affected = { it.anchorName == null }, accept = { it.environment != null })
            onDone()
        } catch (e: Exception) {
            message.value = "無法信任：" + describe(e)
        }
    }

    fun removeIntermediate(i: diw.wallet.core.trust.StoredIntermediate) = scope.launch {
        trust.removeIntermediate(i)
        loadAnchors()
        status.reevaluateIssuers("移除中繼憑證「${i.name}」", affected = { it.anchorName != null && it.trustEnvironment != TrustEnvironment.TEST })
    }

    private fun commonName(c: X509Cert): String = c.subject.components[OID.COMMON_NAME.oid]?.value ?: c.displaySubject()

    fun removeAnchor(anchor: StoredAnchor) = scope.launch {
        if (anchor.environment == TrustEnvironment.PRODUCTION) return@launch
        trust.removeAnchor(anchor)
        loadAnchors()
        // Documents trusted through this anchor are judged again and no longer show it.
        val name = anchor.metadata.displayName
        status.reevaluateIssuers("移除信任錨點「$name」", affected = { it.trustEnvironment == anchor.environment && it.anchorName == name })
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
            status.reevaluateIssuers("信任 DID", affected = { it.anchorName == null }, accept = { it.environment == TrustEnvironment.USER })
        } catch (e: Exception) {
            message.value = "無法加入：" + describe(e)
        }
    }

    fun untrustDid(did: String) = scope.launch {
        val name = userDids.all().firstOrNull { it.did == did }?.name
        userDids.remove(did)
        loadAnchors()
        if (name != null) {
            status.reevaluateIssuers("不再信任 DID「$name」", affected = { it.trustEnvironment == TrustEnvironment.USER && it.anchorName == name })
        }
    }

    /**
     * Fetches the self-signed Entity Configuration of [entityId] and holds it for confirmation: an anchor's keys are
     * trusted on the user's word, so the key thumbprints are shown to compare with what the federation publishes.
     */
    fun fetchFederationAnchor(entityId: String, name: String, environment: TrustEnvironment) = scope.launch {
        try {
            val id = entityId.trim()
            if (environment == TrustEnvironment.TEST && !settings.testEnvironment) throw ProtocolException("invalid_request", "測試錨點需先開啟測試環境")
            val ec = FederationResolver(http, { emptyList() }, environmentPolicy.insecureLoopbackAllowed).configuration(id)
            ec.checkTime(kotlin.time.Clock.System.now().epochSeconds, 120)
            val organization = ec.metadata.obj("federation_entity")?.str("organization_name")
            val jwks = kotlinx.serialization.json.buildJsonObject { put("keys", kotlinx.serialization.json.JsonArray(ec.jwks.map { publicJwk(it) })) }
            val anchor = FederationAnchor(
                entityId = id,
                jwks = jwks.toString(),
                name = name.trim().ifEmpty { organization ?: runCatching { io.ktor.http.Url(id).host }.getOrDefault(id) },
                environment = environment.id,
                addedAt = kotlin.time.Clock.System.now().epochSeconds,
            )
            pendingFederationAnchor.value = PendingFederationAnchor(
                anchor, organization, ec.authorityHints,
                ec.jwks.map { k -> (k.str("kid")?.let { "$it：" } ?: "") + runCatching { jwkThumbprint(k) }.getOrDefault("無法計算") },
            )
        } catch (e: Exception) {
            message.value = "無法取得 Trust Anchor：" + describe(e)
        }
    }

    fun confirmFederationAnchor() = scope.launch {
        val p = pendingFederationAnchor.value ?: return@launch
        pendingFederationAnchor.value = null
        try {
            federationAnchors.put(p.anchor)
            message.value = "已信任 OpenID Federation Trust Anchor「${p.anchor.name}」"
            loadAnchors()
        } catch (e: Exception) {
            message.value = "無法加入：" + describe(e)
        }
    }

    fun removeFederationAnchor(anchor: FederationAnchor) = scope.launch {
        federationAnchors.remove(anchor.entityId)
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
            Regex("\\b1010\\b").containsMatchIn(m) || ("403" in m && "wallet.gov.tw" in m) -> "\n數位憑證皮夾的伺服器拒絕了連線，可在設定調整送往 wallet.gov.tw 的 User-Agent 後再試。"
            // A credential 5xx does not establish that every issuer-side compatibility check passed.
            "Credential request failed (5" in m && "TWDIW resp_code" in m ->
                "\n發證端回報錯誤，可能是服務異常或領卡流程不相容。請到發證網站重新產生 QR Code 再試；若官方 App 可正常領卡，請回報 DIW 版本與此錯誤碼。"
            e.code == "untrusted_verifier" ->"\n對方不在數位憑證皮夾的信任清單或未在區塊鏈上註冊，為保護資料已停止。"
            else -> ""
        }
    }

    companion object {
        /** The credential offer of a DC API create request as an offer URI the OpenID4VCI client reads. */
        internal fun dcApiOfferUri(data: JsonObject): String {
            val uri = (data["credential_offer_uri"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (uri != null) return "openid-credential-offer://?credential_offer_uri=" + uri.encodeURLParameter()
            val offer = when (val o = data["credential_offer"]) {
                is JsonObject -> o
                is JsonPrimitive -> if (o.isString) DiwJson.parseToJsonElement(o.content) as? JsonObject else null
                else -> null
            } ?: data.takeIf { "credential_issuer" in it }?.let { JsonObject(it - "credential_issuer_metadata" - "authorization_server_metadata") }
                ?: throw ProtocolException("invalid_request", "Digital Credentials API 請求沒有領卡資訊（credential offer）")
            return "openid-credential-offer://?credential_offer=" + DiwJson.encodeToString(JsonObject.serializer(), offer).encodeURLParameter()
        }

        /** One spec per table name and process: storage rejects a second spec object for the same table. */
        private val settingsTable = StorageTableSpec(name = "DiwSettings", supportPartitions = false, supportExpiration = false)
        private val artTable = StorageTableSpec(name = "DiwCardArt", supportPartitions = false, supportExpiration = false)
        /** Longest side, in pixels, of a picture searched for a QR Code; larger pictures are scaled down. */
        const val MAX_QR_IMAGE_SIDE = 2400
        val ISSUER_PATHS = listOf("/issuer", "/draft13", "/openid4vci", "/oid4vci", "/v1")
        const val MULTIPAZ_ISSUER = "https://issuer.multipaz.org/issuer"
        const val UTOPIA_ISSUER = "https://utopia.multipaz.org/id"
        const val EUDI_ANCHORS = "https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-app-android-wallet-ui/main/resources-logic/src/main/res/raw"

        fun tierTitle(t: TrustTier): String = when (t) {
            TrustTier.T1 -> "T1 官方已驗證"
            TrustTier.T2 -> "T2 連到信任根"
            TrustTier.T3 -> "T3 未連到信任根"
            TrustTier.T4 -> "T4 無法驗證"
        }

        fun randomId() = PlatformCrypto.randomBytes(9).toBase64Url()

        private val PEM_CERT = Regex("-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\\s]+-----END CERTIFICATE-----")

        /** Risk a verifier adds to a request: none when led to a trust root (T1, T2), high when its identity cannot be verified. */
        fun verifierRisk(tier: TrustTier): RiskLevel = when (tier) {
            TrustTier.T1, TrustTier.T2 -> RiskLevel.LOW
            TrustTier.T3 -> RiskLevel.MEDIUM
            TrustTier.T4 -> RiskLevel.HIGH
        }

        fun requestRisk(items: List<ConsentItem>, verifierTier: TrustTier): RiskLevel =
            items.fold(verifierRisk(verifierTier)) { acc, i -> RiskLevel.max(acc, i.sensitivity) }
    }
}

/** A Trust Anchor fetched from its Entity Configuration, waiting for the user to compare its keys. */
data class PendingFederationAnchor(
    val anchor: FederationAnchor,
    val organization: String?,
    /** A Trust Anchor normally has none; hints mean the entity is itself under another anchor. */
    val authorityHints: List<String>,
    /** "kid：RFC 7638 thumbprint" for each key. */
    val thumbprints: List<String>,
)

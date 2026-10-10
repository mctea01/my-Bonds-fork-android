package diw.wallet.app

import diw.wallet.core.compat.Draft13Dialect
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.PlatformCrypto
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
import diw.wallet.core.oid4vp.PreparedPresentation
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.isAcceptableEndpoint
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
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
    /** OpenID4VCI draft 13 and earlier SD-JWT VC drafts (walt.id and many deployed issuers). */
    val compatDraft13: Boolean = true,
    /** TWDIW profile: W3C credentials in SD-JWT without vct, issuer keys via jku. Non-standard, off by default. */
    val compatTwdiw: Boolean = false,
)

sealed class Screen {
    data object Home : Screen()
    data object Settings : Screen()
    data object Issuance : Screen()
    data object Presentation : Screen()
    data class DocumentDetail(val documentId: String) : Screen()
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
data class ConsentItem(val documentName: String, val claims: List<String>, val documentTrust: TrustDecision?)

sealed class PresentationUi {
    data object Loading : PresentationUi()
    data class Consent(
        val prepared: PreparedPresentation,
        val selection: CredentialSelection,
        val items: List<ConsentItem>,
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
    val documents = MutableStateFlow<List<Document>>(emptyList())
    val issuance = MutableStateFlow<IssuanceUi>(IssuanceUi.Loading)
    val presentation = MutableStateFlow<PresentationUi>(PresentationUi.Loading)
    val settingsFlow = MutableStateFlow(WalletSettings())
    val pinRequest = MutableStateFlow<PinRequest?>(null)
    val message = MutableStateFlow<String?>(null)
    val statuses = MutableStateFlow<Map<String, CredentialStatus>>(emptyMap())
    val ready = MutableStateFlow(false)

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
    val http: HttpClient by lazy { platform.httpClient() }

    private var issuanceSession: IssuanceSession? = null
    private var dcApiResult: CompletableDeferred<JsonObject?>? = null

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
        backends = platform.keyBackends(storage) { reason -> operationPin(reason) }
        val repo = SecureAreaRepository.Builder().apply { backends.map { it.secureArea }.distinct().forEach { add(it) } }.build()
        documentStore = buildDocumentStore(storage, repo) {}
        trust = TrustRegistry(storage, environmentPolicy)
        source = SimplePresentmentSource(
            documentStore = documentStore,
            documentTypeRepository = documentTypes,
            domainsMdocSignature = listOf(CredentialDomains.MDOC),
            domainsKeyBoundSdJwt = listOf(CredentialDomains.SD_JWT),
            domainsKeylessSdJwt = listOf(CredentialDomains.SD_JWT_KEYLESS),
        )
        refreshDocuments()
        ready.value = true
    }

    // ---------------------------------------------------------------- settings

    private val settingsTable = StorageTableSpec(name = "DiwSettings", supportPartitions = false, supportExpiration = false)

    private suspend fun loadSettings(): WalletSettings {
        val t = storage.getTable(settingsTable)
        val raw = t.get("settings") ?: return WalletSettings()
        return runCatching { DiwJson.decodeFromString(WalletSettings.serializer(), raw.decodeToString()) }.getOrDefault(WalletSettings())
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

    private fun endOperation() {
        pinCache = null
    }

    // ---------------------------------------------------------------- documents

    fun refreshDocuments() = scope.launch {
        documents.value = documentStore.listDocuments()
    }

    fun deleteDocument(doc: Document) = scope.launch {
        documentStore.deleteDocument(doc.identifier)
        refreshDocuments()
        platform.registerDigitalCredentials(this@WalletModel)
        screen.value = Screen.Home
    }

    fun checkStatus(doc: Document) = scope.launch {
        val cred = doc.getCertifiedCredentials().firstOrNull() ?: return@launch
        val s = CredentialStatusChecker(http, trust).check(cred, bypassCache = true)
        statuses.value = statuses.value + (doc.identifier to s)
    }

    // ---------------------------------------------------------------- entry

    /** Dispatches any wallet URI: credential offers, presentation requests, and the OID4VCI redirect. */
    fun handleUri(uri: String) {
        val u = uri.trim()
        val scheme = u.substringBefore(':').lowercase()
        when {
            u.startsWith(platform.oid4vciRedirectUri) -> completeAuthorization(u)
            scheme in setOf("openid-credential-offer", "haip-vci") || "credential_offer" in u -> startIssuance(u)
            scheme in setOf("openid4vp", "haip-vp", "eudi-openid4vp", "mdoc-openid4vp") || ("client_id=" in u && scheme == "https") -> startPresentation(u)
            // A bare issuer address: list what it issues and let the user pick (wallet-initiated issuance).
            scheme == "https" || scheme == "http" -> startFromIssuer(u)
            '.' in u && ' ' !in u && ':' !in u -> startFromIssuer("https://$u")
            else -> message.value = "無法辨識的連結"
        }
    }

    // ---------------------------------------------------------------- issuance

    private fun oid4vci(): Oid4vciClient = Oid4vciClient(
        http, trust, environmentPolicy, walletProvider(), documentStore,
        dialects = buildList {
            val loopback = environmentPolicy.insecureLoopbackAllowed
            if (settings.compatDraft13) add(Draft13Dialect(http, loopback))
            if (settings.compatTwdiw) add(TwdiwDialect(http, loopback))
        },
    )

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

    fun startIssuance(uri: String) {
        issuance.value = IssuanceUi.Loading
        screen.value = Screen.Issuance
        scope.launch {
            try {
                val c = oid4vci()
                val session = c.startFromOffer(uri)
                issuanceSession = session
                val issuerName = session.issuer.display.pick(listOf("zh-TW", "en"))?.name ?: session.issuer.credentialIssuer
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
                if (session.authServer.authorizationEndpoint == null) {
                    throw ProtocolException("unsupported_grant", "此發行端只接受由它產生的領卡連結（預授權碼），請從發行端網頁取得 QR Code 或連結")
                }
                issuance.value = IssuanceUi.Review(
                    session = session,
                    configurations = issuer.configurations.values.sortedBy { it.display.pick(listOf("zh-TW", "en"))?.name ?: it.id },
                    issuerName = issuer.display.pick(listOf("zh-TW", "en"))?.name ?: issuer.credentialIssuer,
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
                c.authorizePreAuthorized(review.session, txCode)
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
                    val name = config.display.pick(listOf("zh-TW", "en"))?.name ?: config.id
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
        issuance.value = if (results.isEmpty() && failures.size == 1) IssuanceUi.Failed(failures.single().second)
        else IssuanceUi.Done(results, failures)
    }

    private fun keyRequest(): KeyRequest {
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

    private fun holder() = Oid4vpHolder(http, trust, source, environmentPolicy, PresentationPolicy())

    fun startPresentation(uri: String) {
        presentation.value = PresentationUi.Loading
        screen.value = Screen.Presentation
        scope.launch {
            try {
                presentation.value = consentFor(holder().prepare(holder().resolveUri(uri)))
            } catch (e: Exception) {
                presentation.value = PresentationUi.Failed(describe(e))
            }
        }
    }

    /** Digital Credentials API entry (Android Credential Manager). Completes with the response data, or null when declined. */
    suspend fun presentDcApi(protocol: String, data: JsonObject, origin: String): JsonObject? {
        val done = CompletableDeferred<JsonObject?>()
        dcApiResult = done
        presentation.value = PresentationUi.Loading
        screen.value = Screen.Presentation
        try {
            val h = holder()
            presentation.value = consentFor(h.prepare(h.resolveDcApi(protocol, data, origin)))
        } catch (e: Exception) {
            presentation.value = PresentationUi.Failed(describe(e))
            dcApiResult = null
            return null
        }
        return done.await()
    }

    private suspend fun consentFor(prepared: PreparedPresentation): PresentationUi.Consent {
        val selection = prepared.queryResult.select(emptyList())
        val items = selection.matches.map { m ->
            val doc = m.credential.document
            ConsentItem(
                documentName = doc.displayName ?: "憑證",
                claims = m.claims.values.map { it.displayName },
                documentTrust = null,
            )
        }
        return PresentationUi.Consent(prepared, selection, items)
    }

    fun approve(consent: PresentationUi.Consent) = scope.launch {
        presentation.value = PresentationUi.Working("產生並送出回應")
        try {
            val outcome = try {
                withContext(unlockProvider) { holder().respond(consent.prepared, consent.selection) }
            } finally {
                endOperation()
            }
            if (outcome is PresentationOutcome.DcApi) {
                dcApiResult?.complete(outcome.data)
                dcApiResult = null
            }
            if (outcome is PresentationOutcome.Posted) outcome.redirectUri?.let { platform.openRedirect(it) }
            presentation.value = PresentationUi.Done(outcome)
            refreshDocuments()
        } catch (e: Exception) {
            presentation.value = PresentationUi.Failed(describe(e))
        }
    }

    fun decline(consent: PresentationUi.Consent) = scope.launch {
        runCatching { holder().decline(consent.request) }
        dcApiResult?.complete(null)
        dcApiResult = null
        presentation.value = PresentationUi.Failed("已拒絕分享")
    }

    fun cancelDcApi() {
        dcApiResult?.complete(null)
        dcApiResult = null
    }

    // ---------------------------------------------------------------- helpers

    fun describe(e: Throwable): String = when (e) {
        is diw.wallet.core.oid4vp.RequestValidationException -> "請求驗證失敗（${e.code}）：${e.message}"
        is ProtocolException -> "協定錯誤（${e.code}）：${e.message}" + compatHint(e)
        else -> e.message ?: e::class.simpleName ?: "未知錯誤"
    }

    /** Points at the setting that would help when a failure is one a compatibility mode handles. */
    private fun compatHint(e: ProtocolException): String {
        val m = e.message ?: return ""
        return when {
            !settings.compatTwdiw && ("without vct" in m || "non-https iss" in m) -> "\n此發行端使用非標準格式（如 TWDIW），可在設定開啟「TWDIW 相容模式」後再試。"
            !settings.compatDraft13 && ("non-https iss" in m || e.code == "invalid_proof" || e.code == "invalid_credential_response") ->
                "\n此發行端可能採用 OpenID4VCI 舊版草案，可在設定開啟「舊版草案相容模式」後再試。"
            "No test found with alias" in m -> "\n這是 OpenID 認證測試套件：需先在套件網頁啟動測試模組，等它顯示等待錢包時再掃描或貼上它給的連結。"
            else -> ""
        }
    }

    companion object {
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
    }
}

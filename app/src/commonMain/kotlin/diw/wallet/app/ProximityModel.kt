package diw.wallet.app

import diw.wallet.core.credential.ClaimReader
import diw.wallet.core.credential.ClaimSensitivity
import diw.wallet.core.oid4vci.CredentialDomains
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.x509.displaySubject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.multipaz.asn1.OID
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethod
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodNfc
import org.multipaz.mdoc.engagement.buildDeviceEngagement
import org.multipaz.mdoc.nfc.MdocNfcEngagementHelper
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.transport.MdocTransport
import org.multipaz.mdoc.transport.MdocTransportClosedException
import org.multipaz.mdoc.transport.MdocTransportFactory
import org.multipaz.mdoc.transport.MdocTransportOptions
import org.multipaz.mdoc.transport.advertise
import org.multipaz.mdoc.transport.waitForConnection
import org.multipaz.presentment.ConsentData
import org.multipaz.presentment.CredentialSelection
import org.multipaz.presentment.Iso18013Presentment
import org.multipaz.presentment.PresentmentCanceledException
import org.multipaz.presentment.PresentmentCannotSatisfyRequestException
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.request.Requester
import org.multipaz.util.UUID
import org.multipaz.util.toBase64Url
import kotlin.time.Duration.Companion.minutes

/** How a proximity (ISO/IEC 18013-5) presentation was engaged. */
enum class ProximityChannel(val title: String) {
    NFC("NFC 感應"),
    QR("QR Code"),
}

/** What the proximity presentation screen shows. */
sealed class ProximityUi {
    /** Listening: an NFC tap engages; [qr] is the device engagement shown as a QR code once the user asks for it. */
    data class Ready(val qr: String? = null) : ProximityUi()
    data class Working(val message: String) : ProximityUi()

    /** The reader's request, waiting for the user. */
    data class Consent(
        val channel: ProximityChannel,
        val verifier: String,
        val trust: TrustDecision,
        /** The reader's certificate chain (reader authentication), empty when it did not authenticate. */
        val chain: List<X509Cert>,
        val items: List<ConsentItem>,
        /** Claim names the reader says it will keep (intent to retain). */
        val retained: List<String>,
        val risk: RiskLevel,
        internal val answer: CompletableDeferred<Boolean>,
    ) : ProximityUi()

    data class Done(val verifier: String, val documents: List<String>) : ProximityUi()
    data class Failed(val message: String) : ProximityUi()
}

/**
 * Presents documents in person according to ISO/IEC 18013-5: the reader engages by an NFC tap (NDEF, static or
 * negotiated handover) or by scanning the wallet's QR code, the data goes over BLE or NFC, and the request is shown
 * on the wallet's own consent screen. Keys are unlocked with the App PIN or the platform prompt as for any other
 * presentation, and the presentation is recorded in the history.
 *
 * An NFC tap only engages while the proximity screen is open ([listening]), so a reader never gets an answer
 * without the user having asked to present.
 */
class ProximityModel(private val model: WalletModel) {
    val state = MutableStateFlow<ProximityUi>(ProximityUi.Ready())

    /** True while the proximity screen is open. */
    val listening = MutableStateFlow(false)

    /** Creates BLE and NFC transports; the platform default unless a test replaces it. */
    var transportFactory: MdocTransportFactory = MdocTransportFactory.Default
    var transportOptions = MdocTransportOptions()

    private var job: Job? = null

    /** Opens the proximity screen and starts listening for an NFC tap. */
    fun open() {
        cancel()
        state.value = ProximityUi.Ready()
        listening.value = true
        model.platform.setNfcPresentationActive(true)
        model.screen.value = Screen.Proximity
    }

    /** Leaves the screen: a pending request is refused and the connection closed. */
    fun close() {
        listening.value = false
        model.platform.setNfcPresentationActive(false)
        cancel()
    }

    /** Back to listening after a presentation ended. */
    fun again() {
        cancel()
        state.value = ProximityUi.Ready()
    }

    private fun cancel() {
        (state.value as? ProximityUi.Consent)?.answer?.complete(false)
        job?.cancel()
        job = null
    }

    fun approve(consent: ProximityUi.Consent) {
        consent.answer.complete(true)
    }

    fun decline(consent: ProximityUi.Consent) {
        consent.answer.complete(false)
    }

    /**
     * The NFC engagement for one tap (ISO/IEC 18013-5 clause 8.2.2.1), fed with the reader's APDUs by the platform
     * NFC service; null when the screen is not open. [onEngaged] runs when the reader completed the handover.
     */
    suspend fun nfcEngagement(staticHandover: Boolean = model.settings.nfcStaticHandover, onEngaged: () -> Unit = {}): MdocNfcEngagementHelper? {
        if (!listening.value) return null
        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val bleUuid = UUID.randomUUID()
        val static = if (staticHandover) listOf(
            MdocConnectionMethodBle(supportsPeripheralServerMode = false, supportsCentralClientMode = true, peripheralServerModeUuid = null, centralClientModeUuid = bleUuid),
            MdocConnectionMethodBle(supportsPeripheralServerMode = true, supportsCentralClientMode = false, peripheralServerModeUuid = bleUuid, centralClientModeUuid = null),
            MdocConnectionMethodNfc(commandDataFieldMaxLength = 0xffff, responseDataFieldMaxLength = 0x10000),
        ) else null
        return MdocNfcEngagementHelper(
            eDeviceKey = eDeviceKey.publicKey,
            onHandoverComplete = { methods, encodedDeviceEngagement, handover ->
                onEngaged()
                start(ProximityChannel.NFC) {
                    val transports = methods.advertise(MdocRole.MDOC, transportFactory, transportOptions)
                    Engaged(eDeviceKey, Cbor.decode(encodedDeviceEngagement.toByteArray()), handover, transports)
                }
            },
            // Anything that is not an mdoc reader (another phone reading NDEF, a payment terminal) is ignored quietly.
            onError = {},
            staticHandoverMethods = static,
            negotiatedHandoverPicker = if (staticHandover) null else { methods -> pick(methods) },
        )
    }

    /** Shows the device engagement as a QR code (ISO/IEC 18013-5 clause 8.2.2.3) and waits for the reader over BLE. */
    fun showQr() {
        start(ProximityChannel.QR) {
            model.platform.proximityTransportUnavailableReason()?.let { throw Unavailable(it) }
            val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val methods = listOf<MdocConnectionMethod>(
                MdocConnectionMethodBle(supportsPeripheralServerMode = false, supportsCentralClientMode = true, peripheralServerModeUuid = null, centralClientModeUuid = UUID.randomUUID()),
                MdocConnectionMethodBle(supportsPeripheralServerMode = true, supportsCentralClientMode = false, peripheralServerModeUuid = UUID.randomUUID(), centralClientModeUuid = null),
            )
            val transports = methods.advertise(MdocRole.MDOC, transportFactory, transportOptions)
            val engagement = buildDeviceEngagement(eDeviceKey = eDeviceKey.publicKey) {
                transports.forEach { addConnectionMethod(it.connectionMethod) }
            }.toDataItem()
            state.value = ProximityUi.Ready(qr = "mdoc:" + Cbor.encode(engagement).toBase64Url())
            Engaged(eDeviceKey, engagement, Simple.NULL, transports)
        }
    }

    /** Negotiated handover: BLE with the wallet as central first (fastest on Android), then as peripheral, then NFC. */
    private fun pick(methods: List<MdocConnectionMethod>): MdocConnectionMethod {
        for (prefix in HANDOVER_ORDER) methods.firstOrNull { it.toString().startsWith(prefix) }?.let { return it }
        return methods.first()
    }

    /** The platform cannot carry the presentation now; the message says why. */
    private class Unavailable(message: String) : Exception(message)

    private class Engaged(val eDeviceKey: EcPrivateKey, val deviceEngagement: DataItem, val handover: DataItem, val transports: List<MdocTransport>)

    /** What the user agreed to, for the history once the response is sent. */
    private class Shared(val verifier: String, val trust: TrustDecision, val items: List<ConsentItem>)

    private fun start(channel: ProximityChannel, engage: suspend () -> Engaged) {
        job?.cancel()
        job = model.scope.launch { transact(channel, engage) }
    }

    private suspend fun transact(channel: ProximityChannel, engage: suspend () -> Engaged) {
        var engaged: Engaged? = null
        var transport: MdocTransport? = null
        var shared: Shared? = null
        var sent = false
        var refused: Shared? = null
        fun finish() {
            if (state.value is ProximityUi.Done) return
            val s = shared ?: return
            state.value = ProximityUi.Done(s.verifier, s.items.map { it.documentName })
            model.record(HistoryKind.PRESENTED, s.verifier, s.trust, s.items.map { it.documentName }, s.items.flatMap { it.claims }, note(channel))
        }
        try {
            if (channel == ProximityChannel.NFC) state.value = ProximityUi.Working("已感應，正在連線查驗設備")
            engaged = engage()
            transport = withTimeout(CONNECT_TIMEOUT) { engaged.transports.waitForConnection(eSenderKey = engaged.eDeviceKey.publicKey) }
            state.value = ProximityUi.Working("等待查驗設備的請求")
            val source = source(channel, onShared = { shared = it }, onRefused = { refused = it })
            withContext(model.unlockProvider) {
                Iso18013Presentment(
                    transport = transport,
                    eDeviceKey = engaged.eDeviceKey,
                    deviceEngagement = engaged.deviceEngagement,
                    handover = engaged.handover,
                    source = source,
                    keyAgreementPossible = listOf(engaged.eDeviceKey.curve),
                    // A response was sent when the presentation waits for the reader again.
                    onWaitingForRequest = { if (sent) finish() },
                    onSendingResponse = {
                        sent = true
                        state.value = ProximityUi.Working("送出證件資料")
                    },
                )
            }
            if (sent) finish() else state.value = ProximityUi.Failed("查驗設備結束了連線，沒有提出請求")
        } catch (e: CancellationException) {
            throw e
        } catch (e: PresentmentCanceledException) {
            refused?.let { model.record(HistoryKind.DECLINED, it.verifier, it.trust, it.items.map { i -> i.documentName }, it.items.flatMap { i -> i.claims }, note(channel)) }
            state.value = ProximityUi.Failed("已拒絕分享")
        } catch (e: PresentmentCannotSatisfyRequestException) {
            state.value = ProximityUi.Failed("這支手機沒有查驗設備要求的證件。近距離出示適用行動駕照等 mdoc 證件。")
        } catch (e: Exception) {
            // Readers often close the connection or stop talking once they have the response.
            if (sent) finish() else state.value = ProximityUi.Failed(failure(e))
        } finally {
            runCatching { transport?.close() }
            engaged?.transports?.forEach { t -> if (t !== transport) runCatching { t.close() } }
            model.endOperation()
            model.refreshDocuments()
        }
    }

    private fun failure(e: Exception): String = when (e) {
        is Unavailable -> e.message.orEmpty()
        is kotlinx.coroutines.TimeoutCancellationException -> "查驗設備沒有連線。請確認藍牙已開啟，再感應或掃描一次。"
        is MdocTransportClosedException -> "連線中斷。請再感應或掃描一次。"
        is NotImplementedError -> "此平台不支援近距離傳輸（藍牙或 NFC）"
        else -> "近距離出示失敗：" + model.describe(e)
    }

    private fun note(channel: ProximityChannel) = "近距離出示（ISO/IEC 18013-5，${channel.title}）"

    /** The presentment source: the wallet's documents, with the wallet's consent screen in place of Multipaz's prompt. */
    private fun source(channel: ProximityChannel, onShared: (Shared) -> Unit, onRefused: (Shared) -> Unit) = SimplePresentmentSource(
        documentStore = model.documentStore,
        documentTypeRepository = model.documentTypes,
        showConsentPromptFn = { requester, _, consentData, preselected, onDocumentsInFocus ->
            consent(channel, requester, consentData, preselected, onDocumentsInFocus, onShared, onRefused)
        },
        preferSignatureToKeyAgreement = true,
        domainsMdocSignature = listOf(CredentialDomains.MDOC),
        domainsKeyBoundSdJwt = listOf(CredentialDomains.SD_JWT),
        domainsKeylessSdJwt = listOf(CredentialDomains.SD_JWT_KEYLESS),
    )

    private suspend fun consent(
        channel: ProximityChannel,
        requester: Requester,
        consentData: ConsentData,
        preselected: List<org.multipaz.document.Document>,
        onDocumentsInFocus: (List<org.multipaz.document.Document>) -> Unit,
        onShared: (Shared) -> Unit,
        onRefused: (Shared) -> Unit,
    ): CredentialSelection? {
        val selection = consentData.credentialQueryResult.select(preselected)
        onDocumentsInFocus(selection.matches.map { it.credential.document })
        val items = selection.matches.map { m ->
            val doc = m.credential.document
            ConsentItem(
                documentName = doc.displayName ?: "證件",
                claims = m.claims.values.map { model.claimLabel(ClaimReader.pathOf(it), it.displayName, doc.issuanceRecord) },
                documentTrust = null,
                documentId = doc.identifier,
                sensitivity = ClaimSensitivity.ofAll(m.claims.values.map { ClaimReader.pathOf(it) }),
            )
        }
        val retained = selection.matches.flatMap { m ->
            m.claims.filterKeys { (it as? MdocRequestedClaim)?.intentToRetain == true }.values
                .map { model.claimLabel(ClaimReader.pathOf(it), it.displayName, m.credential.document.issuanceRecord) }
        }.distinct()
        val chain = requester.requesterIdentities.firstOrNull()?.certChain?.certificates.orEmpty()
        val trust = if (chain.isEmpty()) {
            TrustDecision.unknown("The reader did not authenticate (no readerAuth)", labels = setOf(TrustLabel.UNSIGNED_REQUEST))
        } else {
            // The reader's signature over the request was verified against this chain before the prompt.
            model.trust.decide(TrustRole.VERIFIER, chain)
        }
        val verifier = chain.firstOrNull()?.let { c -> c.subject.components[OID.COMMON_NAME.oid]?.value ?: c.displaySubject() } ?: "未提供身分的查驗設備"
        val risk = WalletModel.requestRisk(items, trust.tier)
        model.status.refreshFor(items.mapNotNull { it.documentId }, risk)
        val answer = CompletableDeferred<Boolean>()
        state.value = ProximityUi.Consent(channel, verifier, trust, chain, items, retained, risk, answer)
        val s = Shared(verifier, trust, items)
        return if (answer.await()) {
            onShared(s)
            state.value = ProximityUi.Working("產生並送出回應")
            selection
        } else {
            onRefused(s)
            null
        }
    }

    companion object {
        private val CONNECT_TIMEOUT = 1.minutes
        private val HANDOVER_ORDER = listOf("ble:central_client_mode:", "ble:peripheral_server_mode:", "nfc:")
    }
}

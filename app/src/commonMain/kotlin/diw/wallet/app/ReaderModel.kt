package diw.wallet.app

import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusDecision
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.x509.displaySubject
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.datetime.TimeZone
import kotlin.time.Clock
import org.multipaz.asn1.OID
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.buildCborArray
import org.multipaz.claim.MdocClaim
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.documenttype.DocumentAttributeType
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethod
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodNfc
import org.multipaz.mdoc.engagement.DeviceEngagement
import org.multipaz.mdoc.nfc.MdocReaderNfcHandoverResult
import org.multipaz.mdoc.nfc.mdocReaderNfcHandover
import org.multipaz.mdoc.request.DeviceRequestGenerator
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.sessionencryption.SessionEncryption
import org.multipaz.mdoc.transport.MdocTransport
import org.multipaz.mdoc.transport.MdocTransportClosedException
import org.multipaz.mdoc.transport.MdocTransportException
import org.multipaz.mdoc.transport.MdocTransportFactory
import org.multipaz.mdoc.transport.MdocTransportOptions
import org.multipaz.mdoc.transport.NfcTransportMdocReader
import org.multipaz.nfc.NfcTagLostException
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.util.Constants
import org.multipaz.util.UUID
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** What the reader asks the other wallet for: one ISO mdoc document type and its data elements. */
enum class ReaderRequest(val title: String, val detail: String, val docType: String, val namespace: String, val elements: List<String>) {
    MDL_IDENTITY(
        "行動駕照：身分確認", "姓名、出生日期、照片、證號與有效期限", MDL, MDL_NS,
        listOf("family_name", "given_name", "birth_date", "portrait", "document_number", "issuing_country", "issuing_authority", "issue_date", "expiry_date"),
    ),
    MDL_DRIVING(
        "行動駕照：駕駛資格", "姓名、照片、駕駛類別與有效期限", MDL, MDL_NS,
        listOf("family_name", "given_name", "portrait", "driving_privileges", "expiry_date"),
    ),
    AGE_OVER_18("年滿 18 歲", "只確認是否年滿 18 歲，附照片供比對本人", MDL, MDL_NS, listOf("age_over_18", "portrait")),
    EU_PID(
        "歐盟個人身分（PID）", "姓名、出生日期、國籍與發行國", PID, PID,
        listOf("family_name", "given_name", "birth_date", "nationality", "issuing_country", "expiry_date"),
    ),
}

private const val MDL = "org.iso.18013.5.1.mDL"
private const val MDL_NS = "org.iso.18013.5.1"
private const val PID = "eu.europa.ec.eudi.pid.1"

/** One returned element: its label and rendered value, or the picture's bytes. */
data class ReadClaim(val label: String, val value: String, val picture: ByteArray? = null) {
    override fun equals(other: Any?) = other is ReadClaim && other.label == label && other.value == value && other.picture.contentEquals(picture)
    override fun hashCode() = label.hashCode() * 31 + value.hashCode()
}

/** A document the other wallet returned, verified, with its issuer's trust and its status for the purpose. */
data class ReadDocument(
    val docType: String,
    val title: String,
    val issuer: String,
    val issuerTrust: TrustDecision,
    val chain: List<X509Cert>,
    val validFrom: kotlin.time.Instant,
    val validUntil: kotlin.time.Instant,
    val signedAt: kotlin.time.Instant,
    val claims: List<ReadClaim>,
    /** Requested elements the holder did not return. */
    val withheld: List<String>,
    val status: CredentialStatus,
    val statusDecision: StatusDecision,
)

/** What the in-person verification screen shows. */
sealed class ReaderUi {
    /** Choosing what to ask for, the risk of the purpose and the reader. */
    data object Setup : ReaderUi()
    data class Scanning(val request: ReaderRequest, val message: String) : ReaderUi()
    data class Result(
        val request: ReaderRequest,
        val risk: RiskLevel,
        /** How the data came: NFC or Bluetooth after the tap. */
        val transport: String,
        val documents: List<ReadDocument>,
        /** Why the response could not be verified; null when every document passed the integrity checks. */
        val integrityError: String?,
    ) : ReaderUi()
    data class Failed(val request: ReaderRequest, val message: String) : ReaderUi()
}

/**
 * The wallet as an ISO/IEC 18013-5 mdoc reader: a tap engages the other wallet over NFC (static or negotiated
 * handover), the request and response go over NFC or, on a phone, Bluetooth, and the response is checked here:
 * issuer signature and digests, device authentication bound to this session, validity, the issuer's trust by the
 * wallet's anchors, and the status for the purpose's risk. The reader is the phone's own NFC or an external reader,
 * PC/SC on a computer and USB CCID on a phone.
 */
class ReaderModel(private val model: WalletModel) {
    val state = MutableStateFlow<ReaderUi>(ReaderUi.Setup)
    val readers = MutableStateFlow<NfcReaderList?>(null)

    /** Creates the Bluetooth transport after a tap; the platform default unless a test replaces it. */
    var transportFactory: MdocTransportFactory = MdocTransportFactory.Default
    var transportOptions = MdocTransportOptions()

    private var job: Job? = null

    fun open() {
        cancel()
        state.value = ReaderUi.Setup
        model.screen.value = Screen.Reader
        refreshReaders()
    }

    fun refreshReaders() = model.scope.launch {
        readers.value = try {
            model.platform.nfcReaders()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            NfcReaderList(emptyList(), "無法列出讀卡機：" + model.describe(e))
        }
    }

    fun close() = cancel()

    fun again() {
        cancel()
        state.value = ReaderUi.Setup
    }

    private fun cancel() {
        job?.cancel()
        job = null
    }

    /** Waits for a tap on [option] and reads [request]; the result is judged at [risk]. */
    fun start(option: NfcReaderOption, request: ReaderRequest, risk: RiskLevel) {
        cancel()
        job = model.scope.launch { read(option, request, risk) }
    }

    private class Unavailable(message: String) : Exception(message)

    /** The decrypted DeviceResponse and what it is bound to. */
    private class Received(val response: ByteArray, val transcript: DataItem, val eReaderKey: EcPrivateKey, val transport: String)

    private sealed class Tapped {
        class Done(val received: Received) : Tapped()
        class Bluetooth(val handover: MdocReaderNfcHandoverResult) : Tapped()
    }

    internal suspend fun read(option: NfcReaderOption, request: ReaderRequest, risk: RiskLevel) {
        val where = if (option.external) "讀卡機「${option.name}」" else "這支手機的背面"
        state.value = ReaderUi.Scanning(request, "請對方在錢包開啟「感應出示」，再把手機靠近$where。")
        try {
            val bluetooth = option.bluetooth && model.platform.proximityTransportUnavailableReason() == null
            val offered = buildList<MdocConnectionMethod> {
                if (bluetooth) {
                    add(MdocConnectionMethodBle(supportsPeripheralServerMode = false, supportsCentralClientMode = true, peripheralServerModeUuid = null, centralClientModeUuid = UUID.randomUUID()))
                    add(MdocConnectionMethodBle(supportsPeripheralServerMode = true, supportsCentralClientMode = false, peripheralServerModeUuid = UUID.randomUUID(), centralClientModeUuid = null))
                }
                add(MdocConnectionMethodNfc(commandDataFieldMaxLength = 0xffff, responseDataFieldMaxLength = 0x10000))
            }
            val eReaderKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val tapped = option.reader.scan<Tapped>(
                message = "請將對方的手機靠近",
                tagInteractionFunc = { tag ->
                    // Not an mdoc (a card, a locked phone that asks to be unlocked): keep waiting for the next tap.
                    val handover = mdocReaderNfcHandover(tag, offered) ?: return@scan null
                    val methods = MdocConnectionMethod.disambiguate(handover.connectionMethods, MdocRole.MDOC_READER)
                    val nfc = methods.filterIsInstance<MdocConnectionMethodNfc>().firstOrNull()
                    if (bluetooth && methods.any { it is MdocConnectionMethodBle } || nfc == null) {
                        tag.close()
                        Tapped.Bluetooth(handover.copy(connectionMethods = methods))
                    } else {
                        state.value = ReaderUi.Scanning(request, "已感應，請對方在手機上確認分享，期間手機請保持靠近。")
                        val transport = NfcTransportMdocReader(MdocRole.MDOC_READER, transportOptions, nfc)
                        transport.setTag(tag)
                        Tapped.Done(exchange(transport, handover, eReaderKey, request, "NFC"))
                    }
                },
            )
            val received = when (tapped) {
                is Tapped.Done -> tapped.received
                is Tapped.Bluetooth -> {
                    val ble = tapped.handover.connectionMethods.firstOrNull { it is MdocConnectionMethodBle }
                    if (ble == null || !bluetooth) {
                        throw Unavailable(
                            if (option.bluetooth) "對方要求以藍牙傳送，但這支手機的藍牙目前無法使用（未開啟或沒有權限）。"
                            else "對方只提供藍牙傳送，這個讀卡機只能用 NFC 讀取。請對方在錢包改用 NFC 傳送後再感應一次。"
                        )
                    }
                    state.value = ReaderUi.Scanning(request, "已感應，以藍牙連線。請對方在手機上確認分享。")
                    exchange(transportFactory.createTransport(ble, MdocRole.MDOC_READER, transportOptions), tapped.handover, eReaderKey, request, "藍牙")
                }
            }
            state.value = ReaderUi.Scanning(request, "驗證證件與查詢狀態")
            state.value = evaluate(received, request, risk)
        } catch (e: CancellationException) {
            throw e
        } catch (e: NotImplementedError) {
            // A transport the platform does not implement (Bluetooth on the desktop).
            val message = "此平台不支援藍牙近距離傳輸"
            model.record(HistoryKind.VERIFIED, "出示者", null, note = note(request, null), failure = message)
            state.value = ReaderUi.Failed(request, message)
        } catch (e: Exception) {
            val message = failure(e)
            model.record(HistoryKind.VERIFIED, "出示者", null, note = note(request, null), failure = message)
            state.value = ReaderUi.Failed(request, message)
        }
    }

    /** Sends the request on [transport] and waits for the holder's answer; closes the transport. */
    private suspend fun exchange(
        transport: MdocTransport,
        handover: MdocReaderNfcHandoverResult,
        eReaderKey: EcPrivateKey,
        request: ReaderRequest,
        via: String,
    ): Received {
        try {
            val encodedEngagement = handover.encodedDeviceEngagement.toByteArray()
            val engagement = DeviceEngagement.fromDataItem(Cbor.decode(encodedEngagement))
            val transcript = buildCborArray {
                add(Tagged(Tagged.ENCODED_CBOR, Bstr(encodedEngagement)))
                add(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(eReaderKey.publicKey.toCoseKey().toDataItem()))))
                add(handover.handover)
            }
            val encodedTranscript = Cbor.encode(transcript)
            val session = SessionEncryption(
                role = MdocRole.MDOC_READER,
                eSelfKey = eReaderKey,
                remotePublicKey = engagement.eDeviceKey,
                encodedSessionTranscript = encodedTranscript,
            )
            val deviceRequest = DeviceRequestGenerator(encodedTranscript).addDocumentRequest(
                docType = request.docType,
                // Nothing is kept: the wallet records field names only.
                itemsToRequest = mapOf(request.namespace to request.elements.associateWith { false }),
                requestInfo = null,
                readerKey = null,
                signatureAlgorithm = Algorithm.UNSET,
                readerKeyCertificateChain = null,
            ).generate()
            // Not withTimeout: the NFC transport runs its I/O loop as a child of the caller, which withTimeout would
            // wait for. A watchdog closes the transport instead when the holder never connects.
            val watchdog = model.scope.launch {
                delay(CONNECT_TIMEOUT)
                runCatching { transport.close() }
            }
            try {
                transport.open(engagement.eDeviceKey)
            } finally {
                watchdog.cancel()
            }
            transport.sendMessage(session.encryptMessage(deviceRequest, null))
            // The holder reads the request and decides; this may take a while.
            val message = withTimeout(ANSWER_TIMEOUT) { transport.waitForMessage() }
            val (plain, status) = session.decryptMessage(message)
            if (plain == null) {
                throw Unavailable(
                    if (status == Constants.SESSION_DATA_STATUS_SESSION_TERMINATION) "對方拒絕分享或結束了連線。"
                    else "對方沒有提供證件（狀態碼 $status）。"
                )
            }
            if (transport !is NfcTransportMdocReader) {
                runCatching { transport.sendMessage(SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION)) }
            }
            return Received(plain, transcript, eReaderKey, via)
        } finally {
            runCatching { transport.close() }
        }
    }

    private suspend fun evaluate(received: Received, request: ReaderRequest, risk: RiskLevel): ReaderUi {
        val response = DeviceResponse.fromDataItem(Cbor.decode(received.response))
        // Issuer signature, digests, validity at this time and device authentication bound to this session.
        val integrity = try {
            response.verify(sessionTranscript = received.transcript, eReaderKey = AsymmetricKey.anonymous(received.eReaderKey))
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            integrityFailure(e)
        }
        if (integrity != null) {
            model.record(HistoryKind.VERIFIED, "出示者", null, note = note(request, received.transport), failure = integrity)
            return ReaderUi.Result(request, risk, received.transport, emptyList(), integrity)
        }
        if (response.status != DeviceResponse.STATUS_OK && response.documents.isEmpty()) {
            throw Unavailable("對方回應錯誤（狀態碼 ${response.status}），沒有提供證件。")
        }
        if (response.documents.isEmpty()) throw Unavailable("對方沒有「${request.title}」要求的證件，或拒絕提供。")
        val documents = response.documents.map { document(it, request, risk) }
        documents.forEach { d ->
            model.record(
                HistoryKind.VERIFIED, "出示者（${d.title}）", d.issuerTrust,
                listOf(d.issuerTrust.anchorName ?: d.issuer),
                d.claims.map { it.label },
                note(request, received.transport) + "；" + StatusTexts.summary(d.statusDecision),
            )
        }
        return ReaderUi.Result(request, risk, received.transport, documents, null)
    }

    private suspend fun document(doc: MdocDocument, request: ReaderRequest, risk: RiskLevel): ReadDocument {
        val chain = doc.issuerCertChain.certificates
        // The docType limits an issuer CA that a VICAL authorises for some document types only.
        val trust = model.trust.decide(TrustRole.ISSUER, chain, docType = doc.docType)
        val mso = doc.mso
        val type = model.documentTypes.getDocumentTypeForMdoc(doc.docType)
        val claims = doc.issuerNamespaces.data.flatMap { (ns, items) ->
            items.map { (element, item) ->
                val attribute = type?.mdocDocumentType?.namespaces?.get(ns)?.dataElements?.get(element)?.attribute
                val label = model.claimLabel(listOf(ns, element), attribute?.displayName, null)
                val value = item.dataElementValue
                when (attribute?.type) {
                    DocumentAttributeType.Picture -> ReadClaim(label, "", runCatching { value.asBstr }.getOrNull())
                    DocumentAttributeType.Boolean -> ReadClaim(label, if (runCatching { value.asBoolean }.getOrDefault(false)) "是" else "否")
                    else -> ReadClaim(label, MdocClaim(label, attribute, doc.docType, ns, element, value).render(TimeZone.currentSystemDefault()))
                }
            }
        }
        val withheld = doc.errors.flatMap { (ns, errors) -> errors.keys.map { model.claimLabel(listOf(ns, it), null, null) } }
        val status = mso.revocationStatus?.let { ref ->
            withTimeoutOrNull(STATUS_TIMEOUT) {
                runCatching { CredentialStatusChecker(model.http, model.trust, didTrust = model.didTrust).check(ref, chain, bypassCache = true) }.getOrNull()
            } ?: CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "離線或狀態清單逾時未回應")
        } ?: CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "Credential carries no status reference", referenced = false)
        val issuer = chain.firstOrNull()?.let { c -> c.subject.components[OID.COMMON_NAME.oid]?.value ?: c.displaySubject() } ?: "未知的發行端"
        return ReadDocument(
            docType = doc.docType,
            title = documentTitle(doc.docType, type?.displayName),
            issuer = issuer,
            issuerTrust = trust,
            chain = chain,
            validFrom = mso.validFrom,
            validUntil = mso.validUntil,
            signedAt = mso.signedAt,
            claims = claims,
            withheld = withheld,
            status = status,
            statusDecision = StatusPolicy.decide(status, risk),
        )
    }

    private fun integrityFailure(e: Exception): String {
        val m = e.message.orEmpty()
        return when {
            "validUntil" in m || "validFrom" in m || "valid" in m && "period" in m -> "證件不在有效期間內（已過期或尚未生效）。"
            "signature" in m.lowercase() -> "簽章驗證失敗：證件資料或出示者的簽章不相符。"
            "digest" in m.lowercase() -> "資料摘要不符：證件內容遭到修改。"
            else -> "證件驗證失敗：" + model.describe(e)
        }
    }

    private fun failure(e: Exception): String = when (e) {
        is Unavailable -> e.message.orEmpty()
        is TimeoutCancellationException -> "等待逾時：對方沒有在時間內回應。請重新感應。"
        is NfcTagLostException -> "感應中斷：請讓對方的手機保持靠近，直到讀取完成。"
        is MdocTransportClosedException -> "連線已結束，對方沒有提供證件。"
        is MdocTransportException -> "感應中斷或連線失敗：請讓對方的手機保持靠近，直到讀取完成。"
        else -> "讀取失敗：" + model.describe(e)
    }

    private fun note(request: ReaderRequest, via: String?) =
        "感應查驗（ISO/IEC 18013-5" + (via?.let { "，$it" } ?: "") + "），要求：${request.title}"

    companion object {
        private val CONNECT_TIMEOUT = 1.minutes
        private val ANSWER_TIMEOUT = 3.minutes
        private val STATUS_TIMEOUT = 8.seconds

        fun documentTitle(docType: String, typeName: String?): String = when (docType) {
            MDL -> "行動駕照"
            PID -> "歐盟個人身分（PID）"
            else -> typeName ?: docType
        }
    }
}

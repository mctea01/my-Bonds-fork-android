package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.StringResource
import diw.wallet.core.zk.LongfellowZk
import org.multipaz.mdoc.request.buildDeviceRequest
import org.multipaz.mdoc.request.DocRequestInfo
import org.multipaz.mdoc.request.ZkRequest
import org.multipaz.mdoc.zkp.ZkSystemSpec
import org.multipaz.mdoc.zkp.ZkDocument
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusDecision
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.document.derived.EvidenceResult
import diw.wallet.core.document.derived.TravelDocumentPhotoId
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
enum class ReaderRequest(
    private val titleRes: StringResource,
    private val detailRes: StringResource,
    val docType: String,
    val namespace: String,
    val elements: List<String>,
    /** Elements of other namespaces of the same document. */
    val more: Map<String, List<String>> = emptyMap(),
) {
    MDL_IDENTITY(
        Res.string.reader_mdl_identity, Res.string.reader_mdl_identity_text, MDL, MDL_NS,
        listOf("family_name", "given_name", "birth_date", "portrait", "document_number", "issuing_country", "issuing_authority", "issue_date", "expiry_date"),
    ),
    MDL_DRIVING(
        Res.string.reader_mdl_driving, Res.string.reader_mdl_driving_text, MDL, MDL_NS,
        listOf("family_name", "given_name", "portrait", "driving_privileges", "expiry_date"),
    ),
    AGE_OVER_18(Res.string.reader_age_18, Res.string.reader_age_18_text, MDL, MDL_NS, listOf("age_over_18", "portrait")),
    EU_PID(
        Res.string.reader_eu_pid, Res.string.reader_eu_pid_text, PID, PID,
        listOf("family_name", "given_name", "birth_date", "nationality", "issuing_country", "expiry_date"),
    ),
    /** A Photo ID made from an electronic passport, with the chip files so passive authentication is repeated here. */
    PHOTO_ID(
        Res.string.reader_photo_id, Res.string.reader_photo_id_text, TravelDocumentPhotoId.DOCTYPE, TravelDocumentPhotoId.NAMESPACE,
        listOf("family_name", "given_name", "birth_date", "portrait", "nationality", "issuing_country", "document_number", "expiry_date"),
        mapOf(TravelDocumentPhotoId.DATAGROUPS_NAMESPACE to listOf("dg1", "dg2", "sod")),
    );

    val title: String get() = tr(titleRes)
    val detail: String get() = tr(detailRes)
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
    /** What the verifier checked beyond the issuer signature (passive authentication of a Photo ID's chip files). */
    val evidence: List<EvidenceResult> = emptyList(),
)

/** A proof reveals neither MSO dates nor a credential status reference. */
data class ReadZkDocument(
    val docType: String,
    val issuerTrust: TrustDecision,
    val chain: List<X509Cert>,
    val proofTime: kotlin.time.Instant,
    val claims: List<ReadClaim>,
) {
    override fun toString() = "ReadZkDocument"
}

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
        val zkDocuments: List<ReadZkDocument> = emptyList(),
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
    val longfellow by lazy { LongfellowZk(model.platform.platformName) }

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
            NfcReaderList(emptyList(), tr(Res.string.reader_list_failed) + model.describe(e))
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

    /** Waits for a tap. [requireZk] requests only age_over_18 and forbids ordinary mdoc responses. */
    fun start(option: NfcReaderOption, request: ReaderRequest, risk: RiskLevel, requireZk: Boolean = false) {
        cancel()
        job = model.scope.launch { read(option, request, risk, requireZk) }
    }

    private class Unavailable(message: String) : Exception(message)

    /** The decrypted DeviceResponse and what it is bound to. */
    private class Received(val response: ByteArray, val transcript: DataItem, val eReaderKey: EcPrivateKey, val transport: String, val zkSpecs: List<ZkSystemSpec>)

    private sealed class Tapped {
        class Done(val received: Received) : Tapped()
        class Bluetooth(val handover: MdocReaderNfcHandoverResult) : Tapped()
    }

    internal suspend fun read(option: NfcReaderOption, request: ReaderRequest, risk: RiskLevel, requireZk: Boolean = false) {
        val where = if (option.external) tr(Res.string.reader_named, option.name) else tr(Res.string.reader_phone_back)
        state.value = ReaderUi.Scanning(request, tr(Res.string.reader_tap_hint, where))
        try {
            val zkSpecs = if (requireZk) {
                if (request != ReaderRequest.AGE_OVER_18) throw Unavailable(tr(Res.string.reader_zk_age_only))
                longfellow.unavailableReason?.let { throw Unavailable(it) }
                longfellow.specs(1).also { if (it.isEmpty()) throw Unavailable(tr(Res.string.reader_no_circuit)) }
            } else emptyList()
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
                message = tr(Res.string.reader_tap_hold, where),
                tagInteractionFunc = { tag ->
                    // Not an mdoc (a card, a locked phone that asks to be unlocked): keep waiting for the next tap.
                    val handover = mdocReaderNfcHandover(tag, offered) ?: return@scan null
                    val methods = MdocConnectionMethod.disambiguate(handover.connectionMethods, MdocRole.MDOC_READER)
                    val nfc = methods.filterIsInstance<MdocConnectionMethodNfc>().firstOrNull()
                    if (bluetooth && methods.any { it is MdocConnectionMethodBle } || nfc == null) {
                        tag.close()
                        Tapped.Bluetooth(handover.copy(connectionMethods = methods))
                    } else {
                        state.value = ReaderUi.Scanning(request, tr(Res.string.reader_tapped))
                        val transport = NfcTransportMdocReader(MdocRole.MDOC_READER, transportOptions, nfc)
                        transport.setTag(tag)
                        Tapped.Done(exchange(transport, handover, eReaderKey, request, "NFC", zkSpecs))
                    }
                },
            )
            val received = when (tapped) {
                is Tapped.Done -> tapped.received
                is Tapped.Bluetooth -> {
                    val ble = tapped.handover.connectionMethods.firstOrNull { it is MdocConnectionMethodBle }
                    if (ble == null || !bluetooth) {
                        throw Unavailable(
                            if (option.bluetooth) tr(Res.string.reader_ble_off)
                            else tr(Res.string.reader_ble_only)
                        )
                    }
                    state.value = ReaderUi.Scanning(request, tr(Res.string.reader_tapped_ble))
                    exchange(transportFactory.createTransport(ble, MdocRole.MDOC_READER, transportOptions), tapped.handover, eReaderKey, request, tr(Res.string.age_route_label_bluetooth), zkSpecs)
                }
            }
            state.value = ReaderUi.Scanning(request, tr(Res.string.reader_verifying))
            state.value = evaluate(received, request, risk)
        } catch (e: CancellationException) {
            throw e
        } catch (e: NotImplementedError) {
            // A transport the platform does not implement (Bluetooth on the desktop).
            val message = tr(Res.string.reader_no_ble)
            model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = note(request, null), failure = message)
            state.value = ReaderUi.Failed(request, message)
        } catch (e: Exception) {
            val message = failure(e)
            model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = note(request, null), failure = message)
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
        zkSpecs: List<ZkSystemSpec>,
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
            val deviceRequest = if (zkSpecs.isNotEmpty()) Cbor.encode(buildDeviceRequest(transcript) {
                addDocRequest(request.docType, mapOf(request.namespace to mapOf("age_over_18" to false)),
                    DocRequestInfo(zkRequest = ZkRequest(systemSpecs = zkSpecs, zkRequired = true)))
            }.toDataItem()) else DeviceRequestGenerator(encodedTranscript).addDocumentRequest(
                docType = request.docType,
                // Nothing is kept: the wallet records field names only.
                itemsToRequest = mapOf(request.namespace to request.elements.associateWith { false }) +
                    request.more.mapValues { (_, names) -> names.associateWith { false } },
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
                    if (status == Constants.SESSION_DATA_STATUS_SESSION_TERMINATION) tr(Res.string.reader_declined)
                    else tr(Res.string.reader_no_document_status, status)
                )
            }
            if (transport !is NfcTransportMdocReader) {
                runCatching { transport.sendMessage(SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION)) }
            }
            return Received(plain, transcript, eReaderKey, via, zkSpecs)
        } finally {
            runCatching { transport.close() }
        }
    }

    private suspend fun evaluate(received: Received, request: ReaderRequest, risk: RiskLevel): ReaderUi {
        val response = DeviceResponse.fromDataItem(Cbor.decode(received.response))
        // Issuer signature, digests, validity at this time and device authentication bound to this session.
        val integrity = try {
            response.verify(sessionTranscript = received.transcript, eReaderKey = AsymmetricKey.anonymous(received.eReaderKey))
            if (received.zkSpecs.isNotEmpty()) {
                require(response.status == DeviceResponse.STATUS_OK && response.documents.isEmpty() && response.zkDocuments.size == 1)
                val proof = response.zkDocuments.single()
                require(proof.documentData.docType == request.docType)
                require(proof.documentData.issuerSigned.keys == setOf(request.namespace))
                require(proof.documentData.issuerSigned.getValue(request.namespace).keys == setOf("age_over_18"))
                longfellow.verify(proof, received.zkSpecs, received.transcript)
            }
            null
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (received.zkSpecs.isNotEmpty()) tr(Res.string.reader_zk_failed) else integrityFailure(e)
        }
        if (integrity != null) {
            model.record(HistoryKind.VERIFIED, tr(Res.string.tw_holder), null, note = note(request, received.transport), failure = integrity)
            return ReaderUi.Result(request, risk, received.transport, emptyList(), integrity)
        }
        if (received.zkSpecs.isNotEmpty()) {
            val documents = response.zkDocuments.map { zkDocument(it) }
            documents.forEach { d ->
                model.record(HistoryKind.VERIFIED, tr(Res.string.reader_zk_age_proof), d.issuerTrust,
                    claims = d.claims.map { it.label }, note = note(request, received.transport) + tr(Res.string.reader_zk_note))
            }
            return ReaderUi.Result(request, risk, received.transport, emptyList(), null, documents)
        }
        if (response.status != DeviceResponse.STATUS_OK && response.documents.isEmpty()) {
            throw Unavailable(tr(Res.string.reader_error_status, response.status))
        }
        if (response.documents.isEmpty()) throw Unavailable(tr(Res.string.reader_no_matching, request.title))
        val documents = response.documents.map { document(it, request, risk) }
        documents.forEach { d ->
            model.record(
                HistoryKind.VERIFIED, tr(Res.string.reader_holder_of, d.title), d.issuerTrust,
                listOf(d.issuerTrust.anchorName ?: d.issuer),
                d.claims.map { it.label },
                note(request, received.transport) + tr(Res.string.sep_semicolon) + StatusTexts.summary(d.statusDecision),
            )
        }
        return ReaderUi.Result(request, risk, received.transport, documents, null)
    }

    private suspend fun zkDocument(proof: ZkDocument): ReadZkDocument {
        val data = proof.documentData
        val chain = data.msoX5chain?.certificates ?: emptyList()
        // The proof binds the docType, so a VICAL that authorises the issuer for other document types still limits it.
        val trust = model.trust.decide(TrustRole.ISSUER, chain, docType = data.docType)
        val value = data.issuerSigned.getValue(MDL_NS).getValue("age_over_18").asBoolean
        return ReadZkDocument(data.docType, trust, chain, data.timestamp,
            listOf(ReadClaim(model.claimLabel(listOf(MDL_NS, "age_over_18"), null, null), if (value) tr(Res.string.answer_yes) else tr(Res.string.answer_no))))
    }

    private suspend fun document(doc: MdocDocument, request: ReaderRequest, risk: RiskLevel): ReadDocument {
        val chain = doc.issuerCertChain.certificates
        // The docType limits an issuer CA that a VICAL authorises for some document types only.
        val anchored = model.trust.decide(TrustRole.ISSUER, chain, docType = doc.docType)
        // A Photo ID a holder wallet made from a passport is that wallet's statement (T3); its chip files are checked here.
        val photoId = doc.docType == TravelDocumentPhotoId.DOCTYPE
        val trust = if (photoId && anchored.environment == null) {
            TrustDecision(TrustTier.T3, TrustEnvironment.USER, official = false, anchorName = tr(Res.string.reader_holder_wallet), labels = setOf(TrustLabel.SELF_ISSUED))
        } else anchored
        val evidence = if (photoId) {
            val disclosed = doc.issuerNamespaces.data.mapValues { (_, items) -> items.mapValues { it.value.dataElementValue } }
            runCatching { TravelDocumentPhotoId.verify(disclosed, model.files.trustSource) }.getOrDefault(emptyList())
        } else emptyList()
        val mso = doc.mso
        val type = model.documentTypes.getDocumentTypeForMdoc(doc.docType)
        val claims = doc.issuerNamespaces.data.flatMap { (ns, items) ->
            items.map { (element, item) ->
                val attribute = type?.mdocDocumentType?.namespaces?.get(ns)?.dataElements?.get(element)?.attribute
                val label = model.claimLabel(listOf(ns, element), attribute?.displayName, null)
                val value = item.dataElementValue
                when {
                    ns == TravelDocumentPhotoId.DATAGROUPS_NAMESPACE ->
                        ReadClaim(label, tr(Res.string.reader_chip_file, runCatching { value.asBstr.size }.getOrDefault(0)))
                    else -> when (attribute?.type) {
                    DocumentAttributeType.Picture -> ReadClaim(label, "", runCatching { value.asBstr }.getOrNull())
                    DocumentAttributeType.Boolean -> ReadClaim(label, if (runCatching { value.asBoolean }.getOrDefault(false)) tr(Res.string.answer_yes) else tr(Res.string.answer_no))
                    else -> ReadClaim(label, MdocClaim(label, attribute, doc.docType, ns, element, value).render(TimeZone.currentSystemDefault()))
                    }
                }
            }
        }
        val withheld = doc.errors.flatMap { (ns, errors) -> errors.keys.map { model.claimLabel(listOf(ns, it), null, null) } }
        val status = mso.revocationStatus?.let { ref ->
            withTimeoutOrNull(STATUS_TIMEOUT) {
                runCatching { CredentialStatusChecker(model.http, model.trust, didTrust = model.didTrust).check(ref, chain, bypassCache = true) }.getOrNull()
            } ?: CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), tr(Res.string.tw_status_timeout))
        } ?: CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), "Credential carries no status reference", referenced = false)
        val issuer = chain.firstOrNull()?.let { c -> c.subject.components[OID.COMMON_NAME.oid]?.value ?: c.displaySubject() } ?: tr(Res.string.reader_unknown_issuer)
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
            evidence = evidence,
        )
    }

    private fun integrityFailure(e: Exception): String {
        val m = e.message.orEmpty()
        return when {
            "validUntil" in m || "validFrom" in m || "valid" in m && "period" in m -> tr(Res.string.reader_not_valid_now)
            "signature" in m.lowercase() -> tr(Res.string.reader_signature_failed)
            "digest" in m.lowercase() -> tr(Res.string.reader_digest_mismatch)
            else -> tr(Res.string.reader_verify_failed) + model.describe(e)
        }
    }

    private fun failure(e: Exception): String = when (e) {
        is Unavailable -> e.message.orEmpty()
        is TimeoutCancellationException -> tr(Res.string.reader_timeout)
        is NfcTagLostException -> tr(Res.string.reader_tap_lost)
        is MdocTransportClosedException -> tr(Res.string.reader_ended)
        is MdocTransportException -> tr(Res.string.reader_tap_or_link_lost)
        else -> tr(Res.string.reader_read_failed) + model.describe(e)
    }

    private fun note(request: ReaderRequest, via: String?) =
        tr(Res.string.reader_note_start) + (via?.let { tr(Res.string.reader_via, it) } ?: "") + tr(Res.string.reader_note_end, request.title)

    companion object {
        private val CONNECT_TIMEOUT = 1.minutes
        private val ANSWER_TIMEOUT = 3.minutes
        private val STATUS_TIMEOUT = 8.seconds

        fun documentTitle(docType: String, typeName: String?): String = when (docType) {
            MDL -> tr(Res.string.reader_mdl)
            PID -> tr(Res.string.reader_eu_pid)
            else -> typeName ?: docType
        }
    }
}

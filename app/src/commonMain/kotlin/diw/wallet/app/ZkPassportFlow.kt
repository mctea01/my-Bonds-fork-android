package diw.wallet.app

import diw.wallet.app.legal.Integration
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportAnswer
import diw.wallet.core.zkpassport.ZkPassportAnswerFailure
import diw.wallet.core.zkpassport.ZkPassportAnswerProgress
import diw.wallet.core.zkpassport.ZkPassportChip
import diw.wallet.core.zkpassport.ZkPassportCscaCheck
import diw.wallet.core.zkpassport.ZkPassportConfig
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportIncoming
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportResult
import diw.wallet.core.zkpassport.ZkPassportSession
import diw.wallet.core.zkpassport.ZkPassportState
import io.ktor.http.Url
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull

/**
 * The wallet as a zkPassport verifier (docs/design/zkpassport.md 5.2): a request QR for the holder's zkPassport app,
 * proofs received over zkPassport's bridge and verified on this device against the on-chain registries. Needs the
 * zkPassport statement; the bridge, the circuit CDN and the Ethereum node are the only parties contacted.
 */
class ZkPassportFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var session: ZkPassportSession? = null
    private var job: Job? = null
    private var answer: ZkPassportAnswer? = null

    /** The domain requests are made for: the user's setting, else [serverDomain]. */
    fun defaultDomain(): String = model.settings.zkPassportDomain.trim().ifEmpty { serverDomain() }

    /** The host of this wallet's own production server, what an empty domain setting falls back to; empty without one. */
    fun serverDomain(): String =
        model.settings.zkVerifierUrl.trim().takeIf { it.isNotEmpty() }?.let { runCatching { Url(it).host }.getOrNull() }.orEmpty()

    fun openSetup() {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.screen.value = Screen.IntegrationStatement(Integration.ZKPASSPORT)
            return
        }
        stop()
        val note = if (model.platform.zk?.zkPassport == null) tr(Res.string.zkp_no_engine) else null
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.ZkPassportSetup(defaultDomain(), model.settings.testEnvironment, note)
    }

    fun start(request: ZkPassportRequest) {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.message.value = model.legal.disabledMessage(Integration.ZKPASSPORT)
            return
        }
        val engine = model.platform.zk?.zkPassport ?: run {
            model.message.value = tr(Res.string.zkp_no_engine)
            return
        }
        stop()
        val settings = model.settings
        val config = ZkPassportConfig(
            mainnetRpc = settings.zkPassportMainnetRpc.trim().ifEmpty { null },
            sepoliaRpc = settings.zkPassportSepoliaRpc.trim().ifEmpty { null },
            verifierApi = settings.zkPassportVerifierApi,
        )
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.ZkPassportWaiting(request, null, ZkPassportState.Connecting)
        model.platform.keepScreenOn(true)
        job = model.scope.launch {
            val opened = engine.open(request, config.copy(cscaAnchors = cscaAnchors(), oprfKeyHash = oprfKeyHash()), model.scope)
            session = opened
            try {
                var url: String? = null
                opened.state.takeWhile { s ->
                    when (s) {
                        is ZkPassportState.Waiting -> url = s.url
                        is ZkPassportState.Scanned -> url = s.url
                        else -> {}
                    }
                    when (s) {
                        is ZkPassportState.Done -> show(request, s.result, null)
                        ZkPassportState.Rejected -> show(request, null, tr(Res.string.zkp_rejected))
                        is ZkPassportState.Failed -> show(request, null, failure(s.code, s.detail))
                        else -> ui.value = OfflineUi.ZkPassportWaiting(request, url, s)
                    }
                    s !is ZkPassportState.Done && s != ZkPassportState.Rejected && s !is ZkPassportState.Failed
                }.collect {}
            } finally {
                opened.close()
                model.platform.keepScreenOn(false)
            }
        }
    }

    /** This wallet's CSCA anchors (production and the user's own), as DER. */
    private suspend fun cscaAnchors(): List<ByteArray> =
        listOf(TrustEnvironment.PRODUCTION, TrustEnvironment.USER).flatMap { env ->
            runCatching { model.trust.travelDocumentAnchors(env) }.getOrDefault(emptyList()).map { it.encoded.toByteArray() }
        }.distinctBy { it.toList() }

    /**
     * The OPRF key hash this wallet's server publishes (5.5), read fresh at each request; salted identifiers are
     * accepted only under it. Null without a server or when it offers no OPRF, so salted identifiers are refused.
     */
    private suspend fun oprfKeyHash(): String? =
        model.server.base()?.let { runCatching { model.server.oprfKeyHash(it) }.getOrNull() }

    /**
     * Answers a zkPassport request link with a passport stored in this wallet (Z3, docs/design/zkpassport.md 5.3):
     * the bridge is opened first, so the consent screen can show the origin the bridge reports for the requester.
     * Covered by version 3 of the zkPassport statement.
     */
    fun answer(incoming: ZkPassportIncoming) {
        if (!model.legal.enabled(Integration.ZKPASSPORT)) {
            model.screen.value = Screen.IntegrationStatement(Integration.ZKPASSPORT, pendingUri = incoming.link)
            return
        }
        stop()
        model.screen.value = Screen.Offline
        val holder = model.platform.zk?.zkPassportHolder ?: run {
            ui.value = OfflineUi.ZkPassportAnswerDone(incoming, false, tr(Res.string.zkp_answer_no_engine))
            return
        }
        ui.value = OfflineUi.ZkPassportAnswerConnecting(incoming)
        job = model.scope.launch {
            val opened = try {
                holder.connect(incoming, rpc(incoming))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.ZkPassportAnswerDone(incoming, false, answerFailure((e as? ZkPassportAnswerFailure)?.code ?: "connection"))
                return@launch
            }
            answer = opened
            ui.value = OfflineUi.ZkPassportAnswerConsent(incoming, opened.origin, opened.originMatches, passports(), unsupported(incoming))
        }
    }

    /** Proves the request from the stored passport [file] and sends the proofs. */
    fun accept(file: StoredFile) {
        val a = answer ?: return
        val incoming = (ui.value as? OfflineUi.ZkPassportAnswerConsent)?.incoming ?: return
        ui.value = OfflineUi.ZkPassportAnswerProving(incoming, null)
        model.platform.keepScreenOn(true)
        job = model.scope.launch {
            try {
                val chip = chip(file) ?: throw ZkPassportAnswerFailure("passport")
                a.answer(chip) { p -> ui.value = OfflineUi.ZkPassportAnswerProving(incoming, p) }
                answered(incoming, a.origin, file, null)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                answered(incoming, a.origin, file, answerFailure((e as? ZkPassportAnswerFailure)?.code ?: "other"))
            } finally {
                a.close()
                if (answer === a) answer = null
                model.platform.keepScreenOn(false)
            }
        }
    }

    /** Tells the requester the holder declined. */
    fun reject() {
        val a = answer ?: return
        val incoming = (ui.value as? OfflineUi.ZkPassportAnswerConsent)?.incoming ?: return
        answer = null
        job = model.scope.launch {
            try {
                runCatching { a.reject() }
            } finally {
                a.close()
            }
            ui.value = OfflineUi.ZkPassportAnswerDone(incoming, false, null)
            model.record(
                HistoryKind.DECLINED, incoming.domain, null, emptyList(), asks(incoming.query),
                tr(Res.string.zkp_answer_history_note, a.origin),
            )
        }
    }

    private fun answered(incoming: ZkPassportIncoming, origin: String, file: StoredFile, error: String?) {
        ui.value = OfflineUi.ZkPassportAnswerDone(incoming, error == null, error)
        model.record(
            HistoryKind.PRESENTED, incoming.domain, null, listOf(file.name), asks(incoming.query),
            tr(Res.string.zkp_answer_history_note, origin) + (if (incoming.devMode) tr(Res.string.zkp_answer_history_test) else ""),
            error,
        )
    }

    /** The Ethereum node for the registries of the request's chain; null uses the built-in one. */
    private fun rpc(incoming: ZkPassportIncoming): String? =
        (if (incoming.devMode) model.settings.zkPassportSepoliaRpc else model.settings.zkPassportMainnetRpc).trim().ifEmpty { null }

    /** The electronic passports stored in this wallet, newest first. */
    private fun passports(): List<StoredFile> =
        model.files.files.value.filter { it.report?.format == DocumentFormat.EMRTD }.sortedByDescending { it.addedAt }

    /** The chip files of the stored passport [file]; null when its read lacks the SOD or DG1. */
    private suspend fun chip(file: StoredFile): ZkPassportChip? = withContext(Dispatchers.Default) {
        val dump = MrtdDump.decode(model.files.data(file.id)) ?: return@withContext null
        val sod = dump.file(LdsFile.SOD) ?: return@withContext null
        val dg1 = dump.file(LdsFile.DG1) ?: return@withContext null
        ZkPassportChip(sod, dg1, dump.file(LdsFile.DG2))
    }

    fun stop() {
        answer?.close()
        answer = null
        session?.close()
        session = null
        job?.cancel()
        job = null
    }

    private fun show(request: ZkPassportRequest, result: ZkPassportResult?, error: String?) {
        session = null
        ui.value = OfflineUi.ZkPassportVerified(request, result, error)
        val passed = result?.verified == true
        val failure = when {
            passed -> null
            error != null -> error
            result != null -> problems(result.errors).joinToString(tr(Res.string.sep_list))
            else -> tr(Res.string.zkp_no_result)
        }
        model.record(
            HistoryKind.VERIFIED, "zkPassport", null,
            listOf(tr(Res.string.zkp_document)),
            result?.let { claims(it) }.orEmpty(),
            tr(Res.string.zkp_history_note, ZkPassport.normalizeDomain(request.domain), request.purpose) +
                (if (request.devMode) tr(Res.string.zkp_history_test) else "") +
                (if (result?.viaVerifierApi == true) tr(Res.string.zkp_history_api) else ""),
            failure,
        )
    }

    companion object {
        /** Fields the setup screen offers; the document type and issuing country are always disclosed. */
        val OPTIONAL_FIELDS = listOf(
            ZkPassportField.FULLNAME, ZkPassportField.NATIONALITY, ZkPassportField.BIRTHDATE,
            ZkPassportField.EXPIRY_DATE, ZkPassportField.DOCUMENT_NUMBER, ZkPassportField.GENDER,
        )

        fun fieldTitle(field: ZkPassportField): String = when (field) {
            ZkPassportField.DOCUMENT_TYPE -> tr(Res.string.zkp_field_document_type)
            ZkPassportField.ISSUING_COUNTRY -> tr(Res.string.zkp_field_issuing_country)
            ZkPassportField.FULLNAME -> tr(Res.string.zkp_field_fullname)
            ZkPassportField.NATIONALITY -> tr(Res.string.zkp_field_nationality)
            ZkPassportField.BIRTHDATE -> tr(Res.string.zkp_field_birthdate)
            ZkPassportField.EXPIRY_DATE -> tr(Res.string.zkp_field_expiry_date)
            ZkPassportField.DOCUMENT_NUMBER -> tr(Res.string.zkp_field_document_number)
            ZkPassportField.GENDER -> tr(Res.string.zkp_field_gender)
        }

        /** ISO 3166-1 alpha-3 codes from free text (commas, spaces or semicolons), or null when one is not a code. */
        fun countries(text: String): List<String>? {
            val codes = text.split(',', ' ', ';', '\n', '、', '，').map { it.trim().uppercase() }.filter { it.isNotEmpty() }
            if (codes.size > MAX_COUNTRIES || codes.any { !Regex("[A-Z]{3}").matches(it) }) return null
            return codes.distinct()
        }

        /** Why [domain] cannot be used, or null. */
        fun domainProblem(domain: String): String? {
            val d = ZkPassport.normalizeDomain(domain)
            return when {
                d.isEmpty() -> tr(Res.string.zkp_domain_missing)
                d.length > 253 || !Regex("[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+").matches(d) -> tr(Res.string.zkp_domain_invalid)
                else -> null
            }
        }

        fun failure(code: String, detail: String?): String = when (code) {
            "unsupported_document" -> tr(Res.string.zkp_fail_unsupported)
            "proof_failed" -> tr(Res.string.zkp_fail_proof)
            "holder_error" -> tr(Res.string.zkp_fail_holder, detail.orEmpty())
            "connection" -> tr(Res.string.zkp_fail_connection)
            else -> tr(Res.string.zkp_fail_other, code)
        }

        /** The checker's error codes in words, each kind once. */
        fun problems(errors: List<String>): List<String> = errors.map { e ->
            when {
                e == "native_unavailable" -> tr(Res.string.zkp_err_native)
                e == "registry_unreachable" -> tr(Res.string.zkp_err_registry)
                e == "manifest_unavailable" || e == "circuit_unavailable" -> tr(Res.string.zkp_err_cdn)
                e.startsWith("certificate_root") -> tr(Res.string.zkp_err_certificate_root)
                e.startsWith("circuit_root") || e.startsWith("manifest") || e.startsWith("vkey:") -> tr(Res.string.zkp_err_circuit_root)
                e.startsWith("proof:") -> tr(Res.string.zkp_err_proof)
                e.startsWith("commitment:") -> tr(Res.string.zkp_err_commitment)
                e.startsWith("scope:") -> tr(Res.string.zkp_err_scope)
                e.startsWith("date_expired") -> tr(Res.string.zkp_err_date_expired)
                e.startsWith("date_future") -> tr(Res.string.zkp_err_date_future)
                e == "mock" -> tr(Res.string.zkp_err_mock)
                e == "oprf_key" -> tr(Res.string.zkp_err_oprf_key)
                e == "nullifier_mismatch" -> tr(Res.string.zkp_err_nullifier)
                e.startsWith("query") || e.startsWith("missing:") -> tr(Res.string.zkp_err_query)
                else -> tr(Res.string.zkp_err_bundle)
            }
        }.distinct()

        /** What the proofs establish, one line each, as committed to by the proofs. */
        fun claims(r: ZkPassportResult): List<String> = buildList {
            r.disclosed?.let { d ->
                d.documentCode?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.DOCUMENT_TYPE), it)) }
                d.issuingCountry?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.ISSUING_COUNTRY), it)) }
                d.nationality?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.NATIONALITY), it)) }
                listOfNotNull(d.lastName, d.givenNames).filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }?.let {
                    add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.FULLNAME), it.joinToString(", ")))
                }
                d.birthdate?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.BIRTHDATE), it)) }
                d.expiryDate?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.EXPIRY_DATE), it)) }
                d.documentNumber?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.DOCUMENT_NUMBER), it)) }
                d.gender?.let { add(tr(Res.string.zkp_line, fieldTitle(ZkPassportField.GENDER), it)) }
            }
            val min = r.minAge
            val max = r.maxAge?.takeIf { it in 1..149 }
            when {
                min != null && min > 0 && max != null -> add(tr(Res.string.zkp_age_between, min, max))
                min != null && min > 0 -> add(tr(Res.string.zkp_age_at_least, min))
                max != null -> add(tr(Res.string.zkp_age_below, max))
            }
            val sep = tr(Res.string.sep_list)
            if (r.nationalityIn.isNotEmpty()) add(tr(Res.string.zkp_nationality_in, r.nationalityIn.joinToString(sep)))
            if (r.nationalityOut.isNotEmpty()) add(tr(Res.string.zkp_nationality_out, r.nationalityOut.joinToString(sep)))
            if (r.issuingCountryIn.isNotEmpty()) add(tr(Res.string.zkp_issuing_in, r.issuingCountryIn.joinToString(sep)))
            if (r.issuingCountryOut.isNotEmpty()) add(tr(Res.string.zkp_issuing_out, r.issuingCountryOut.joinToString(sep)))
            r.boundData?.let { add(tr(Res.string.zkp_bound, it)) }
        }

        /** The trust line of a passed check (docs/design/zkpassport.md 4.3): T2 when every key is an anchor. */
        fun trust(check: ZkPassportCscaCheck?): String {
            val sep = tr(Res.string.sep_list)
            return when {
                check == null -> tr(Res.string.zkp_trust_registry)
                check.allAnchored -> tr(Res.string.zkp_trust_anchored, check.countries.joinToString(sep))
                check.error != null -> tr(Res.string.zkp_trust_unchecked, if (check.error == "certificates_root") tr(Res.string.zkp_err_certificates_root) else tr(Res.string.zkp_err_certificates))
                else -> tr(Res.string.zkp_trust_partial, check.countries.joinToString(sep), check.inPackage, check.anchored)
            }
        }

        /** Why this wallet cannot answer [incoming], or null: FaceMatch and modes other than fast are not offered. */
        fun unsupported(incoming: ZkPassportIncoming): String? = when {
            "facematch" in incoming.query -> tr(Res.string.zkp_answer_unsupported_facematch)
            !incoming.fastMode -> tr(Res.string.zkp_answer_unsupported_mode, incoming.mode.ifEmpty { "-" })
            else -> null
        }

        /** What a request's query asks for, one line each, in the order of the query. */
        fun asks(query: JsonObject): List<String> = buildList {
            for ((key, value) in query) {
                val o = value as? JsonObject
                val field = ZkPassportField.entries.firstOrNull { it.key == key }
                when {
                    key == "age" && o != null -> {
                        val gte = (o["gte"] as? JsonPrimitive)?.intOrNull
                        val lt = (o["lt"] as? JsonPrimitive)?.intOrNull
                        when {
                            gte != null && o.size == 1 -> add(tr(Res.string.zkp_age_at_least, gte))
                            lt != null && o.size == 1 -> add(tr(Res.string.zkp_age_below, lt))
                            else -> add(tr(Res.string.zkp_answer_ask_condition, tr(Res.string.zkp_answer_age)))
                        }
                    }
                    key == "bind" && o != null -> {
                        val data = (o["custom_data"] as? JsonPrimitive)?.contentOrNull
                        if (data != null) add(tr(Res.string.zkp_bound, data))
                        if (o.keys.any { it != "custom_data" }) add(tr(Res.string.zkp_answer_ask_other, key))
                    }
                    key == "sanctions" -> add(tr(Res.string.zkp_answer_ask_sanctions))
                    key == "facematch" -> add(tr(Res.string.zkp_answer_ask_facematch))
                    o != null -> {
                        val title = field?.let(::fieldTitle) ?: key
                        if ((o["disclose"] as? JsonPrimitive)?.contentOrNull == "true") add(tr(Res.string.zkp_answer_ask_disclose, title))
                        if (o.keys.any { it != "disclose" }) add(tr(Res.string.zkp_answer_ask_condition, title))
                    }
                    else -> add(tr(Res.string.zkp_answer_ask_other, key))
                }
            }
        }

        /** An answer's failure code in words. */
        fun answerFailure(code: String): String = when {
            code == "bridge_origin" -> tr(Res.string.zkp_answer_err_origin)
            code == "connection" -> tr(Res.string.zkp_fail_connection)
            code == "passport" -> tr(Res.string.zkp_answer_err_passport)
            code == "native_unavailable" -> tr(Res.string.zkp_answer_no_engine)
            code == "crs_missing" -> tr(Res.string.zkp_answer_err_crs)
            code == "inputs" -> tr(Res.string.zkp_answer_err_inputs)
            code.startsWith("registry") -> tr(Res.string.zkp_err_registry)
            code == "manifest_unavailable" || code == "circuit_unavailable" -> tr(Res.string.zkp_err_cdn)
            code == "certificates_unavailable" -> tr(Res.string.zkp_answer_err_certificates)
            code.endsWith("_root") || code.startsWith("vkey:") -> tr(Res.string.zkp_answer_err_circuit)
            else -> tr(Res.string.zkp_answer_err_other, code)
        }

        const val MAX_COUNTRIES = 200
    }
}

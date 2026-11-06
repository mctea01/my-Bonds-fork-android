package diw.wallet.app

import diw.wallet.app.legal.Integration
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportConfig
import diw.wallet.core.zkpassport.ZkPassportField
import diw.wallet.core.zkpassport.ZkPassportRequest
import diw.wallet.core.zkpassport.ZkPassportResult
import diw.wallet.core.zkpassport.ZkPassportSession
import diw.wallet.core.zkpassport.ZkPassportState
import io.ktor.http.Url
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.launch

/**
 * The wallet as a zkPassport verifier (docs/design/zkpassport.md 5.2): a request QR for the holder's zkPassport app,
 * proofs received over zkPassport's bridge and verified on this device against the on-chain registries. Needs the
 * zkPassport statement; the bridge, the circuit CDN and the Ethereum node are the only parties contacted.
 */
class ZkPassportFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var session: ZkPassportSession? = null
    private var job: Job? = null

    /** The domain requests are made for: the user's setting, else the host of this wallet's own server. */
    fun defaultDomain(): String = model.settings.zkPassportDomain.trim().ifEmpty {
        model.settings.zkVerifierUrl.trim().takeIf { it.isNotEmpty() }?.let { runCatching { Url(it).host }.getOrNull() }.orEmpty()
    }

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
        if (ZkPassport.normalizeDomain(request.domain) != settings.zkPassportDomain.trim()) {
            model.updateSettings { it.copy(zkPassportDomain = ZkPassport.normalizeDomain(request.domain)) }
        }
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.ZkPassportWaiting(request, null, ZkPassportState.Connecting)
        val opened = engine.open(request, config, model.scope)
        session = opened
        model.platform.keepScreenOn(true)
        job = model.scope.launch {
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
                model.platform.keepScreenOn(false)
            }
        }
    }

    fun stop() {
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
                e == "oprf_key" || e == "nullifier_mismatch" -> tr(Res.string.zkp_err_nullifier)
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

        const val MAX_COUNTRIES = 200
    }
}

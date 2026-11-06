package diw.wallet.core.oid4vp

import diw.wallet.core.i18n.ct
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.documenttype.TransactionType
import org.multipaz.documenttype.knowntypes.PaymentTransaction
import org.multipaz.util.fromBase64Url
import kotlin.math.abs
import kotlin.math.roundToLong

/**
 * The OpenID4VP transaction_data types this wallet answers: CSC remote signing approval, the EUDI TS12 payment
 * (urn:eudi:sca:payment:1, Multipaz [PaymentTransaction]) and the EUDI reference / Animo payments playground payment
 * variants ([EudiPaymentTransaction]). Multipaz applies a TS12 payment only to its own payment credential
 * (org.multipaz.payment.sca.1); an SD-JWT VC binds any accepted entry through transaction_data_hashes, so the
 * variant identifiers only need registering here for the request to be accepted instead of rejected as unsupported.
 */
object WalletTransactionTypes {
    val all: List<TransactionType<*>> =
        QesApprovalTransaction.types + PaymentTransaction + EudiPaymentTransaction.types

    /** What the holder approves for one encoded transaction_data entry, one line per fact. */
    fun describe(encoded: String): List<String> {
        QesApprovalTransaction.describe(encoded)?.let { return listOf(it) }
        val obj = runCatching {
            DiwJson.parseToJsonElement(encoded.fromBase64Url().decodeToString()) as? JsonObject
        }.getOrNull()
        val type = obj?.str("type")
        if (type == PaymentTransaction.identifier) {
            runCatching { describePayment(PaymentTransaction.parseJson(encoded.encodeToByteString()).payload) }.getOrNull()?.let { return it }
            return listOf(ct("core_pay_bad_data"))
        }
        if (obj != null && type in EudiPaymentTransaction.IDENTIFIERS) {
            return describeEudiPayment(obj) ?: listOf(ct("core_pay_missing"))
        }
        return listOf(ct("core_tx_data_start") + (type ?: ct("core_tx_unknown_type")) + ct("core_paren_close"))
    }

    /**
     * Describes the EUDI reference / Animo payment payload. Field names are read as both the TS12 shape (payee object,
     * amount, currency) and simpler shapes (payee string, currency_amount object). Returns null when neither a payee
     * nor an amount can be read, so a payment the holder could not be shown is not treated as supported: AGENTS.md
     * requires the payee and amount on the consent screen, and [EudiPaymentTransaction] rejects such an entry.
     */
    private fun describeEudiPayment(o: JsonObject): List<String>? {
        // Some issuers nest the payment fields under "payload" (as TS12 does); others put them at the top level.
        val p = o.obj("payload") ?: o
        val payee = p.obj("payee")?.str("name") ?: p.str("payee")
        val currencyAmount = p.obj("currency_amount")
        val currency = p.str("currency") ?: currencyAmount?.str("currency")
        val amount = (p["amount"] as? JsonPrimitive)?.content ?: currencyAmount?.str("value")
        if (payee == null || amount == null) return null
        val sum = if (currency != null) "$amount $currency" else amount
        return buildList {
            add(ct("core_pay_to", payee, sum))
            p.obj("payee")?.str("website")?.let { add(ct("core_pay_website", it)) }
            (p.str("transaction_id") ?: p.str("transactionId"))?.let { add(ct("core_pay_tx_id", it)) }
            (p.str("date_time") ?: p.str("dateTime"))?.let { add(ct("core_pay_created", it)) }
            (p.str("execution_date") ?: p.str("executionDate"))?.let { add(ct("core_pay_execution", it)) }
            if (p.obj("recurrence") != null || p.obj("recurring_schedule") != null) add(ct("core_pay_recurring_note"))
        }
    }

    /** Whether a payment payload carries a payee and an amount the holder can be shown (any supported field shape). */
    internal fun eudiPaymentShowable(o: JsonObject): Boolean {
        val p = o.obj("payload") ?: o
        val payee = p.obj("payee")?.str("name") ?: p.str("payee")
        val amount = (p["amount"] as? JsonPrimitive)?.content ?: p.obj("currency_amount")?.str("value")
        return payee != null && amount != null
    }

    private fun describePayment(p: PaymentTransaction.Payload): List<String> = buildList {
        val amount = money(p.amount, p.currency)
        add(ct("core_pay_to", p.payee.name, amount) + if (p.amountEstimated == true) ct("core_pay_estimated") else "")
        add(ct("core_pay_payee", p.payee.name, p.payee.id) + (p.payee.website?.let { ct("core_comma_value", it) } ?: ""))
        add(ct("core_pay_tx_id", p.transactionId))
        p.dateTime?.let { add(ct("core_pay_created", it)) }
        p.executionDate?.let { add(ct("core_pay_execution", it)) }
        if (p.amountEarmarked == true) add(ct("core_pay_earmarked"))
        if (p.sctInst == true) add(ct("core_pay_sct_inst"))
        p.pisp?.let { add(ct("core_pay_pisp", it.brandName, it.legalName, it.domainName)) }
        p.recurrence?.let { r ->
            add(ct("core_pay_recurring") + frequency(r.frequency) +
                (r.startDate?.let { ct("core_pay_from", it) } ?: "") + (r.endDate?.let { ct("core_pay_until", it) } ?: "") + (r.number?.let { ct("core_pay_times", it) } ?: ""))
        }
        p.mitOptions?.let { m ->
            val parts = buildList {
                if (m.amountVariable == true) add(ct("core_pay_variable"))
                m.minAmount?.let { add(ct("core_pay_min") + money(it, p.currency)) }
                m.maxAmount?.let { add(ct("core_pay_max") + money(it, p.currency)) }
                m.totalAmount?.let { add(ct("core_pay_total") + money(it, p.currency)) }
                m.initialAmount?.let { add(ct("core_pay_initial") + money(it, p.currency) + (m.initialAmountNumber?.let { n -> ct("core_pay_installments", n) } ?: "")) }
                m.apr?.let { add(ct("core_pay_apr", it)) }
            }
            add(ct("core_pay_mit") + if (parts.isEmpty()) "" else ct("core_colon") + parts.joinToString(ct("core_sep_comma")))
        }
        if (p.tipRequested == true) add(ct("core_pay_tip"))
    }

    private fun money(amount: Double, currency: String): String {
        val cents = (abs(amount) * 100).roundToLong()
        val whole = (cents / 100).toString().reversed().chunked(3).joinToString(",").reversed()
        val frac = cents % 100
        val sign = if (amount < 0) "-" else ""
        return sign + whole + (if (frac == 0L) "" else "." + frac.toString().padStart(2, '0')) + " " + currency
    }

    private fun frequency(f: PaymentTransaction.Frequency): String = when (f) {
        PaymentTransaction.Frequency.INDA -> ct("core_freq_inda")
        PaymentTransaction.Frequency.DAIL -> ct("core_freq_dail")
        PaymentTransaction.Frequency.WEEK -> ct("core_freq_week")
        PaymentTransaction.Frequency.TOWK -> ct("core_freq_towk")
        PaymentTransaction.Frequency.TWMN -> ct("core_freq_twmn")
        PaymentTransaction.Frequency.MNTH -> ct("core_freq_mnth")
        PaymentTransaction.Frequency.TOMN -> ct("core_freq_tomn")
        PaymentTransaction.Frequency.QUTR -> ct("core_freq_qutr")
        PaymentTransaction.Frequency.FOMN -> ct("core_freq_fomn")
        PaymentTransaction.Frequency.SEMI -> ct("core_freq_semi")
        PaymentTransaction.Frequency.YEAR -> ct("core_freq_year")
        PaymentTransaction.Frequency.TYEA -> ct("core_freq_tyea")
    }
}

/**
 * The EUDI reference implementation / Animo eudi-payments playground payment-confirmation transaction_data types.
 * The standard TS12 identifier urn:eudi:sca:payment:1 is covered by Multipaz [PaymentTransaction]; these vendor
 * variants are parsed leniently as a JSON object so an SD-JWT VC request carrying them is accepted and its
 * transaction_data_hashes bound, instead of being rejected with invalid_transaction_data.
 */
class EudiPaymentTransaction(identifier: String) : TransactionType<JsonObject>(
    displayName = ct("core_pay_authorization"),
    identifier = identifier,
) {
    override fun parseOpenId4VpRequest(jsonString: String): JsonObject {
        val o = DiwJson.parseToJsonElement(jsonString) as? JsonObject
            ?: throw IllegalArgumentException("transaction_data is not an object")
        // A payment the holder cannot be shown (no readable payee and amount) is refused rather than bound blindly
        // into the presentation; the consent screen must show who is paid and how much.
        if (!WalletTransactionTypes.eudiPaymentShowable(o)) {
            throw IllegalArgumentException("payment transaction_data must carry a payee and an amount")
        }
        return o
    }

    companion object {
        val IDENTIFIERS: List<String> = listOf(
            "urn:eudi:sca:eu.europa.ec:payment:single:1",
        )
        val types: List<EudiPaymentTransaction> = IDENTIFIERS.map { EudiPaymentTransaction(it) }
    }
}

package diw.wallet.core.oid4vp

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
            return listOf("付款授權：交易資料格式不正確")
        }
        if (obj != null && type in EudiPaymentTransaction.IDENTIFIERS) {
            return describeEudiPayment(obj)
        }
        return listOf("交易資料（" + (type ?: "未知類型") + "）")
    }

    /**
     * Describes the EUDI reference / Animo payment payload leniently: field names are read as both the TS12 shape
     * (payee object, amount, currency) and simpler shapes (payee string, currency_amount object), so a vendor
     * variant still yields a readable consent line rather than an opaque type name.
     */
    private fun describeEudiPayment(o: JsonObject): List<String> = buildList {
        val payee = o.obj("payee")?.str("name") ?: o.str("payee")
        val currencyAmount = o.obj("currency_amount")
        val currency = o.str("currency") ?: currencyAmount?.str("currency")
        val amount = (o["amount"] as? JsonPrimitive)?.content ?: currencyAmount?.str("value")
        val sum = when {
            amount != null && currency != null -> "$amount $currency"
            amount != null -> amount
            else -> null
        }
        add(
            buildString {
                append("付款授權")
                when {
                    payee != null && sum != null -> append("：向 $payee 支付 $sum")
                    payee != null -> append("：向 $payee 付款")
                    sum != null -> append("：支付 $sum")
                }
            }
        )
        o.obj("payee")?.str("website")?.let { add("收款方網站：$it") }
        (o.str("transaction_id") ?: o.str("transactionId"))?.let { add("交易編號：$it") }
        (o.str("date_time") ?: o.str("dateTime"))?.let { add("建立時間：$it") }
        (o.str("execution_date") ?: o.str("executionDate"))?.let { add("預定執行日：$it") }
        if (o.obj("recurrence") != null || o.obj("recurring_schedule") != null) add("此為定期付款授權")
    }

    private fun describePayment(p: PaymentTransaction.Payload): List<String> = buildList {
        val amount = money(p.amount, p.currency)
        add("付款授權：向 ${p.payee.name} 支付 $amount" + if (p.amountEstimated == true) "（預估金額）" else "")
        add("收款方：${p.payee.name}（代碼 ${p.payee.id}）" + (p.payee.website?.let { "，$it" } ?: ""))
        add("交易編號：${p.transactionId}")
        p.dateTime?.let { add("建立時間：$it") }
        p.executionDate?.let { add("預定執行日：$it") }
        if (p.amountEarmarked == true) add("款項會先行圈存")
        if (p.sctInst == true) add("以 SEPA 即時轉帳執行")
        p.pisp?.let { add("付款發起服務：${it.brandName}（${it.legalName}，${it.domainName}）") }
        p.recurrence?.let { r ->
            add("定期付款：" + frequency(r.frequency) +
                (r.startDate?.let { "，自 $it" } ?: "") + (r.endDate?.let { "，至 $it" } ?: "") + (r.number?.let { "，共 $it 次" } ?: ""))
        }
        p.mitOptions?.let { m ->
            val parts = buildList {
                if (m.amountVariable == true) add("金額依實際用量")
                m.minAmount?.let { add("每次最低 " + money(it, p.currency)) }
                m.maxAmount?.let { add("每次最高 " + money(it, p.currency)) }
                m.totalAmount?.let { add("總額上限 " + money(it, p.currency)) }
                m.initialAmount?.let { add("首期 " + money(it, p.currency) + (m.initialAmountNumber?.let { n -> " 共 $n 期" } ?: "")) }
                m.apr?.let { add("年利率 $it%") }
            }
            add("商家發起扣款" + if (parts.isEmpty()) "" else "：" + parts.joinToString("，"))
        }
        if (p.tipRequested == true) add("收款方提供小費選項；本錢包不另加小費")
    }

    private fun money(amount: Double, currency: String): String {
        val cents = (abs(amount) * 100).roundToLong()
        val whole = (cents / 100).toString().reversed().chunked(3).joinToString(",").reversed()
        val frac = cents % 100
        val sign = if (amount < 0) "-" else ""
        return sign + whole + (if (frac == 0L) "" else "." + frac.toString().padStart(2, '0')) + " " + currency
    }

    private fun frequency(f: PaymentTransaction.Frequency): String = when (f) {
        PaymentTransaction.Frequency.INDA -> "每日多次"
        PaymentTransaction.Frequency.DAIL -> "每日"
        PaymentTransaction.Frequency.WEEK -> "每週"
        PaymentTransaction.Frequency.TOWK -> "每兩週"
        PaymentTransaction.Frequency.TWMN -> "每月兩次"
        PaymentTransaction.Frequency.MNTH -> "每月"
        PaymentTransaction.Frequency.TOMN -> "每兩個月"
        PaymentTransaction.Frequency.QUTR -> "每季"
        PaymentTransaction.Frequency.FOMN -> "每四個月"
        PaymentTransaction.Frequency.SEMI -> "每半年"
        PaymentTransaction.Frequency.YEAR -> "每年"
        PaymentTransaction.Frequency.TYEA -> "每兩年"
    }
}

/**
 * The EUDI reference implementation / Animo eudi-payments playground payment-confirmation transaction_data types.
 * The standard TS12 identifier urn:eudi:sca:payment:1 is covered by Multipaz [PaymentTransaction]; these vendor
 * variants are parsed leniently as a JSON object so an SD-JWT VC request carrying them is accepted and its
 * transaction_data_hashes bound, instead of being rejected with invalid_transaction_data.
 */
class EudiPaymentTransaction(identifier: String) : TransactionType<JsonObject>(
    displayName = "付款授權",
    identifier = identifier,
) {
    override fun parseOpenId4VpRequest(jsonString: String): JsonObject =
        DiwJson.parseToJsonElement(jsonString) as? JsonObject
            ?: throw IllegalArgumentException("transaction_data is not an object")

    companion object {
        val IDENTIFIERS: List<String> = listOf(
            "urn:eudi:sca:eu.europa.ec:payment:single:1",
        )
        val types: List<EudiPaymentTransaction> = IDENTIFIERS.map { EudiPaymentTransaction(it) }
    }
}

package diw.wallet.core.oid4vp

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.str
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonObject
import org.multipaz.documenttype.TransactionType
import org.multipaz.documenttype.knowntypes.PaymentTransaction
import org.multipaz.util.fromBase64Url
import kotlin.math.abs
import kotlin.math.roundToLong

/**
 * The OpenID4VP transaction_data types this wallet answers: CSC remote signing approval and the EUDI TS12 payment
 * (urn:eudi:sca:payment:1, Multipaz [PaymentTransaction]). Multipaz applies a payment only to its own payment
 * credential (org.multipaz.payment.sca.1); other entries make the request fail as unsupported transaction data.
 */
object WalletTransactionTypes {
    val all: List<TransactionType<*>> = QesApprovalTransaction.types + PaymentTransaction

    /** What the holder approves for one encoded transaction_data entry, one line per fact. */
    fun describe(encoded: String): List<String> {
        QesApprovalTransaction.describe(encoded)?.let { return listOf(it) }
        val type = runCatching {
            (DiwJson.parseToJsonElement(encoded.fromBase64Url().decodeToString()) as JsonObject).str("type")
        }.getOrNull()
        if (type == PaymentTransaction.identifier) {
            runCatching { describePayment(PaymentTransaction.parseJson(encoded.encodeToByteString()).payload) }.getOrNull()?.let { return it }
            return listOf("付款授權：交易資料格式不正確")
        }
        return listOf("交易資料（" + (type ?: "未知類型") + "）")
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

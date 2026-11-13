package diw.wallet.core.document.derived

import diw.wallet.core.profile.bonds.MyDataText
import kotlinx.datetime.LocalDate

/**
 * A mainland China electronic invoice (数电发票 "电子发票（普通发票）" or "（增值税专用发票）", and the earlier
 * 增值税电子普通发票): read from the custom tags of an OFD invoice (the eInvoice tag file names the page objects that
 * hold each value) when it has them, else from the text layer of the OFD or PDF. Buyer and seller sit side by side
 * or one above the other; either way the buyer comes first.
 */
data class ChinaInvoice(
    val kind: String,
    val number: String?,
    val code: String?,
    val issueDate: LocalDate?,
    val buyerName: String?,
    val buyerTaxId: String?,
    val sellerName: String?,
    val sellerTaxId: String?,
    val amount: String?,
    val tax: String?,
    val total: String?,
    val totalInWords: String?,
    val checkCode: String?,
    val issuedBy: String?,
    val items: List<String>,
) : ParsedCertificate {

    override fun claims(): List<DerivedClaim> = buildList {
        add(DerivedClaim("invoiceType", kind, "發票種類"))
        number?.let { add(DerivedClaim("invoiceNumber", it, "發票號碼")) }
        code?.let { add(DerivedClaim("invoiceCode", it, "發票代碼")) }
        issueDate?.let { add(DerivedClaim("issueDate", it.toString(), "開票日期")) }
        buyerName?.let { add(DerivedClaim("buyerName", it, "購買方名稱")) }
        buyerTaxId?.let { add(DerivedClaim("buyerTaxId", it, "購買方納稅人識別號")) }
        sellerName?.let { add(DerivedClaim("sellerName", it, "銷售方名稱")) }
        sellerTaxId?.let { add(DerivedClaim("sellerTaxId", it, "銷售方納稅人識別號")) }
        amount?.let { add(DerivedClaim("amountExcludingTax", it, "合計金額")) }
        tax?.let { add(DerivedClaim("taxAmount", it, "合計稅額")) }
        total?.let { add(DerivedClaim("totalAmount", it, "價稅合計")) }
        totalInWords?.let { add(DerivedClaim("totalAmountInWords", it, "價稅合計（大寫）")) }
        checkCode?.let { add(DerivedClaim("checkCode", it, "校驗碼")) }
        issuedBy?.let { add(DerivedClaim("issuedBy", it, "開票人")) }
        if (items.isNotEmpty()) add(DerivedClaim("items", items.joinToString("；"), "項目"))
    }

    companion object {
        private const val SP = "\\s*"

        fun recognize(text: String): Boolean {
            val t = MyDataText.halfWidth(text).replace(Regex("\\s+"), "")
            return ("发票号码" in t || "發票號碼" in t) && ("开票日期" in t || "開票日期" in t) && ("发票" in t || "發票" in t)
        }

        /**
         * The invoice in [text] (a text layer laid out line by line), with [tags] (custom tag values by element
         * name, as in the eInvoice schema: InvoiceNo, IssueDate, BuyerName, ...) taking precedence. Null when
         * neither looks like an invoice.
         */
        fun parse(text: String?, tags: Map<String, String> = emptyMap()): ChinaInvoice? {
            val hasTags = tags.keys.any { it in TAG_KEYS }
            if (!hasTags && (text == null || !recognize(text))) return null
            val t = MyDataText.halfWidth(text.orEmpty())
            fun first(re: String) = Regex(re).find(t)?.groupValues?.get(1)?.trim()?.ifEmpty { null }
            fun tag(vararg names: String) = names.firstNotNullOfOrNull { n -> tags[n]?.trim()?.ifEmpty { null } }

            // The title: "电子发票（普通发票）", "增值税电子普通发票" and the like, not "发票号码" or "发票代码".
            val kind = Regex("[\\u4e00-\\u9fff]{0,12}(?:发票|發票)(?:[（(][\\u4e00-\\u9fff]{2,12}[）)])?(?![号號代])")
                .findAll(text.orEmpty()).map { it.value }.firstOrNull { it.length >= 4 }
                ?: tag("InvoiceType", "TypeName")
                ?: "电子发票"
            val number = tag("InvoiceNo", "InvoiceNumber", "EIid") ?: first("(?:发票号码|發票號碼)$SP:$SP([0-9]{8,20})")
            val code = tag("InvoiceCode") ?: first("(?:发票代码|發票代碼)$SP:$SP([0-9]{10,12})")
            val date = date(tag("IssueDate", "InvoiceDate") ?: first("(?:开票日期|開票日期)$SP:$SP([0-9]{4}\\s*(?:年|-|/)\\s*[0-9]{1,2}\\s*(?:月|-|/)\\s*[0-9]{1,2}日?)"))

            // Names and tax IDs in reading order: the buyer first, then the seller. A party may have no tax ID
            // (an individual), so each label keeps its own (possibly empty) value.
            val names = Regex("名$SP" + "称$SP:$SP([^\\s:]+)").findAll(t).map { it.groupValues[1] }.toList()
            val taxIds = Regex("(?:统一社会信用代码/纳税人识别号|统一社会信用代码|纳$SP" + "税$SP" + "人$SP" + "识$SP" + "别$SP" + "号)$SP:$SP([0-9A-Z]{15,20})?")
                .findAll(t).map { it.groupValues[1].ifEmpty { null } }.toList()

            fun money(v: String?) = v?.let { Regex("-?[0-9,]+(?:\\.[0-9]+)?").find(MyDataText.halfWidth(it))?.value }
            val total = money(tag("TaxInclusiveTotalAmount", "TotalAmWithTax"))
                ?: first("\\(小写\\)$SP[¥￥]?$SP(-?[0-9,]+\\.[0-9]{2})")
            val words = first("价税合计$SP\\(大写\\)$SP[^\\u4e00-\\u9fff]*([\\u4e00-\\u9fff]+)")?.takeIf { it != "小写" }
            val sums = Regex("合$SP" + "计$SP[¥￥]$SP(-?[0-9,]+\\.[0-9]{2})(?:$SP[¥￥]$SP(-?[0-9,]+\\.[0-9]{2}))?").find(t)
            val amount = money(tag("TaxExclusiveTotalAmount", "TotalAmount")) ?: sums?.groupValues?.get(1)?.ifEmpty { null }
            val tax = money(tag("TaxTotalAmount", "TotalTaxAm")) ?: sums?.groupValues?.get(2)?.ifEmpty { null }
            val check = (tag("InvoiceCheckCode") ?: first("校验码$SP:$SP([0-9 ]{16,})"))?.replace(" ", "")
            val clerk = tag("InvoiceClerk", "Drawer") ?: first("开票人$SP:$SP(\\S+)")
            val items = Regex("\\*[^*\\s]{1,20}\\*[^\\s*]{0,40}").findAll(t).map { it.value }.distinct().take(20).toList()

            return ChinaInvoice(
                kind = kind,
                number = number,
                code = code,
                issueDate = date,
                buyerName = tag("BuyerName") ?: names.getOrNull(0),
                buyerTaxId = tag("BuyerTaxID", "BuyerIdNum") ?: taxIds.getOrNull(0),
                sellerName = tag("SellerName") ?: names.getOrNull(1),
                sellerTaxId = tag("SellerTaxID", "SellerIdNum") ?: taxIds.getOrNull(1),
                amount = amount,
                tax = tax,
                total = total,
                totalInWords = words,
                checkCode = check,
                issuedBy = clerk,
                items = items,
            ).takeIf { it.number != null || it.total != null }
        }

        private val TAG_KEYS = setOf("InvoiceNo", "InvoiceNumber", "InvoiceCode", "IssueDate", "BuyerName", "SellerName", "TaxInclusiveTotalAmount")

        /** "2026年10月06日", "2026-10-06", "2026/10/6" or "20261006". */
        fun date(s: String?): LocalDate? {
            val m = s?.let { Regex("([0-9]{4})\\s*(?:年|-|/)?\\s*([0-9]{1,2})\\s*(?:月|-|/)?\\s*([0-9]{1,2})").find(it) } ?: return null
            return runCatching { LocalDate(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt()) }.getOrNull()
        }
    }
}

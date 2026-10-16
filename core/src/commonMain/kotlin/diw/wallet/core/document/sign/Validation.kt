package diw.wallet.core.document.sign

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.Serializable

/** Fetches revocation data and issuer certificates: a GET, or a POST of [body] as [contentType]; null on failure. */
fun interface HttpFetch {
    suspend fun fetch(url: String, body: ByteArray?, contentType: String?): ByteArray?
}

/** [HttpFetch] over ktor; only http and https, at most [maxBytes] (large CRLs are refused, OCSP comes first). */
class KtorFetch(private val http: HttpClient, private val maxBytes: Int = 16 * 1024 * 1024) : HttpFetch {
    override suspend fun fetch(url: String, body: ByteArray?, contentType: String?): ByteArray? = runCatching {
        if (!url.startsWith("http://") && !url.startsWith("https://")) return null
        val response = if (body != null) http.post(url) {
            contentType?.let { contentType(ContentType.parse(it)) }
            header("Accept", "*/*")
            setBody(body)
        } else http.get(url)
        if (!response.status.isSuccess()) return null
        response.bodyAsBytes().takeIf { it.isNotEmpty() && it.size <= maxBytes }
    }.getOrNull()
}

/** What the revocation check of one certificate found when the data was collected. */
@Serializable
data class RevocationStatus(
    val subject: String,
    /** "OCSP", "CRL" or "NONE" when neither could be fetched. */
    val source: String,
    /** "GOOD", "REVOKED", "UNKNOWN" or "UNAVAILABLE". */
    val status: String,
    val detail: String? = null,
)

/**
 * Validation data collected for a certificate chain (the signer's or a time-stamp authority's): the chain completed
 * through the AIA links, OCSP responses (preferred) or CRLs, each base64 DER, and what they said.
 */
@Serializable
data class ValidationData(
    val certificates: List<String> = emptyList(),
    val ocsps: List<String> = emptyList(),
    val crls: List<String> = emptyList(),
    val statuses: List<RevocationStatus> = emptyList(),
    val collectedAt: Long = 0,
) {
    val empty: Boolean get() = ocsps.isEmpty() && crls.isEmpty()

    /** Every certificate checked has a good status. */
    val allGood: Boolean get() = statuses.isNotEmpty() && statuses.all { it.status == "GOOD" }

    fun plus(other: ValidationData) = ValidationData(
        (certificates + other.certificates).distinct(), (ocsps + other.ocsps).distinct(), (crls + other.crls).distinct(),
        (statuses + other.statuses).distinctBy { it.subject + it.source }, maxOf(collectedAt, other.collectedAt),
    )

    /** One line for the holder: how many OCSP responses and CRLs, and anything not good. */
    fun summary(): String {
        val parts = ArrayList<String>()
        if (ocsps.isNotEmpty()) parts.add("${ocsps.size} 份 OCSP")
        if (crls.isNotEmpty()) parts.add("${crls.size} 份 CRL")
        val head = if (parts.isEmpty()) "沒有取得撤銷資訊" else "已保存撤銷資訊：" + parts.joinToString("、")
        val bad = statuses.filter { it.status != "GOOD" }.map { s ->
            s.subject + "：" + when (s.status) {
                "REVOKED" -> "已撤銷"
                "UNKNOWN" -> "狀態未知"
                else -> "無法取得"
            }
        }
        return if (bad.isEmpty()) head else head + "（" + bad.joinToString("；") + "）"
    }
}

/** PAdES baseline levels (ETSI EN 319 142-1) the wallet signs a PDF at. */
enum class PadesLevel(val title: String, val detail: String) {
    B_B("PAdES B-B", "簽署憑證與簽章值；沒有可信時間，憑證過期後只能證明完整性"),
    B_T("PAdES B-T", "加上簽章時戳，以時戳機構證明簽署時間"),
    B_LT("PAdES B-LT", "B-T 加上簽署者與時戳機構的憑證鏈及撤銷資訊（DSS，OCSP 優先，取不到才用 CRL），憑證過期或憑證機構停止服務後仍可驗證"),
    B_LTA("PAdES B-LTA", "B-LT 再加文件時戳保護長期驗證資料，之後可再延長");

    val timestamp: Boolean get() = this != B_B
    val revocation: Boolean get() = this == B_LT || this == B_LTA
}

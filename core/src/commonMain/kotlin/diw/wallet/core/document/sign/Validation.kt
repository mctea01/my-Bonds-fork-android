package diw.wallet.core.document.sign

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable

/** Fetches revocation data and issuer certificates: a GET, or a POST of [body] as [contentType]; null on failure. */
fun interface HttpFetch {
    suspend fun fetch(url: String, body: ByteArray?, contentType: String?): ByteArray?
}

/** One HTTP exchange: the status, the body and, for a redirect, where it points. */
class FetchReply(val status: Int, val body: ByteArray, val location: String? = null) {
    val success: Boolean get() = status in 200..299
}

/**
 * HTTP for data that carries its own signature: RFC 3161 time stamps, OCSP responses, CRLs and issuer certificates.
 * Certification and time-stamp authorities publish these over plain http, and every reply is verified by its
 * signature, so a platform that refuses clear text for the rest of the app can give this one route its own client.
 */
fun interface SignedDataHttp {
    /** A GET, or a POST of [body] as [contentType]; throws when the server cannot be reached. Does not follow redirects. */
    suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?): FetchReply
}

/** [SignedDataHttp] over a ktor client that does not follow redirects itself. */
class KtorSignedDataHttp(private val http: HttpClient) : SignedDataHttp {
    override suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?): FetchReply {
        val response = if (body != null) http.post(url) {
            contentType?.let { contentType(ContentType.parse(it)) }
            header("Accept", accept ?: "*/*")
            setBody(body)
        } else http.get(url) { header("Accept", accept ?: "*/*") }
        return FetchReply(response.status.value, response.bodyAsBytes(), response.headers["Location"])
    }
}

/**
 * Sends https to [secure] and http to [cleartext] (or [secure] when there is none) and follows up to [maxRedirects]
 * redirects across both: 307 and 308 repeat the request, the others turn it into a GET.
 */
class SignedDataRoutes(
    private val secure: SignedDataHttp,
    private val cleartext: SignedDataHttp? = null,
    private val maxRedirects: Int = 4,
) : SignedDataHttp {
    override suspend fun exchange(url: String, body: ByteArray?, contentType: String?, accept: String?): FetchReply {
        var current = url
        var payload = body
        repeat(maxRedirects + 1) {
            val client = when {
                current.startsWith("https://") -> secure
                current.startsWith("http://") -> cleartext ?: secure
                else -> throw IllegalArgumentException("Only http and https are fetched: $current")
            }
            val reply = client.exchange(current, payload, contentType, accept)
            val next = reply.location?.takeIf { reply.status in 300..399 } ?: return reply
            current = resolve(current, next)
            if (reply.status != 307 && reply.status != 308) payload = null
        }
        throw IllegalStateException("Too many redirects from $url")
    }

    private fun resolve(base: String, location: String): String = when {
        location.startsWith("http://") || location.startsWith("https://") -> location
        location.startsWith("//") -> base.substringBefore("//") + location
        location.startsWith("/") -> base.substringBefore("//") + "//" + base.substringAfter("//").substringBefore('/') + location
        else -> base.substringBeforeLast('/') + "/" + location
    }
}

/** [HttpFetch] over [SignedDataHttp]; only http and https, at most [maxBytes] (large CRLs are refused, OCSP comes first). */
class SignedDataFetch(private val http: SignedDataHttp, private val maxBytes: Int = 16 * 1024 * 1024) : HttpFetch {
    override suspend fun fetch(url: String, body: ByteArray?, contentType: String?): ByteArray? = try {
        if (!url.startsWith("http://") && !url.startsWith("https://")) null
        else http.exchange(url, body, contentType, null).takeIf { it.success }?.body?.takeIf { it.isNotEmpty() && it.size <= maxBytes }
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        null
    }
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

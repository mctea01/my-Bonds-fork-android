package diw.wallet.core.document.sign

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Mobile citizen certificate signing through the production server's SP account (diw-wallet-server, feature
 * `twfido`), so no SP key ships in the app. The server places the request with the Ministry of the Interior and checks
 * idp_checksum; the ticket it returns is the service's own, so app-to-app still opens the official app with it. The
 * server sees the ID number, the hint and the bytes signed (signed attributes, not the document); [MobileMoicaSigner]
 * still checks every signature against the holder's certificate.
 */
class ServerMobileMoicaClient(
    private val http: HttpClient,
    baseUrl: String,
    /** The access token for this server; sent only to it. */
    private val token: String?,
) : MobileMoicaService {
    private val base = baseUrl.trim().trimEnd('/')

    /** The server's request for each ticket it handed out: its ID and the token that reads it. */
    private val requests = mutableMapOf<String, Pair<String, String>>()

    /** The service environment the server's SP account belongs to, known after the first request. */
    var environment: MobileMoicaEnvironment? = null
        private set

    override suspend fun requestPush(idNumber: String, hint: String, data: ByteArray, timeLimit: Int, deviceAlias: String?): MobileMoicaTicket {
        if (deviceAlias != null) throw MobileMoicaException(null, "正式服務端不支援指定推播裝置")
        return create(MODE_PUSH, idNumber, hint, data, timeLimit)
    }

    override suspend fun requestAppToApp(idNumber: String, hint: String, data: ByteArray, timeLimit: Int): MobileMoicaTicket =
        create(MODE_APP2APP, idNumber, hint, data, timeLimit)

    private suspend fun create(mode: String, idNumber: String, hint: String, data: ByteArray, timeLimit: Int): MobileMoicaTicket {
        TwFidoClient.checkTimeLimit(timeLimit)
        val body = buildJsonObject {
            put("mode", mode)
            put("idNumber", idNumber)
            put("hint", hint)
            put("data", Base64.encode(data))
            put("timeLimit", timeLimit)
        }
        val response = call {
            http.post("$base/twfido/sign") {
                token?.let { header(HttpHeaders.Authorization, "Bearer $it") }
                contentType(ContentType.Application.Json)
                setBody(body.toString())
            }
        }
        val o = json(response)
        if (!response.status.isSuccess()) {
            throw when (response.status) {
                HttpStatusCode.Unauthorized -> MobileMoicaException(
                    "unauthorized",
                    if (token == null) "正式服務端需要存取權杖，請到設定的「零知識證明」頁填入" else "正式服務端不接受這個存取權杖，請到設定的「零知識證明」頁更新",
                )
                HttpStatusCode.NotFound -> MobileMoicaException(null, "這台正式服務端沒有啟用行動自然人憑證簽署")
                else -> MobileMoicaException(o?.str("error"), o?.str("error_description") ?: "正式服務端拒絕簽署要求（HTTP ${response.status.value}）")
            }
        }
        val sessionId = o?.str("sessionId")
        val readToken = o?.str("token")
        val spTicket = o?.str("spTicket")
        if (sessionId.isNullOrEmpty() || readToken.isNullOrEmpty() || spTicket.isNullOrEmpty()) {
            throw MobileMoicaException(null, "正式服務端的回應缺少簽署要求")
        }
        environment = MobileMoicaEnvironment.entries.firstOrNull { it.name == o.str("environment") }
        val ticket = TwFidoClient.parseTicket(spTicket)
        requests[ticket.spTicketId] = sessionId to readToken
        return ticket
    }

    override suspend fun await(ticket: MobileMoicaTicket, timeLimit: Int, pollInterval: Duration): MobileMoicaResult {
        val (sessionId, readToken) = requests[ticket.spTicketId] ?: throw MobileMoicaException(null, "這個簽署要求不是由正式服務端建立")
        try {
            val deadline = Clock.System.now() + timeLimit.seconds + 20.seconds
            val url = "$base/twfido/sign/" + sessionId.encodeURLPathPart() + "?token=" + readToken.encodeURLParameter()
            while (true) {
                delay(pollInterval)
                val response = call { http.get(url) }
                val o = json(response)
                if (response.status == HttpStatusCode.NotFound) throw MobileMoicaException(null, "正式服務端的簽署要求已過期")
                if (!response.status.isSuccess() || o == null) {
                    throw MobileMoicaException(o?.str("error"), o?.str("error_description") ?: "正式服務端無法回報簽署結果（HTTP ${response.status.value}）")
                }
                when (o.str("status")) {
                    "pending" -> Unit
                    "done" -> {
                        val signature = o.str("signature")?.let { runCatching { Base64.decode(it) }.getOrNull() }
                        val certificate = o.str("certificate")?.let { runCatching { Base64.decode(it) }.getOrNull() }
                        if (signature == null || certificate == null) throw MobileMoicaException(null, "正式服務端的回應缺少簽章值或憑證")
                        return MobileMoicaResult(signature, certificate, o.str("hashedIdNumber").orEmpty())
                    }
                    "failed" -> throw MobileMoicaException(o.str("code"), o.str("reason") ?: "行動自然人憑證簽署失敗")
                    else -> throw MobileMoicaException(null, "正式服務端回報了不明的狀態")
                }
                if (Clock.System.now() > deadline) throw MobileMoicaException(null, "等待逾時：沒有在 $timeLimit 秒內於行動自然人憑證 App 完成簽署")
            }
        } finally {
            requests.remove(ticket.spTicketId)
        }
    }

    private suspend fun call(block: suspend () -> HttpResponse): HttpResponse = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        throw MobileMoicaException(null, "無法連線到正式服務端：" + (e.message ?: e::class.simpleName))
    }

    private suspend fun json(response: HttpResponse): JsonObject? =
        runCatching { DiwJson.parseToJsonElement(response.bodyAsText()) as? JsonObject }.getOrNull()

    companion object {
        const val MODE_PUSH = "push"
        const val MODE_APP2APP = "app2app"
    }
}

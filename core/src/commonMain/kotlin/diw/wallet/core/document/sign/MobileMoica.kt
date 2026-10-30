package diw.wallet.core.document.sign

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import io.ktor.client.HttpClient
import io.ktor.client.request.accept
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.toSecretKey
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/** TW FidO (mobile citizen certificate) service hosts; UAT needs its own SP account. */
enum class MobileMoicaEnvironment(val baseUrl: String, val title: String) {
    PRODUCTION("https://fidoapi.moi.gov.tw/", "正式環境"),
    UAT("https://fido-test.moi.gov.tw/", "測試環境（UAT）"),
}

/**
 * The service provider account issued by the Ministry of the Interior: the SP service ID and the 32-byte AES key
 * (base64) that authenticates requests and responses. The app gets it from its build configuration (never from the
 * repository) or, as a developer option, typed in by an SP licence holder for one run.
 */
class MobileMoicaCredentials(val serviceId: String, val aesKeyBase64: String) {
    internal val key: ByteArray by lazy {
        val k = runCatching { Base64.decode(aesKeyBase64.trim()) }.getOrNull()
        if (k == null || k.size != 32) throw SigningException("SP 金鑰必須是 base64 編碼的 32 位元組 AES 金鑰")
        k
    }
}

/** A sign request accepted by the service: sp_ticket and the IDs inside it. */
class MobileMoicaTicket(val spTicket: String, val transactionId: String, val spTicketId: String)

/** A finished signature: PKCS#1 v1.5 RSA with SHA-256 over the bytes sent, and the holder's certificate (DER). */
class MobileMoicaResult(val signature: ByteArray, val certificate: ByteArray, val hashedIdNumber: String)

/** A terminal error code from the service; [code] is the raw error_code. */
class MobileMoicaException(val code: String?, message: String) : Exception(message)

/**
 * TW FidO SP API v2.9 client for the SIGN operation, following Bonds' implementation: push to the holder's device
 * (ATH-03), app-to-app tickets (ATH-01) and result polling (ATH-02). Every request carries sp_checksum and every
 * result is accepted only when idp_checksum opens under the same key and covers this response.
 */
class TwFidoClient(
    private val httpClient: HttpClient,
    private val environment: MobileMoicaEnvironment,
    private val credentials: MobileMoicaCredentials,
    private val baseUrl: String = environment.baseUrl,
) {
    /** Asks the service to push a signing prompt to the holder's devices ([deviceAlias] limits it to one device). */
    suspend fun requestPush(idNumber: String, hint: String, data: ByteArray, timeLimit: Int, deviceAlias: String? = null): MobileMoicaTicket {
        checkTimeLimit(timeLimit)
        val txn = newTransactionId()
        val signData = Base64.encode(data)
        val payload = txn + credentials.serviceId + idNumber + deviceAlias.orEmpty() + OP_CODE + hint + signData
        val body = signBody(txn, idNumber, null, hint, timeLimit, deviceAlias, signData, checksum(payload))
        return ticket(post(PATH_PUSH, body))
    }

    /** Issues an app-to-app ticket; open [deepLink] to hand the request to the mobile citizen certificate app. */
    suspend fun requestAppToApp(idNumber: String, hint: String, data: ByteArray, timeLimit: Int): MobileMoicaTicket {
        checkTimeLimit(timeLimit)
        val txn = newTransactionId()
        val signData = Base64.encode(data)
        val payload = txn + credentials.serviceId + idNumber + OP_CODE + OP_MODE_APP2APP + hint + signData
        val body = signBody(txn, idNumber, OP_MODE_APP2APP, hint, timeLimit, null, signData, checksum(payload))
        return ticket(post(PATH_APP2APP, body))
    }

    /** One poll: null while the holder has not finished. */
    suspend fun result(ticket: MobileMoicaTicket): MobileMoicaResult? {
        val payload = ticket.transactionId + credentials.serviceId + ticket.spTicketId
        val body = buildJsonObject {
            put("transaction_id", ticket.transactionId)
            put("sp_service_id", credentials.serviceId)
            put("sp_checksum", checksum(payload))
            put("sp_ticket_id", ticket.spTicketId)
        }
        val envelope = post(PATH_RESULT, body)
        val code = errorCode(envelope)
        if (code != "0") {
            if (isPending(code)) return null
            throw MobileMoicaException(code, describe(code, envelope))
        }
        val result = envelope["result"] as? JsonObject ?: throw MobileMoicaException(code, "行動自然人憑證服務的回應缺少 result")
        val hashed = result.text("hashed_id_num").orEmpty()
        val signed = result.text("signed_response").orEmpty()
        val idp = result.text("idp_checksum")?.takeIf { it.isNotEmpty() }
            ?: throw MobileMoicaException(code, "行動自然人憑證服務的回應缺少 idp_checksum，無法確認來源")
        if (!verifyChecksum(idp, ticket.transactionId + code + hashed + signed, credentials.key)) {
            throw MobileMoicaException(code, "行動自然人憑證服務的回應無法以 SP 金鑰驗證（idp_checksum 不符）")
        }
        val cert = result.text("cert")?.takeIf { it.isNotEmpty() } ?: throw MobileMoicaException(code, "回應缺少憑證")
        if (signed.isEmpty()) throw MobileMoicaException(code, "回應缺少簽章值")
        val certDer = runCatching { Base64.decode(cert) }.getOrNull() ?: throw MobileMoicaException(code, "回應的憑證不是 base64")
        val sigBytes = runCatching { Base64.decode(signed) }.getOrNull() ?: throw MobileMoicaException(code, "回應的簽章值不是 base64")
        return MobileMoicaResult(sigBytes, certDer, hashed)
    }

    /** Polls until the holder signs or [timeLimit] (plus a margin) passes. */
    suspend fun await(ticket: MobileMoicaTicket, timeLimit: Int, pollInterval: Duration = POLL_INTERVAL): MobileMoicaResult {
        val deadline = Clock.System.now() + timeLimit.seconds + 10.seconds
        while (true) {
            delay(pollInterval)
            result(ticket)?.let { return it }
            if (Clock.System.now() > deadline) throw MobileMoicaException(null, "等待逾時：沒有在 $timeLimit 秒內於行動自然人憑證 App 完成簽署")
        }
    }

    private suspend fun checksum(payload: String): String = spChecksum(payload, credentials.key, PlatformCrypto.randomBytes(12))

    private fun signBody(
        txn: String, idNumber: String, opMode: String?, hint: String, timeLimit: Int, alias: String?, signData: String, checksum: String,
    ): JsonObject = buildJsonObject {
        put("transaction_id", txn)
        put("sp_service_id", credentials.serviceId)
        put("sp_checksum", checksum)
        put("id_num", idNumber)
        put("op_code", OP_CODE)
        // Push requests carry no op_mode at all; adding one is rejected.
        opMode?.let { put("op_mode", it) }
        put("hint", hint)
        put("time_limit", timeLimit)
        alias?.let { put("device_user_def_desc", it) }
        putJsonObject("sign_info") {
            put("sign_data", signData)
            put("sign_type", SIGN_TYPE)
            put("tbs_encoding", "base64")
            put("hash_algorithm", "SHA256")
        }
    }

    private suspend fun post(path: String, body: JsonObject): JsonObject {
        val resp = try {
            httpClient.post(baseUrl + path) {
                contentType(ContentType.Application.Json)
                accept(ContentType.Application.Json)
                setBody(body.toString())
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw MobileMoicaException(null, "無法連線到行動自然人憑證服務（${environment.title}）")
        }
        if (resp.status.value != 200) throw MobileMoicaException(null, "行動自然人憑證服務回應 HTTP ${resp.status.value}")
        return runCatching { DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject }.getOrNull()
            ?: throw MobileMoicaException(null, "行動自然人憑證服務的回應不是 JSON")
    }

    private fun ticket(envelope: JsonObject): MobileMoicaTicket {
        val code = errorCode(envelope)
        if (code != "0") throw MobileMoicaException(code, describe(code, envelope))
        val spTicket = (envelope["result"] as? JsonObject)?.text("sp_ticket")?.takeIf { it.isNotEmpty() }
            ?: throw MobileMoicaException(code, "行動自然人憑證服務的回應缺少 sp_ticket")
        return parseTicket(spTicket)
    }

    companion object {
        const val PATH_PUSH = "moise/sp/requestAthOrSignPush"
        const val PATH_APP2APP = "moise/sp/getSpTicket"
        const val PATH_RESULT = "moise/sp/getAthOrSignResult"
        const val OP_CODE = "SIGN"
        const val OP_MODE_APP2APP = "APP2APP"
        const val SIGN_TYPE = "PKCS#1"
        val TIME_LIMITS = 30..600
        val POLL_INTERVAL = 4.seconds
        private val PENDING = setOf("20002", "20003", "SP-API-ATH-02-SPTKTID_TXNLOG_NF", "SPTKTID_TXNLOG_NF")

        /** hex(iv || AES-256-GCM(lowercase hex of SHA-256(payload)) || tag). */
        suspend fun spChecksum(payload: String, key: ByteArray, iv: ByteArray): String {
            val digestHex = hex(PlatformCrypto.sha256(payload.encodeToByteArray()))
            return hex(iv + Crypto.encrypt(Algorithm.A256GCM, key.toSecretKey(), iv, digestHex.encodeToByteArray()))
        }

        /** Opens [checksum] with [key] and checks that it covers [payload]; false for anything else. */
        suspend fun verifyChecksum(checksum: String, payload: String, key: ByteArray): Boolean {
            val combined = unhex(checksum) ?: return false
            if (combined.size <= 12 + 16) return false
            val opened = runCatching { Crypto.decrypt(Algorithm.A256GCM, key.toSecretKey(), combined.copyOfRange(0, 12), combined.copyOfRange(12, combined.size)) }
                .getOrNull() ?: return false
            return opened.contentEquals(hex(PlatformCrypto.sha256(payload.encodeToByteArray())).encodeToByteArray())
        }

        /** sp_ticket is base64url(json) "." digest; split at the last dot. */
        fun parseTicket(spTicket: String): MobileMoicaTicket {
            val dot = spTicket.lastIndexOf('.')
            if (dot <= 0) throw MobileMoicaException(null, "sp_ticket 格式錯誤")
            val json = runCatching {
                DiwJson.parseToJsonElement(Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(spTicket.substring(0, dot)).decodeToString()) as JsonObject
            }.getOrNull() ?: throw MobileMoicaException(null, "sp_ticket 內容不是 JSON")
            val txn = json.text("transaction_id") ?: throw MobileMoicaException(null, "sp_ticket 缺少 transaction_id")
            val id = json.text("sp_ticket_id") ?: throw MobileMoicaException(null, "sp_ticket 缺少 sp_ticket_id")
            return MobileMoicaTicket(spTicket, txn, id)
        }

        /** mobilemoica://moica.moi.gov.tw/a2a/verifySign with the ticket, the return URL and the transaction ID. */
        fun deepLink(ticket: MobileMoicaTicket, returnUrl: String): String {
            val rtnUrl = Base64.encode(returnUrl.encodeToByteArray())
            val rtnVal = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(ticket.transactionId.encodeToByteArray())
            return "mobilemoica://moica.moi.gov.tw/a2a/verifySign?sp_ticket=" + percent(ticket.spTicket) +
                "&rtn_url=" + percent(rtnUrl) + "&rtn_val=" + percent(rtnVal)
        }

        /** The part before a colon decides; the service sometimes appends an explanation. */
        fun isPending(code: String): Boolean = code.substringBefore(':').trim() in PENDING

        fun checkTimeLimit(timeLimit: Int) {
            if (timeLimit !in TIME_LIMITS) throw SigningException("等待時間必須在 ${TIME_LIMITS.first} 到 ${TIME_LIMITS.last} 秒之間")
        }

        /** Upper-case UUID v4, the form Bonds sends. */
        fun newTransactionId(): String {
            val b = PlatformCrypto.randomBytes(16)
            b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
            b[8] = ((b[8].toInt() and 0x3f) or 0x80).toByte()
            val h = hex(b).uppercase()
            return h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" + h.substring(16, 20) + "-" + h.substring(20)
        }

        private fun errorCode(envelope: JsonObject): String = (envelope["error_code"] as? JsonPrimitive)?.content?.trim() ?: ""

        private fun describe(code: String, envelope: JsonObject): String {
            val msg = (envelope["error_message"] as? JsonPrimitive)?.content
            return "行動自然人憑證服務拒絕要求（$code）" + if (msg.isNullOrBlank()) "" else "：$msg"
        }

        private fun JsonObject.text(name: String): String? = (this[name] as? JsonPrimitive)?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }

        private fun percent(value: String): String = buildString {
            for (b in value.encodeToByteArray()) {
                val c = (b.toInt() and 0xff).toChar()
                if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '.' || c == '_' || c == '~') append(c)
                else append('%').append(HEX[(b.toInt() shr 4) and 0x0f].uppercaseChar()).append(HEX[b.toInt() and 0x0f].uppercaseChar())
            }
        }

        private const val HEX = "0123456789abcdef"

        fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
            for (b in bytes) { append(HEX[(b.toInt() shr 4) and 0x0f]); append(HEX[b.toInt() and 0x0f]) }
        }

        /** Strict: odd length or a non-hex character gives null. */
        fun unhex(s: String): ByteArray? {
            if (s.length % 2 != 0) return null
            val out = ByteArray(s.length / 2)
            for (i in out.indices) {
                val hi = HEX.indexOf(s[2 * i].lowercaseChar())
                val lo = HEX.indexOf(s[2 * i + 1].lowercaseChar())
                if (hi < 0 || lo < 0) return null
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }
    }
}

/** How the signing request reaches the holder. */
enum class MobileMoicaMode(val title: String) {
    /** The service pushes a prompt to the phones bound to the ID number. */
    PUSH("推播到手機"),
    /** This phone opens the mobile citizen certificate app with the ticket. */
    APP_TO_APP("開啟行動自然人憑證 App"),
}

/**
 * Signs through the mobile citizen certificate. The certificate is only returned with a signature, so [load] asks
 * the holder once to sign a short confirmation text and keeps the certificate; each [sign] is a further approval in
 * the app. Every signature is checked against that certificate, so another holder's answer is refused.
 */
class MobileMoicaSigner(
    private val client: TwFidoClient,
    private val idNumber: String,
    private val mode: MobileMoicaMode,
    private val hint: String,
    /** Opens the app-to-app deep link (APP_TO_APP mode). */
    private val openApp: (String) -> Boolean,
    private val returnUrl: String,
    /** Status lines for the screen while the holder approves. */
    private val onStatus: (String) -> Unit = {},
    private val timeLimit: Int = 180,
    private val pollInterval: Duration = TwFidoClient.POLL_INTERVAL,
    certificate: ByteArray? = null,
    private val intermediates: List<ByteArray> = emptyList(),
) : DocumentSigner {
    private var cert: ByteArray? = certificate

    override val certificateChain: List<ByteArray>
        get() = listOf(cert ?: throw SigningException("尚未取得行動自然人憑證的憑證")) + intermediates
    override val keyType = SignerKeyType.RSA
    override val source = SignerSource.MOBILE_MOICA

    /** Gets the holder's certificate through one signature over a confirmation text. */
    suspend fun load(): ByteArray {
        val text = "DIW MY WALLET certificate request " + Clock.System.now().toString()
        val r = request(text.encodeToByteArray(), "取得簽署憑證")
        cert = r.certificate
        return r.certificate
    }

    /** A signer for the same holder with [chain] appended after the certificate read by [load]. */
    fun withIntermediates(chain: List<ByteArray>): MobileMoicaSigner = MobileMoicaSigner(
        client, idNumber, mode, hint, openApp, returnUrl, onStatus, timeLimit, pollInterval, cert, chain,
    )

    override suspend fun sign(data: ByteArray): ByteArray {
        val expected = cert ?: throw SigningException("尚未取得行動自然人憑證的憑證")
        val r = request(data, hint)
        if (!r.certificate.contentEquals(expected)) throw SigningException("簽署者的憑證與先前取得的不同，請使用同一個行動自然人憑證")
        return r.signature
    }

    private suspend fun request(data: ByteArray, hintText: String): MobileMoicaResult {
        val ticket = try {
            when (mode) {
                MobileMoicaMode.PUSH -> client.requestPush(idNumber, hintText, data, timeLimit)
                MobileMoicaMode.APP_TO_APP -> client.requestAppToApp(idNumber, hintText, data, timeLimit)
            }
        } catch (e: MobileMoicaException) {
            throw SigningException(e.message ?: "行動自然人憑證要求失敗", e)
        }
        when (mode) {
            MobileMoicaMode.PUSH -> onStatus("已推播到你的手機：請在行動自然人憑證 App 確認「$hintText」")
            MobileMoicaMode.APP_TO_APP -> {
                if (!openApp(TwFidoClient.deepLink(ticket, returnUrl))) throw SigningException("這支手機沒有安裝行動自然人憑證 App")
                onStatus("請在行動自然人憑證 App 確認「$hintText」，完成後回到這裡")
            }
        }
        val r = try {
            client.await(ticket, timeLimit, pollInterval)
        } catch (e: MobileMoicaException) {
            throw SigningException(e.message ?: "行動自然人憑證簽署失敗", e)
        }
        val rsa = PlatformCrypto.rsaPublicKeyFromCertificate(r.certificate) ?: throw SigningException("行動自然人憑證的憑證不是 RSA 金鑰")
        if (!PlatformCrypto.verifyRsa("RS256", rsa, data, r.signature)) throw SigningException("行動自然人憑證回傳的簽章與憑證不符")
        return r
    }
}

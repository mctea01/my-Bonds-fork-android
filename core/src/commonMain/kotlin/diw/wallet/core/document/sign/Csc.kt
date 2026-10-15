package diw.wallet.core.document.sign

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.int
import diw.wallet.core.util.long
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.http.decodeURLQueryComponent
import io.ktor.http.isSuccess
import io.ktor.http.parameters
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.EcSignature
import org.multipaz.util.fromBase64
import kotlin.io.encoding.Base64
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** Whether a remote signing service issues real signatures or test ones; the UI keeps the two apart. */
enum class CscEnvironment(val title: String) { TEST("測試服務"), PRODUCTION("正式服務") }

/**
 * A remote signing service reached through the Cloud Signature Consortium API v2 with OAuth 2.0 authorization code
 * flow (PKCE). [baseUrl] is the CSC API root that serves /info, /credentials/list and /signatures/signHash.
 */
@Serializable
data class CscService(
    val id: String,
    val name: String,
    val baseUrl: String,
    val clientId: String,
    val clientSecret: String? = null,
    val redirectUri: String,
    val environment: CscEnvironment,
    val note: String? = null,
    val builtIn: Boolean = false,
)

/** Services that come with the wallet. */
object CscServices {
    /** Redirect address the wallet handles itself; services added by the user register this one. */
    const val WALLET_REDIRECT = "diw-wallet://csc/callback"

    /** The EUDI reference wallet's settings for the wallet-centric rQES test QTSP (RQESConfigImpl). */
    val EUDI_DEMO = CscService(
        id = "eudi-walletcentric",
        name = "EUDI 遠端簽章測試服務",
        baseUrl = "https://walletcentric.signer.eudiw.dev/csc/v2",
        clientId = "wallet-client",
        clientSecret = "somesecret2",
        redirectUri = "rqes://oauth/callback",
        environment = CscEnvironment.TEST,
        note = "歐盟數位身分錢包參考實作的測試簽章服務：以 EUDI 測試身分（PID，SD-JWT VC）登入，第一次使用時自動建立測試簽章憑證",
        builtIn = true,
    )

    val EUDI_DEV = EUDI_DEMO.copy(
        id = "eudi-walletcentric-dev",
        name = "EUDI 遠端簽章測試服務（開發版）",
        baseUrl = "https://walletcentric.signer.dev.eudiw.dev/csc/v2",
        note = "EUDI 簽章服務的開發版本，功能較新但可能不穩定",
    )

    val builtIn: List<CscService> = listOf(EUDI_DEMO, EUDI_DEV)
}

/** A failure reported by a remote signing service or in its authorization; [message] is shown as is. */
class CscException(message: String, val error: String? = null, cause: Throwable? = null) : Exception(message, cause)

/** What /info says about a service. */
data class CscInfo(
    val name: String?,
    val oauth2: String?,
    val oauth2Issuer: String?,
    val authTypes: List<String>,
    val methods: List<String>,
    val signAlgorithms: List<String>,
)

/** A signing key and certificate the user holds at a service (credentials/list or credentials/info). */
data class CscCredential(
    val id: String,
    val description: String?,
    /** End-entity certificate first, then its chain (DER). */
    val certificates: List<ByteArray>,
    val subject: String?,
    val keyAlgorithms: List<String>,
    val keyEnabled: Boolean,
    val certificateStatus: String?,
    /** implicit, explicit or oauth2code. */
    val authMode: String,
    val scal: String?,
    val pinNeeded: Boolean,
    val otpNeeded: Boolean,
    val otpOnline: Boolean,
) {
    val usable: Boolean get() = keyEnabled && certificates.isNotEmpty() && (certificateStatus == null || certificateStatus == "valid")
}

class CscToken(val accessToken: String, val expiresAt: Instant?) {
    val valid: Boolean get() = expiresAt == null || Clock.System.now() < expiresAt - 30.seconds
}

/** An authorization request in flight: the address to open and what the answer must match. */
class CscAuthorizationRequest(val url: String, val state: String, val codeVerifier: String)

/**
 * How the wallet lets the holder take part: [authorize] opens an authorization address (a sign-in page, or a
 * presentation request the wallet answers itself) and returns the address the service redirected to, which starts
 * with [redirectUri]; [askSecret] asks for a PIN or one-time password and returns null when the holder cancels.
 */
interface CscUserAgent {
    suspend fun authorize(url: String, redirectUri: String, purpose: String): String
    suspend fun askSecret(label: String, numeric: Boolean): String?
}

/** CSC API v2 client for one [service]. */
class CscClient(private val http: HttpClient, val service: CscService) {
    private var info: CscInfo? = null
    private var endpoints: Pair<String, String>? = null
    private val base = service.baseUrl.trim().trimEnd('/')

    suspend fun info(): CscInfo = info ?: run {
        val o = call("info", buildJsonObject { put("lang", "en-US") }, null)
        CscInfo(
            name = o.str("name"),
            oauth2 = o.str("oauth2"),
            oauth2Issuer = o.str("oauth2Issuer"),
            authTypes = o.strList("authType"),
            methods = o.strList("methods"),
            signAlgorithms = o.obj("signAlgorithms")?.strList("algos").orEmpty(),
        ).also { info = it }
    }

    /** Authorization and token endpoints: RFC 8414 metadata of oauth2Issuer, else the oauth2 base address. */
    private suspend fun endpoints(): Pair<String, String> = endpoints ?: run {
        val i = info()
        val issuer = i.oauth2Issuer?.trimEnd('/')
        val fromMetadata = issuer?.let { iss ->
            runCatching {
                val r = http.get("$iss/.well-known/oauth-authorization-server")
                val m = DiwJson.parseToJsonElement(r.bodyAsText()) as JsonObject
                val a = m.str("authorization_endpoint")
                val t = m.str("token_endpoint")
                if (r.status.isSuccess() && a != null && t != null) a to t else null
            }.getOrNull()
        }
        val oauth = (i.oauth2 ?: issuer)?.trimEnd('/')
        (fromMetadata ?: oauth?.let { "$it/oauth2/authorize" to "$it/oauth2/token" }
            ?: throw CscException("遠端簽章服務沒有提供 OAuth 2.0 授權位址，目前只支援 OAuth 授權的服務")).also { endpoints = it }
    }

    /**
     * Authorization request for [scope] ("service" to list credentials, "credential" to approve signatures) with
     * [extra] parameters such as credentialID, numSignatures, hashes and hashAlgorithmOID.
     */
    suspend fun authorizationRequest(scope: String, extra: Map<String, String> = emptyMap()): CscAuthorizationRequest {
        val (authorize, _) = endpoints()
        val verifier = PlatformCrypto.randomBytes(32).toBase64Url()
        val challenge = PlatformCrypto.sha256(verifier.encodeToByteArray()).toBase64Url()
        val state = PlatformCrypto.randomBytes(16).toBase64Url()
        val url = URLBuilder(authorize).apply {
            parameters.append("response_type", "code")
            parameters.append("client_id", service.clientId)
            parameters.append("redirect_uri", service.redirectUri)
            parameters.append("scope", scope)
            parameters.append("code_challenge", challenge)
            parameters.append("code_challenge_method", "S256")
            parameters.append("state", state)
            parameters.append("lang", "zh-TW")
            extra.forEach { (k, v) -> parameters.append(k, v) }
        }.buildString()
        return CscAuthorizationRequest(url, state, verifier)
    }

    /** The authorization code in the address the service redirected to, after checking state and errors. */
    fun code(redirected: String, request: CscAuthorizationRequest): String {
        val query = redirected.substringAfter('?', "").substringBefore('#')
        val params = query.split('&').filter { '=' in it }.associate {
            it.substringBefore('=').decodeURLQueryComponent() to it.substringAfter('=').decodeURLQueryComponent(plusIsSpace = true)
        }
        params["error"]?.let { e ->
            throw CscException("遠端簽章服務拒絕授權：" + (params["error_description"] ?: e), e)
        }
        if (params["state"] != request.state) throw CscException("授權回應與這次要求不符（state 不同），已停止")
        return params["code"] ?: throw CscException("授權回應沒有授權碼")
    }

    suspend fun token(code: String, request: CscAuthorizationRequest): CscToken {
        val (_, tokenEndpoint) = endpoints()
        val r = http.submitForm(tokenEndpoint, parameters {
            append("grant_type", "authorization_code")
            append("code", code)
            append("redirect_uri", service.redirectUri)
            append("code_verifier", request.codeVerifier)
            append("client_id", service.clientId)
        }) {
            service.clientSecret?.takeIf { it.isNotEmpty() }?.let { secret ->
                header(HttpHeaders.Authorization, "Basic " + Base64.Default.encode("${service.clientId}:$secret".encodeToByteArray()))
            }
        }
        val o = parse(r, "取得存取權杖")
        val access = o.str("access_token") ?: throw CscException("遠端簽章服務沒有回傳存取權杖")
        return CscToken(access, o.long("expires_in")?.let { Clock.System.now() + it.seconds })
    }

    /** The holder's credentials with their certificates; credentials/info fills in what the list leaves out. */
    suspend fun credentials(token: CscToken): List<CscCredential> {
        val o = call("credentials/list", buildJsonObject {
            put("credentialInfo", true)
            put("certificates", "chain")
            put("certInfo", true)
            put("authInfo", true)
        }, token)
        val ids = o.strList("credentialIDs")
        val infos = o.arr("credentialInfos")?.mapNotNull { it as? JsonObject }.orEmpty()
        return ids.map { id ->
            val i = infos.firstOrNull { it.str("credentialID") == id } ?: infos.getOrNull(ids.indexOf(id))?.takeIf { it.str("credentialID") == null }
                ?: call("credentials/info", buildJsonObject {
                    put("credentialID", id)
                    put("certificates", "chain")
                    put("certInfo", true)
                    put("authInfo", true)
                }, token)
            credential(id, i)
        }
    }

    private fun credential(id: String, o: JsonObject): CscCredential {
        val key = o.obj("key")
        val cert = o.obj("cert")
        val auth = o.obj("auth")
        // CSC v1 put PIN and OTP beside authMode; v2 lists them as auth objects.
        val objects = auth?.arr("objects")?.mapNotNull { it as? JsonObject }.orEmpty()
        val pin = o.obj("PIN")?.str("presence") == "true" || objects.any { it.str("type").equals("PIN", true) }
        val otp = o.obj("OTP")?.str("presence") == "true" || objects.any { it.str("type").equals("OTP", true) }
        val otpOnline = o.obj("OTP")?.str("type") == "online" || objects.any { it.str("type").equals("OTP", true) && it.str("generator") == "online" }
        return CscCredential(
            id = id,
            description = o.str("description"),
            certificates = cert?.strList("certificates").orEmpty().mapNotNull { runCatching { it.fromBase64() }.getOrNull() },
            subject = cert?.str("subjectDN"),
            keyAlgorithms = key?.strList("algo").orEmpty(),
            keyEnabled = key?.str("status")?.let { it == "enabled" } ?: true,
            certificateStatus = cert?.str("status"),
            authMode = auth?.str("mode") ?: o.str("authMode") ?: "oauth2code",
            scal = o.str("SCAL") ?: o.int("SCAL")?.toString(),
            pinNeeded = pin,
            otpNeeded = otp,
            otpOnline = otpOnline,
        )
    }

    suspend fun sendOtp(token: CscToken, credentialId: String) {
        call("credentials/sendOTP", buildJsonObject { put("credentialID", credentialId) }, token)
    }

    /** credentials/authorize for implicit and explicit modes; returns the signature activation data. */
    suspend fun authorizeCredential(token: CscToken, credentialId: String, hashes: List<ByteArray>, pin: String?, otp: String?, description: String?): String {
        val o = call("credentials/authorize", buildJsonObject {
            put("credentialID", credentialId)
            put("numSignatures", hashes.size)
            putJsonArray("hashes") { hashes.forEach { add(JsonPrimitive(Base64.Default.encode(it))) } }
            put("hashAlgorithmOID", SHA256_OID)
            pin?.let { put("PIN", it) }
            otp?.let { put("OTP", it) }
            description?.let { put("description", it) }
        }, token)
        return o.str("SAD") ?: throw CscException("遠端簽章服務沒有回傳簽章啟用資料（SAD）")
    }

    suspend fun signHash(token: CscToken, credentialId: String, hashes: List<ByteArray>, signAlgorithm: String, sad: String? = null): List<ByteArray> {
        val o = call("signatures/signHash", buildJsonObject {
            put("credentialID", credentialId)
            sad?.let { put("SAD", it) }
            putJsonArray("hashes") { hashes.forEach { add(JsonPrimitive(Base64.Default.encode(it))) } }
            put("hashAlgorithmOID", SHA256_OID)
            put("signAlgo", signAlgorithm)
            put("operationMode", "S")
        }, token)
        val signatures = o.strList("signatures").map { it.fromBase64() }
        if (signatures.size != hashes.size) throw CscException("遠端簽章服務回傳的簽章數量不符")
        return signatures
    }

    private suspend fun call(method: String, body: JsonObject, token: CscToken?): JsonObject {
        val r = http.post("$base/$method") {
            token?.let { header(HttpHeaders.Authorization, "Bearer " + it.accessToken) }
            contentType(ContentType.Application.Json)
            setBody(body.toString())
        }
        return parse(r, method)
    }

    private suspend fun parse(r: HttpResponse, what: String): JsonObject {
        val text = r.bodyAsText()
        val o = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull()
        if (!r.status.isSuccess()) {
            val error = o?.str("error")
            val description = o?.str("error_description") ?: o?.str("message") ?: error
            throw CscException("遠端簽章服務在「$what」回應錯誤（HTTP ${r.status.value}）" + (description?.let { "：$it" } ?: ""), error)
        }
        return o ?: if (text.isBlank()) JsonObject(emptyMap()) else throw CscException("遠端簽章服務在「$what」的回應不是 JSON")
    }

    companion object {
        const val SHA256_OID = "2.16.840.1.101.3.4.2.1"
        const val ECDSA_SHA256 = "1.2.840.10045.4.3.2"
        const val EC_PUBLIC_KEY = "1.2.840.10045.2.1"
        const val RSA_SHA256 = "1.2.840.113549.1.1.11"
        const val RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
    }
}

/**
 * Signs through a CSC remote signing service. [load] signs the holder in to the service and reads the credential
 * (certificate chain); each [sign] approves that one hash with the service (an OAuth credential authorization, or a
 * PIN and one-time password) and calls signatures/signHash. Signatures are checked against the certificate by the
 * document formats, so a wrong key never reaches a file.
 */
class CscSigner(
    private val client: CscClient,
    private val agent: CscUserAgent,
    private val credentialId: String? = null,
    private val hint: String = "DIW MY WALLET 文件簽署",
    private val onStatus: (String) -> Unit = {},
    serviceToken: CscToken? = null,
) : DocumentSigner {
    var serviceToken: CscToken? = serviceToken
        private set
    var credential: CscCredential? = null
        private set

    override val certificateChain: List<ByteArray>
        get() = credential?.certificates ?: throw SigningException("尚未取得遠端簽章憑證")
    override val keyType: SignerKeyType
        get() = keyTypeOf(certificateChain.first())
    override val source = SignerSource.CSC

    /** Signs in when needed and picks the credential: the one asked for, else the first usable one. */
    suspend fun load(): CscCredential {
        val token = serviceToken()
        onStatus("讀取遠端簽章憑證")
        val list = client.credentials(token)
        val chosen = credentialId?.let { id -> list.firstOrNull { it.id == id } ?: throw SigningException("遠端簽章服務找不到選擇的憑證") }
            ?: list.firstOrNull { it.usable }
            ?: throw SigningException(if (list.isEmpty()) "這個帳號在遠端簽章服務沒有簽章憑證" else "遠端簽章服務的憑證都無法使用（金鑰停用、憑證過期或撤銷）")
        if (!chosen.usable) throw SigningException("選擇的遠端簽章憑證無法使用（金鑰停用、憑證過期或撤銷）")
        keyTypeOf(chosen.certificates.first())
        credential = chosen
        return chosen
    }

    private suspend fun serviceToken(): CscToken {
        serviceToken?.takeIf { it.valid }?.let { return it }
        client.info()
        onStatus("登入遠端簽章服務")
        val request = client.authorizationRequest("service")
        val back = agent.authorize(request.url, client.service.redirectUri, "登入「${client.service.name}」")
        return client.token(client.code(back, request), request).also { serviceToken = it }
    }

    override suspend fun sign(data: ByteArray): ByteArray {
        val c = credential ?: load()
        val hash = PlatformCrypto.sha256(data)
        val algorithm = signAlgorithm(c)
        val signature = when (c.authMode) {
            "implicit", "explicit" -> {
                val token = serviceToken()
                if (c.otpNeeded && c.otpOnline) client.sendOtp(token, c.id)
                val pin = if (c.pinNeeded) agent.askSecret("遠端簽章 PIN 碼", false) ?: throw SigningException("已取消簽署") else null
                val otp = if (c.otpNeeded) agent.askSecret("一次性密碼（OTP）", true) ?: throw SigningException("已取消簽署") else null
                onStatus("遠端簽章服務簽署中")
                val sad = client.authorizeCredential(token, c.id, listOf(hash), pin, otp, hint)
                client.signHash(token, c.id, listOf(hash), algorithm, sad)
            }
            else -> {
                onStatus("授權這次簽章")
                val request = client.authorizationRequest("credential", mapOf(
                    "credentialID" to c.id,
                    "numSignatures" to "1",
                    "hashes" to hash.toBase64Url(),
                    "hashAlgorithmOID" to CscClient.SHA256_OID,
                    "description" to hint,
                ))
                val back = agent.authorize(request.url, client.service.redirectUri, "授權「${client.service.name}」簽署：$hint")
                val token = client.token(client.code(back, request), request)
                onStatus("遠端簽章服務簽署中")
                client.signHash(token, c.id, listOf(hash), algorithm)
            }
        }.single()
        return if (keyTypeOf(c.certificates.first()) == SignerKeyType.EC_P256 && signature.size == 64) {
            EcSignature(signature.copyOfRange(0, 32), signature.copyOfRange(32, 64)).toDerEncoded()
        } else signature
    }

    companion object {
        /** RSA or EC P-256 from the certificate; other keys are refused because the document formats cannot use them. */
        fun keyTypeOf(certificate: ByteArray): SignerKeyType {
            if (PlatformCrypto.rsaPublicKeyFromCertificate(certificate) != null) return SignerKeyType.RSA
            val ec = runCatching { org.multipaz.crypto.X509Cert(kotlinx.io.bytestring.ByteString(certificate)).ecPublicKey }.getOrNull()
                ?: throw SigningException("無法讀取遠端簽章憑證的公開金鑰")
            if (ec.curve != org.multipaz.crypto.EcCurve.P256) throw SigningException("遠端簽章憑證的金鑰（${ec.curve.name}）不支援，只支援 RSA 與 EC P-256")
            return SignerKeyType.EC_P256
        }

        /** A signature algorithm the credential lists, with SHA-256 for the hash the wallet computed. */
        fun signAlgorithm(c: CscCredential): String {
            val algos = c.keyAlgorithms
            return when (keyTypeOf(c.certificates.first())) {
                SignerKeyType.EC_P256 -> if (algos.isEmpty() || CscClient.ECDSA_SHA256 in algos) CscClient.ECDSA_SHA256 else algos.first()
                SignerKeyType.RSA -> if (algos.isEmpty() || CscClient.RSA_SHA256 in algos) CscClient.RSA_SHA256 else algos.first()
            }
        }
    }
}

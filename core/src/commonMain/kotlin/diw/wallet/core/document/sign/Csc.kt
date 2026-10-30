package diw.wallet.core.document.sign

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.int
import diw.wallet.core.util.long
import diw.wallet.core.util.isAcceptableEndpoint
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
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
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

    /**
     * Services from a CSC profile: a JSON object, or an array of them, holding what /info cannot tell, so the user
     * does not type each value. Members: "type" ("csc-profile"), "name", "baseUrl" (the CSC API root), "clientId",
     * optional "clientSecret", "redirectUri" (the wallet's own when absent), "environment" ("test" or
     * "production"), optional "note". [allowHttp] admits http base addresses (loopback test servers only).
     */
    fun fromProfile(json: String, allowHttp: Boolean = false): List<CscService> {
        val root = runCatching { DiwJson.parseToJsonElement(json.trim()) }.getOrElse { throw CscException("CSC Profile 不是 JSON") }
        val items = when (root) {
            is JsonObject -> listOf(root)
            is kotlinx.serialization.json.JsonArray -> root.mapNotNull { it as? JsonObject }
            else -> emptyList()
        }
        if (items.isEmpty()) throw CscException("CSC Profile 沒有任何服務")
        return items.mapIndexed { i, o ->
            o.str("type")?.let { if (it != PROFILE_TYPE) throw CscException("第 ${i + 1} 項不是 CSC Profile（type 為 $it）") }
            val name = o.str("name")?.trim()?.takeIf { it.isNotEmpty() } ?: throw CscException("第 ${i + 1} 項缺少 name")
            val base = o.str("baseUrl")?.trim()?.trimEnd('/') ?: throw CscException("「$name」缺少 baseUrl")
            if (!base.startsWith("https://") && !(allowHttp && base.startsWith("http://"))) throw CscException("「$name」的 baseUrl 必須是 https")
            val clientId = o.str("clientId")?.trim()?.takeIf { it.isNotEmpty() } ?: throw CscException("「$name」缺少 clientId")
            val env = when (o.str("environment")?.lowercase()) {
                "test" -> CscEnvironment.TEST
                "production", null -> CscEnvironment.PRODUCTION
                else -> throw CscException("「$name」的 environment 只能是 test 或 production")
            }
            CscService(
                id = "user-" + PlatformCrypto.sha256((base + "|" + clientId).encodeToByteArray()).copyOfRange(0, 6).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') },
                name = name.take(60),
                baseUrl = base,
                clientId = clientId,
                clientSecret = o.str("clientSecret")?.trim()?.ifEmpty { null },
                redirectUri = o.str("redirectUri")?.trim()?.takeIf { ':' in it } ?: WALLET_REDIRECT,
                environment = env,
                note = o.str("note")?.take(200),
            )
        }
    }

    /** A profile for [s] that another wallet can import; the client secret is left out unless [withSecret]. */
    fun profileOf(s: CscService, withSecret: Boolean = false): String = buildJsonObject {
        put("type", PROFILE_TYPE)
        put("name", s.name)
        put("baseUrl", s.baseUrl)
        put("clientId", s.clientId)
        if (withSecret) s.clientSecret?.let { put("clientSecret", it) }
        put("redirectUri", s.redirectUri)
        put("environment", if (s.environment == CscEnvironment.TEST) "test" else "production")
        s.note?.let { put("note", it) }
    }.toString()

    const val PROFILE_TYPE = "csc-profile"
}

/** A failure reported by a remote signing service or in its authorization; [message] is shown as is. */
class CscException(message: String, val error: String? = null, cause: Throwable? = null) : Exception(message, cause)

/** What /info says about a service (CSC API v2.2 section 11.1). */
data class CscInfo(
    val name: String?,
    val oauth2: String?,
    val oauth2Issuer: String?,
    val authTypes: List<String>,
    val methods: List<String>,
    val signAlgorithms: List<String>,
    val specs: String? = null,
    val region: String? = null,
    /** RFC 9396 authorization_details is accepted at the authorization server. */
    val supportsRar: Boolean = false,
    val asynchronousOperationMode: Boolean = false,
    /** signatures/signDoc: signature formats (C, X, P, J), envelope properties and conformance levels. */
    val signatureFormats: List<String> = emptyList(),
    val conformanceLevels: List<String> = emptyList(),
) {
    fun supports(method: String): Boolean = methods.isEmpty() && method == "signatures/signHash" || method in methods
}

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
class CscAuthorizationRequest(
    val url: String,
    val state: String,
    val codeVerifier: String,
    /** RFC 9396 authorization_details sent with the request, repeated in the token request. */
    val authorizationDetails: String? = null,
)

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
    private var endpoints: OAuthEndpoints? = null
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
            specs = o.str("specs"),
            region = o.str("region"),
            supportsRar = o.bool("supportsRar") == true,
            asynchronousOperationMode = o.bool("asynchronousOperationMode") == true,
            signatureFormats = o.obj("signature_formats")?.strList("formats").orEmpty(),
            conformanceLevels = o.strList("conformance_levels"),
        ).also { info = it }
    }

    /** The OAuth endpoints: authorization, token, and pushed authorization (RFC 9126) when the service has one. */
    private class OAuthEndpoints(val authorize: String, val token: String, val par: String?)

    /**
     * Authorization, token and pushed authorization endpoints: RFC 8414 metadata of oauth2Issuer, else the oauth2 base
     * address with the CSC paths (oauth2/pushed_authorize only when /info lists it).
     */
    private suspend fun endpoints(): OAuthEndpoints = endpoints ?: run {
        val i = info()
        val issuer = i.oauth2Issuer?.trimEnd('/')
        val fromMetadata = issuer?.let { iss ->
            runCatching {
                val r = http.get("$iss/.well-known/oauth-authorization-server")
                val m = DiwJson.parseToJsonElement(r.bodyAsText()) as JsonObject
                val a = m.str("authorization_endpoint")
                val t = m.str("token_endpoint")
                if (r.status.isSuccess() && a != null && t != null) OAuthEndpoints(a, t, m.str("pushed_authorization_request_endpoint")) else null
            }.getOrNull()
        }
        val oauth = (i.oauth2 ?: issuer)?.trimEnd('/')
        val found = fromMetadata ?: oauth?.let {
            OAuthEndpoints("$it/oauth2/authorize", "$it/oauth2/token", if ("oauth2/pushed_authorize" in i.methods) "$it/oauth2/pushed_authorize" else null)
        } ?: throw CscException("遠端簽章服務沒有提供 OAuth 2.0 授權位址，目前只支援 OAuth 授權的服務")
        val allowTestLocalhost = service.environment == CscEnvironment.TEST
        if (listOfNotNull(found.authorize, found.token, found.par).any { !isAcceptableEndpoint(it, allowTestLocalhost) }) {
            throw CscException("遠端簽章 OAuth 授權與 Token 端點必須使用 HTTPS（本機測試環境除外）")
        }
        found.also { endpoints = it }
    }

    /** True when the authorization request goes through the pushed authorization endpoint. */
    suspend fun usesPushedAuthorization(): Boolean = endpoints().par != null

    /**
     * Authorization request for [scope] ("service" to list credentials, "credential" to approve signatures) with
     * [extra] parameters such as credentialID, numSignatures, hashes and hashAlgorithmOID.
     */
    suspend fun authorizationRequest(
        scope: String,
        extra: Map<String, String> = emptyMap(),
        authorizationDetails: String? = null,
    ): CscAuthorizationRequest {
        val ep = endpoints()
        val verifier = PlatformCrypto.randomBytes(32).toBase64Url()
        val challenge = PlatformCrypto.sha256(verifier.encodeToByteArray()).toBase64Url()
        val state = PlatformCrypto.randomBytes(16).toBase64Url()
        val params = LinkedHashMap<String, String>()
        params["response_type"] = "code"
        params["client_id"] = service.clientId
        params["redirect_uri"] = service.redirectUri
        params["scope"] = scope
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"
        params["state"] = state
        params["lang"] = "zh-TW"
        params.putAll(extra)
        authorizationDetails?.let { params["authorization_details"] = it }
        val url = if (ep.par != null) {
            // RFC 9126: the parameters go to the service directly (authenticated like a token request); the browser
            // only carries client_id and the request_uri the service answers with.
            val r = http.submitForm(ep.par, parameters { params.forEach { (k, v) -> append(k, v) } }) { clientAuthentication() }
            val o = parse(r, "推送授權要求")
            val requestUri = o.str("request_uri") ?: throw CscException("遠端簽章服務的推送授權沒有回傳 request_uri")
            URLBuilder(ep.authorize).apply {
                parameters.append("client_id", service.clientId)
                parameters.append("request_uri", requestUri)
            }.buildString()
        } else URLBuilder(ep.authorize).apply { params.forEach { (k, v) -> parameters.append(k, v) } }.buildString()
        return CscAuthorizationRequest(url, state, verifier, authorizationDetails)
    }

    private fun io.ktor.client.request.HttpRequestBuilder.clientAuthentication() {
        service.clientSecret?.takeIf { it.isNotEmpty() }?.let { secret ->
            header(HttpHeaders.Authorization, "Basic " + Base64.Default.encode("${service.clientId}:$secret".encodeToByteArray()))
        }
    }

    /** The authorization code in the address the service redirected to, after checking state and errors. */
    fun code(redirected: String, request: CscAuthorizationRequest): String {
        if (redirected.substringBefore('?').substringBefore('#') != service.redirectUri) {
            throw CscException("遠端簽章授權回呼網址與已登記的 redirect_uri 不符")
        }
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
        val tokenEndpoint = endpoints().token
        val r = http.submitForm(tokenEndpoint, parameters {
            append("grant_type", "authorization_code")
            append("code", code)
            append("redirect_uri", service.redirectUri)
            append("code_verifier", request.codeVerifier)
            append("client_id", service.clientId)
            request.authorizationDetails?.let { append("authorization_details", it) }
        }) { clientAuthentication() }
        val o = parse(r, "取得存取權杖")
        val access = o.str("access_token") ?: throw CscException("遠端簽章服務沒有回傳存取權杖")
        if (!o.str("token_type").equals("Bearer", true)) {
            throw CscException("遠端簽章服務未回傳 Bearer 型別的存取權杖")
        }
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
        // A service may process the request asynchronously anyway and answer with a responseID (section 11.13).
        val done = o.str("responseID")?.takeIf { o["signatures"] == null }?.let { poll(token, it) } ?: o
        val signatures = done.strList("signatures").map { it.fromBase64() }
        if (signatures.size != hashes.size) throw CscException("遠端簽章服務回傳的簽章數量不符")
        return signatures
    }

    /**
     * signatures/signDoc with one document digest (section 11.14): the service builds the AdES signature itself and
     * returns the SignatureObject, for PAdES (format "P") the CMS SignedData to embed in the PDF. [level] is a
     * conformance level such as AdES-B-B or AdES-B-T.
     */
    suspend fun signDoc(token: CscToken, credentialId: String, hash: ByteArray, format: String, level: String, signAlgorithm: String, sad: String? = null): ByteArray {
        val o = call("signatures/signDoc", buildJsonObject {
            put("credentialID", credentialId)
            sad?.let { put("SAD", it) }
            putJsonArray("documentDigests") {
                addJsonObject {
                    putJsonArray("hashes") { add(JsonPrimitive(Base64.Default.encode(hash))) }
                    put("hashAlgorithmOID", SHA256_OID)
                    put("signature_format", format)
                    put("conformance_level", level)
                    put("signAlgo", signAlgorithm)
                    if (format == "C") put("signed_envelope_property", "Detached")
                }
            }
            put("hashAlgorithmOID", SHA256_OID)
            put("operationMode", "S")
        }, token)
        val done = o.str("responseID")?.takeIf { o["SignatureObject"] == null && o["DocumentWithSignature"] == null }?.let { poll(token, it) } ?: o
        return done.strList("SignatureObject").singleOrNull()?.fromBase64()
            ?: throw CscException("遠端簽章服務的 signDoc 沒有回傳簽章物件（SignatureObject）")
    }

    /** signatures/signPolling until the asynchronous request completes (200) rather than pending (202). */
    private suspend fun poll(token: CscToken, responseId: String): JsonObject {
        repeat(POLL_ATTEMPTS) {
            val r = http.post("$base/signatures/signPolling") {
                header(HttpHeaders.Authorization, "Bearer " + token.accessToken)
                contentType(ContentType.Application.Json)
                setBody(buildJsonObject { put("requestID", responseId) }.toString())
            }
            if (r.status.value != 202) return parse(r, "signatures/signPolling")
            kotlinx.coroutines.delay(POLL_INTERVAL_MS)
        }
        throw CscException("遠端簽章服務在 ${POLL_ATTEMPTS * POLL_INTERVAL_MS / 1000} 秒內沒有完成簽章")
    }

    /** signatures/timestamp (section 11.16): an RFC 3161 token from the service over [hash] (SHA-256), with a nonce. */
    suspend fun timestamp(token: CscToken, hash: ByteArray): ByteArray {
        val nonce = PlatformCrypto.randomBytes(16).joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
        val o = call("signatures/timestamp", buildJsonObject {
            put("hash", Base64.Default.encode(hash))
            put("hashAlgo", SHA256_OID)
            put("nonce", nonce)
        }, token)
        return o.str("timestamp")?.fromBase64() ?: throw CscException("遠端簽章服務沒有回傳時戳")
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
        private const val POLL_ATTEMPTS = 60
        private const val POLL_INTERVAL_MS = 2000L
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
        val (token, sad) = authorize(c, hash)
        onStatus("遠端簽章服務簽署中")
        val signature = client.signHash(token, c.id, listOf(hash), algorithm, sad).single()
        return if (keyTypeOf(c.certificates.first()) == SignerKeyType.EC_P256 && signature.size == 64) {
            EcSignature(signature.copyOfRange(0, 32), signature.copyOfRange(32, 64)).toDerEncoded()
        } else signature
    }

    /** The service offers raw signatures (signatures/signHash); a service without it can still sign PAdES through signDoc. */
    suspend fun supportsSignHash(): Boolean = client.info().supports("signatures/signHash")

    suspend fun supportsSignDoc(): Boolean = client.info().supports("signatures/signDoc")

    /**
     * A PAdES signature built by the service (signatures/signDoc, format P) over [signedData], the bytes a PDF
     * signature covers: returns the CMS SignedData to place in /Contents. [level] is AdES-B-B or AdES-B-T.
     */
    suspend fun signPadesDigest(signedData: ByteArray, level: String): ByteArray {
        val c = credential ?: load()
        val hash = PlatformCrypto.sha256(signedData)
        val (token, sad) = authorize(c, hash)
        onStatus("遠端簽章服務產生 PAdES 簽章")
        return client.signDoc(token, c.id, hash, "P", level, signAlgorithm(c), sad)
    }

    /**
     * The service's own time-stamp authority (signatures/timestamp) when /info lists it, so B-T and later levels use
     * the RSSP's pre-configured service as the specification intends; null otherwise.
     */
    suspend fun timestamper(): Timestamper? {
        if (!client.info().supports("signatures/timestamp")) return null
        return Timestamper { data ->
            onStatus("取得遠端簽章服務的時戳")
            client.timestamp(serviceToken(), PlatformCrypto.sha256(data))
        }
    }

    /**
     * Approves signing [hash] with the credential: implicit and explicit modes ask for a PIN or OTP and return the
     * service token with the SAD; oauth2code runs a credential-scope authorization and returns its token.
     */
    private suspend fun authorize(c: CscCredential, hash: ByteArray): Pair<CscToken, String?> = when (c.authMode) {
        "implicit", "explicit" -> {
            val token = serviceToken()
            if (c.otpNeeded && c.otpOnline) client.sendOtp(token, c.id)
            val pin = if (c.pinNeeded) agent.askSecret("遠端簽章 PIN 碼", false) ?: throw SigningException("已取消簽署") else null
            val otp = if (c.otpNeeded) agent.askSecret("一次性密碼（OTP）", true) ?: throw SigningException("已取消簽署") else null
            onStatus("遠端簽章服務授權中")
            token to client.authorizeCredential(token, c.id, listOf(hash), pin, otp, asciiDescription(hint))
        }
        else -> {
            onStatus("授權這次簽章")
            // CSC v2 lists the credential parameters; services built on the EUDI signer read only the RFC 9396
            // authorization_details form (the demo answers 400 without it), so both are sent.
            val details = buildJsonArray {
                addJsonObject {
                    put("type", "credential")
                    put("credentialID", c.id)
                    put("numSignatures", 1)
                    putJsonArray("documentDigests") {
                        addJsonObject {
                            put("hash", Base64.Default.encode(hash))
                            put("label", asciiDescription(hint))
                        }
                    }
                    put("hashAlgorithmOID", CscClient.SHA256_OID)
                }
            }.toString()
            val request = client.authorizationRequest("credential", mapOf(
                "credentialID" to c.id,
                "numSignatures" to "1",
                "hashes" to hash.toBase64Url(),
                "hashAlgorithmOID" to CscClient.SHA256_OID,
                "description" to asciiDescription(hint),
            ), details)
            val back = agent.authorize(request.url, client.service.redirectUri, "授權「${client.service.name}」簽署：$hint")
            client.token(client.code(back, request), request) to null
        }
    }

    companion object {
        /**
         * The description sent to the signing service. Services have turned Chinese text into "?" on the way back
         * (EUDI's approval screen), so non-ASCII text is replaced by a plain English line naming the file type; the
         * wallet's own screens keep the full Chinese description.
         */
        fun asciiDescription(hint: String): String {
            if (hint.all { it.code in 0x20..0x7E }) return hint
            val ext = Regex("\\.([A-Za-z0-9]{1,8})$").find(hint.trim())?.groupValues?.get(1)?.lowercase()
            return "DIW MY WALLET document signing" + (ext?.let { " (.$it file)" } ?: "")
        }

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
                SignerKeyType.EC_P256 -> if (algos.isEmpty() || CscClient.ECDSA_SHA256 in algos) CscClient.ECDSA_SHA256
                    else throw SigningException("遠端簽章憑證未宣告 SHA-256 ECDSA 演算法")
                SignerKeyType.RSA -> if (algos.isEmpty() || CscClient.RSA_SHA256 in algos) CscClient.RSA_SHA256
                    else throw SigningException("遠端簽章憑證未宣告 SHA-256 RSA 演算法")
            }
        }
    }
}

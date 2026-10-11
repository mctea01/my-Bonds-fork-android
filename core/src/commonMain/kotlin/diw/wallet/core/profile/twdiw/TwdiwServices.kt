package diw.wallet.core.profile.twdiw

import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.oid4vp.compat.TwdiwCustomField
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.hostOf
import diw.wallet.core.util.obj
import diw.wallet.core.util.queryParameters
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.util.fromBase64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** A card that can be applied for through the platform (apply/vcList, e.g. the telecom phone number cards). */
data class TwdiwCardService(val vcUid: String, val name: String, val type: Int?, val issuerServiceUrl: String?) {
    /** type 1 opens the issuer's own site or app; others are shown in an embedded page that returns an offer. */
    val opensExternally: Boolean get() = type == 1
}

/** An offline presentation service (offline/vpList, e.g. 7-ELEVEN pickup). */
data class TwdiwOfflineService(val vpUid: String, val name: String, val verifierModuleUrl: String, val logoUrl: String?)

/** Where a static code leads: an issuer page for a card (mode vc), or a presentation request (mode vp). */
sealed interface TwdiwStaticTarget {
    data class IssuerPage(val name: String?, val url: String, val opensExternally: Boolean) : TwdiwStaticTarget
    data class Request(val name: String?, val entry: TwdiwEntry.Presentation, val fields: List<TwdiwCustomField>) : TwdiwStaticTarget
}

/** A started DWVP-05 offline presentation: present [entry], then fetch the barcode with [transactionId]. */
data class TwdiwOfflineSession(
    val service: TwdiwOfflineService,
    val transactionId: String,
    val entry: TwdiwEntry.Presentation,
    val description: String?,
    val fields: List<TwdiwCustomField>,
)

/** The server-generated barcode shown at the counter, valid until [expiresAt]. */
class TwdiwBarcode(val png: ByteArray, val expiresAt: Instant)

/**
 * TWDIW platform services outside OpenID4VC: the card service catalogue, static code resolution, and the DWVP-05
 * offline presentation (convenience store pickup), whose barcode is produced and encrypted by the verifier module;
 * the wallet only proves possession of the presented card key and shows the returned PNG.
 */
class TwdiwServices(
    private val httpClient: HttpClient,
    private val trustList: TwdiwTrustList,
    private val platform: TwdiwPlatform = TwdiwPlatform.PRODUCTION,
) {
    suspend fun cardServices(name: String = ""): List<TwdiwCardService> {
        val body = getJson("${platform.frontendUrl}/api/moda/dwapp/apply/vcList?name=${name.encodeURLPathPart()}&page=0&size=50")
        return items(body, "vcItems").mapNotNull { o ->
            TwdiwCardService(o.str("vcUid") ?: return@mapNotNull null, o.str("name") ?: "", intOf(o["type"]), o.str("issuerServiceUrl"))
        }
    }

    suspend fun offlineServices(name: String = ""): List<TwdiwOfflineService> {
        val body = getJson("${platform.frontendUrl}/api/moda/dwapp/offline/vpList?name=${name.encodeURLPathPart()}&page=0&size=100")
        return items(body, "vpItems").mapNotNull { o ->
            TwdiwOfflineService(
                o.str("vpUid") ?: return@mapNotNull null,
                o.str("name") ?: "",
                o.str("verifierModuleUrl") ?: return@mapNotNull null,
                o.str("logoUrl"),
            )
        }
    }

    /** Resolves a static code (serviceUrl lookup, then the verifier's deep link for mode vp). */
    suspend fun resolveStatic(code: TwdiwEntry.StaticQr): TwdiwStaticTarget {
        val body = getJson("${platform.frontendUrl}/api/moda/dwapp/serviceUrl/${code.uid.encodeURLPathPart()}?mode=${code.mode}")
        val data = body.obj("data") ?: body
        val name = data.str("name")
        if (code.mode == "vc") {
            val url = data.str("issuerServiceUrl") ?: data.str("serviceUrl") ?: throw ProtocolException("invalid_request", "No issuer page for ${code.uid}")
            requireHttps(url)
            return TwdiwStaticTarget.IssuerPage(name, url, intOf(data["type"]) == 1)
        }
        val serviceUrl = data.str("verifierServiceUrl") ?: data.str("serviceUrl") ?: data.str("verifierModuleUrl")
            ?: throw ProtocolException("invalid_request", "No verifier service for ${code.uid}")
        requireHttps(serviceUrl)
        val vp = getJson(serviceUrl.trimEnd('/') + "/" + code.uid.encodeURLPathPart())
        val vpData = vp.obj("data") ?: vp
        val link = vpData.str("deepLink") ?: vpData.str("deeplink") ?: vpData.str("authUri")
            ?: throw ProtocolException("invalid_request", "Verifier service returned no request")
        val entry = TwdiwEntryParser.parse(link) as? TwdiwEntry.Presentation
            ?: throw ProtocolException("invalid_request", "Verifier service returned an unknown link")
        return TwdiwStaticTarget.Request(name ?: vpData.str("name"), entry, fieldsOf(vpData))
    }

    /**
     * Starts an offline presentation: the verifier module must be a listed host whose organisation is anchored,
     * and its deep link must fetch the request from the same host.
     */
    suspend fun startOffline(service: TwdiwOfflineService): TwdiwOfflineSession {
        val moduleHost = TwdiwHosts.canonicalHost(service.verifierModuleUrl)
            ?: throw ProtocolException("untrusted_verifier", "Verifier module URL is not an acceptable https URL")
        val anchored = trustList.entriesForHost(moduleHost).any { e ->
            val snap = trustList.verified(e.did)
            snap != null && snap.documentVerified && (snap.anchor == AnchorState.VERIFIED.name || platform.test)
        }
        if (!anchored) throw ProtocolException("untrusted_verifier", "$moduleHost is not an anchored organisation in the TWDIW trust list")
        val body = getJson(service.verifierModuleUrl.trimEnd('/') + "/api/ext/offline/qrcode/" + service.vpUid.encodeURLPathPart())
        checkCode(body)
        val data = body.obj("data") ?: body
        val transactionId = data.str("transactionId") ?: throw ProtocolException("invalid_request", "No transactionId")
        val link = data.str("deepLink") ?: throw ProtocolException("invalid_request", "No deep link")
        val entry = TwdiwEntryParser.parse(link) as? TwdiwEntry.Presentation
            ?: throw ProtocolException("invalid_request", "Unknown deep link")
        val requestUri = queryParameters(entry.uri)["request_uri"]
        if (requestUri != null && TwdiwHosts.canonicalHost(requestUri) != moduleHost) {
            throw ProtocolException("untrusted_verifier", "request_uri host differs from the verifier module")
        }
        return TwdiwOfflineSession(service, transactionId, entry, data.str("description"), fieldsOf(data))
    }

    /** Checks that the request fetched for [session] is the module's own request for this service. */
    fun checkOfflineRequest(session: TwdiwOfflineSession, request: ValidatedAuthorizationRequest) {
        val moduleHost = TwdiwHosts.canonicalHost(session.service.verifierModuleUrl)
        val target = request.target?.let { runCatching { hostOf(it) }.getOrNull() }
        if (target != moduleHost) throw ProtocolException("untrusted_verifier", "response_uri host differs from the verifier module")
        val definitionId = request.presentationDefinition?.str("id")
        if (definitionId != null && definitionId != session.service.vpUid) {
            throw ProtocolException("invalid_request", "Presentation definition $definitionId is not ${session.service.vpUid}")
        }
    }

    /** Fetches the counter barcode after the presentation, signed with the key of the presented card. */
    suspend fun barcode(session: TwdiwOfflineSession, holder: HolderKey): TwdiwBarcode {
        val did = holder.did ?: HolderKey.didFor(holder.publicKey, HolderKey.DID_KEY_JWK_JCS)
        val jwt = signJws(
            buildJsonObject { put("typ", "JWT"); put("alg", "ES256"); put("kid", did) },
            buildJsonObject { put("transactionId", session.transactionId) },
            holder.signingKey("ES256"),
        )
        val resp = httpClient.post(session.service.verifierModuleUrl.trimEnd('/') + "/api/ext/offline/getEncryptionData") {
            contentType(ContentType.Application.Json)
            header(HttpHeaders.Accept, "application/json")
            setBody(buildJsonObject { put("jwt", jwt) }.toString())
        }
        if (!resp.status.isSuccess()) throw ProtocolException("server_error", "getEncryptionData returned ${resp.status.value}")
        val body = DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject
        checkCode(body)
        val data = body.obj("data") ?: body
        val qr = data.str("qrcode") ?: throw ProtocolException("server_error", "No barcode returned")
        val png = qr.substringAfter("base64,", qr).let { runCatching { it.fromBase64() }.getOrNull() }
            ?: throw ProtocolException("server_error", "Barcode is not base64")
        if (png.size > MAX_PNG || png.size < 8 || !png.copyOfRange(0, 8).contentEquals(PNG_MAGIC)) {
            throw ProtocolException("server_error", "Barcode is not a PNG image")
        }
        val timeout = (data["totptimeout"] as? JsonPrimitive)?.content?.toLongOrNull() ?: DEFAULT_TIMEOUT
        return TwdiwBarcode(png, Clock.System.now() + timeout.seconds)
    }

    private fun checkCode(body: JsonObject) {
        val code = (body["code"] as? JsonPrimitive)?.content ?: return
        if (code != "0") throw ProtocolException("server_error", "TWDIW service returned code $code ${body.str("message") ?: ""}".trim())
    }

    private fun requireHttps(url: String) {
        if (TwdiwHosts.canonicalHost(url) == null) throw ProtocolException("invalid_request", "Not an acceptable https URL: $url")
    }

    private suspend fun getJson(url: String): JsonObject {
        val resp = httpClient.get(url) { header(HttpHeaders.Accept, "application/json") }
        if (!resp.status.isSuccess()) throw ProtocolException("server_error", "$url returned ${resp.status.value}")
        return DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject ?: throw ProtocolException("server_error", "$url did not return JSON")
    }

    private fun items(body: JsonObject, name: String): List<JsonObject> =
        (body.obj("data")?.arr(name) ?: body.arr(name) ?: JsonArray(emptyList())).filterIsInstance<JsonObject>()

    private fun intOf(e: kotlinx.serialization.json.JsonElement?): Int? = (e as? JsonPrimitive)?.content?.toIntOrNull()

    private fun fieldsOf(data: JsonObject): List<TwdiwCustomField> {
        val list = data.arr("fields") ?: data.obj("custom")?.arr("fields") ?: return emptyList()
        return list.filterIsInstance<JsonObject>().mapNotNull { f ->
            val ename = f.str("ename") ?: return@mapNotNull null
            TwdiwCustomField(f.str("cname") ?: ename, ename, f.str("description"), f.str("regex"))
        }
    }

    companion object {
        private const val MAX_PNG = 5 * 1024 * 1024
        private const val DEFAULT_TIMEOUT = 300L
        private val PNG_MAGIC = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    }
}

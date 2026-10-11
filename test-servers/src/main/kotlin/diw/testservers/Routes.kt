package diw.testservers

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.bool
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.withCharset
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveParameters
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

internal suspend fun ApplicationCall.respondJson(obj: JsonObject, status: HttpStatusCode = HttpStatusCode.OK) =
    respondText(obj.toString(), ContentType.Application.Json, status)

internal suspend fun ApplicationCall.receiveJsonObject(): JsonObject {
    val t = receiveText()
    return if (t.isBlank()) JsonObject(emptyMap()) else DiwJson.parseToJsonElement(t) as JsonObject
}

internal suspend fun ApplicationCall.respondError(status: HttpStatusCode, error: String, description: String) =
    respondJson(buildJsonObject { put("error", error); put("error_description", description) }, status)

private val REQUEST_OBJECT = ContentType("application", "oauth-authz-req+jwt")
private val VERIFIER_PAGE by lazy { VerifierService::class.java.getResource("/verifier.html")!!.readText() }

fun Route.verifierRoutes(service: VerifierService) {
    // Manual test page: QR code or same-device link for OpenID4VP, and a DC API button.
    get("/verifier") { call.respondText(VERIFIER_PAGE, ContentType.Text.Html.withCharset(Charsets.UTF_8)) }
    post("/verifier/sessions") {
        val body = call.receiveJsonObject()
        val req = VerifierSessionRequest(
            clientIdPrefix = body.str("client_id_prefix") ?: "x509_san_dns",
            responseMode = body.str("response_mode") ?: "direct_post.jwt",
            requestUriMethod = body.str("request_uri_method") ?: "get",
            dcql = body.obj("dcql_query") ?: VerifierService.DEFAULT_DCQL,
            tamper = body.str("tamper"),
        )
        val (s, uri) = service.create(req)
        call.respondJson(buildJsonObject { put("id", s.id); put("uri", uri) })
    }
    get("/verifier/sessions/{id}") {
        val s = service.session(call.parameters["id"]!!) ?: return@get call.respondError(HttpStatusCode.NotFound, "not_found", "unknown session")
        call.respondJson(VerifierService.resultJson(s.result))
    }
    get("/verifier/requests/{id}") {
        val jwt = runCatching { service.requestObject(call.parameters["id"]!!, null) }.getOrElse {
            return@get call.respondError(HttpStatusCode.NotFound, "not_found", it.message ?: "")
        }
        call.respondText(jwt, REQUEST_OBJECT)
    }
    post("/verifier/requests/{id}") {
        val form = call.receiveParameters()
        val jwt = runCatching { service.requestObject(call.parameters["id"]!!, form["wallet_nonce"]) }.getOrElse {
            return@post call.respondError(HttpStatusCode.NotFound, "not_found", it.message ?: "")
        }
        call.respondText(jwt, REQUEST_OBJECT)
    }
    post("/verifier/responses/{id}") {
        val form = call.receiveParameters()
        val map = form.names().associateWith { form[it]!! }
        val r = runCatching { service.receive(call.parameters["id"]!!, map) }.getOrElse {
            return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", it.message ?: "")
        }
        if (r.error != null && r.credentials.isEmpty() && map.containsKey("error")) {
            call.respondJson(buildJsonObject {})
        } else {
            call.respondJson(buildJsonObject { put("redirect_uri", "${call.request.local.scheme}://${call.request.local.serverHost}:${call.request.local.serverPort}/verifier/done/${call.parameters["id"]}") })
        }
    }
    get("/verifier/done/{id}") {
        val s = service.session(call.parameters["id"]!!)
        call.respondJson(VerifierService.resultJson(s?.result))
    }
    post("/verifier/dcapi/sessions") {
        val body = call.receiveJsonObject()
        val origin = body.str("origin") ?: return@post call.respondError(HttpStatusCode.BadRequest, "invalid_request", "origin required")
        val (s, protocol, data) = service.createDcApi(
            origin = origin,
            signed = body.bool("signed") ?: true,
            encrypted = body.bool("encrypted") ?: true,
            dcql = body.obj("dcql_query") ?: VerifierService.DEFAULT_DCQL,
        )
        call.respondJson(buildJsonObject { put("id", s.id); put("protocol", protocol); put("data", data) })
    }
    post("/verifier/dcapi/responses/{id}") {
        val body = call.receiveJsonObject()
        val r = service.receiveDcApi(call.parameters["id"]!!, body.obj("data") ?: JsonObject(emptyMap()), body.str("origin") ?: "")
        call.respondJson(VerifierService.resultJson(r))
    }
}

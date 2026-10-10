package diw.testservers

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.int
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.contentType
import io.ktor.server.request.header
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

private val HEADER_NAMES = listOf("Authorization", "DPoP", "OAuth-Client-Attestation", "OAuth-Client-Attestation-PoP")

private fun ApplicationCall.protocolHeaders(): Map<String, String?> = HEADER_NAMES.associateWith { request.header(it) }

private suspend fun ApplicationCall.send(r: IssuerReply) {
    r.headers.forEach { (k, v) -> response.header(k, v) }
    if (r.status == HttpStatusCode.NoContent) {
        respondText("", status = r.status)
    } else {
        respondText(r.body, ContentType.parse(r.contentType), r.status)
    }
}

/** Runs [block] and maps [IssuerError] and protocol errors to OAuth error responses. */
private suspend fun ApplicationCall.guard(block: suspend () -> Unit) {
    try {
        block()
    } catch (e: IssuerError) {
        e.headers.forEach { (k, v) -> response.header(k, v) }
        respondError(e.status, e.error, e.description)
    } catch (e: ProtocolException) {
        respondError(HttpStatusCode.BadRequest, e.code, e.message ?: "")
    }
}

fun Route.issuerRoutes(issuer: IssuerService) {
    get("/.well-known/openid-credential-issuer/issuer") {
        call.guard {
            val wantsJwt = call.request.header("Accept")?.contains("application/jwt") == true
            val signed = if (wantsJwt) issuer.signedIssuerMetadata() else null
            if (signed != null) call.respondText(signed, ContentType("application", "jwt"))
            else call.respondJson(issuer.issuerMetadata())
        }
    }
    get("/.well-known/oauth-authorization-server/issuer") { call.respondJson(issuer.authServerMetadata()) }

    post("/issuer/offers") {
        call.guard {
            val body = call.receiveJsonObject()
            val uri = issuer.createOffer(
                configIds = body.strList("configuration_ids").ifEmpty { listOf("pid_sd_jwt") },
                grant = body.str("grant") ?: "pre-authorized",
                txCode = body.str("tx_code"),
                byReference = body["by_reference"]?.toString() == "true",
            )
            call.respondJson(buildJsonObject { put("offer_uri", uri) })
        }
    }
    get("/issuer/offers/{id}") {
        val o = issuer.offer(call.parameters["id"]!!) ?: return@get call.respondError(HttpStatusCode.NotFound, "not_found", "unknown offer")
        call.respondJson(o)
    }
    post("/issuer/par") {
        call.guard { call.send(issuer.pushedAuthorization(IssuerService.parseForm(call.receiveText()), call.protocolHeaders())) }
    }
    get("/issuer/authorize") {
        call.guard { call.respondRedirect(issuer.authorize(call.request.queryParameters), permanent = false) }
    }
    post("/issuer/token") {
        call.guard { call.send(issuer.token(IssuerService.parseForm(call.receiveText()), call.protocolHeaders())) }
    }
    post("/issuer/nonce") { call.send(issuer.nonce()) }
    post("/issuer/credential") {
        call.guard { call.send(issuer.credential(call.receiveText(), call.request.contentType().toString(), call.protocolHeaders())) }
    }
    post("/issuer/deferred") {
        call.guard { call.send(issuer.deferredCredential(call.receiveText(), call.request.contentType().toString(), call.protocolHeaders())) }
    }
    post("/issuer/notification") {
        call.guard { call.send(issuer.notification(call.receiveText(), call.protocolHeaders())) }
    }
    get("/issuer/status/{list}") {
        val jwt = issuer.statusListJwt(call.parameters["list"]!!)
            ?: return@get call.respondError(HttpStatusCode.NotFound, "not_found", "unknown status list")
        call.respondText(jwt, ContentType("application", "statuslist+jwt"))
    }
    post("/issuer/admin/status") {
        call.guard {
            val body = call.receiveJsonObject()
            issuer.setStatus(body.str("list") ?: "sdjwt", body.int("idx") ?: 0, body.int("status") ?: 1)
            call.respondJson(buildJsonObject { put("ok", true) })
        }
    }
}

fun Route.walletProviderRoutes(provider: WalletProviderService) {
    post("/wallet-provider/wallet-attestation") {
        call.guard { call.respondJson(provider.walletAttestation(call.receiveJsonObject())) }
    }
    post("/wallet-provider/key-attestation") {
        call.guard { call.respondJson(provider.keyAttestation(call.receiveJsonObject())) }
    }
}

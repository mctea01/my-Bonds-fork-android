package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.oid4vp.ClientIdPrefix
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * walt.id verifier2 serves the request object of a redirect_uri client as plain JSON and answers 406 Not Acceptable
 * when the Accept header names only application/oauth-authz-req+jwt. The wallet must accept JSON as a fallback.
 */
class RequestUriNegotiationTest {
    private val session = "https://$HOST/verification-session/s1"

    private fun requestObject() = buildJsonObject {
        put("response_type", "vp_token")
        put("client_id", "redirect_uri:$session/response")
        put("state", "st-1")
        put("response_mode", "direct_post")
        put("nonce", "n-1")
        put("response_uri", "$session/response")
        putJsonObject("dcql_query") {
            putJsonArray("credentials") {
                addJsonObject {
                    put("id", "b")
                    put("format", "jwt_vc_json")
                    putJsonObject("meta") { putJsonArray("type_values") { add(buildJsonArray("VerifiableCredential", "OpenBadgeCredential")) } }
                }
            }
        }
    }

    private fun buildJsonArray(vararg values: String) = kotlinx.serialization.json.buildJsonArray { values.forEach { add(it) } }

    @Test
    fun jsonRequestObjectBehindContentNegotiation() = runBlocking<Unit> {
        val accepts = mutableListOf<String>()
        val http = HttpClient(MockEngine { request ->
            val accept = request.headers[HttpHeaders.Accept].orEmpty()
            accepts += accept
            if (request.url.toString() != "$session/request") respond("", HttpStatusCode.NotFound)
            else if ("application/json" !in accept) respond("", HttpStatusCode.NotAcceptable)
            else respond(requestObject().toString(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
        }) { followRedirects = false }
        val w = WalletFixture(trustVerifierRoot = false, trustIssuer = false, httpClient = http, env = EnvironmentPolicy()).init()
        val uri = "openid4vp://authorize?client_id=" + "redirect_uri:$session/response".encodeURLParameter() +
            "&request_uri=" + "$session/request".encodeURLParameter()
        val req = w.holder.resolveUri(uri)
        assertEquals(ClientIdPrefix.REDIRECT_URI, req.verifier.clientId.prefix)
        assertEquals("$session/response", req.responseUri)
        assertEquals(1, accepts.size)
        assertEquals(true, accepts.single().startsWith("application/oauth-authz-req+jwt"))
    }

    companion object {
        const val HOST = "verifier2.mock.example"
    }
}

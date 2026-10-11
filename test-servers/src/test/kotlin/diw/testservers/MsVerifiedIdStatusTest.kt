package diw.testservers

import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.signJws
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.StatusAssurance
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.toBase64Url
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.GZIPOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Microsoft Entra Verified ID status: credentialStatus RevocationList2021Status whose statusListCredential is a DID
 * URL (?service=IdentityHub&queries=...). The wallet posts the query to the Identity Hub named in the issuer's DID
 * document and checks the StatusList2021 JWT it returns, signed by the issuer DID.
 */
class MsVerifiedIdStatusTest {
    private val issuerKey = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val issuerJwk = runBlocking { issuerKey.publicKey.toJwk() }
    private val hubRequests = mutableListOf<JsonObject>()
    private val revoked = mutableSetOf<Int>()

    private fun MockRequestHandleScope.json(o: Any) =
        respond(o.toString(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))

    private suspend fun MockRequestHandleScope.handle(request: HttpRequestData): HttpResponseData = when {
        request.url.host == HOST && request.url.encodedPath == "/.well-known/did.json" -> json(buildJsonObject {
            put("id", DID)
            putJsonArray("verificationMethod") {
                addJsonObject {
                    put("id", "#key1")
                    put("controller", DID)
                    put("type", "JsonWebKey2020")
                    put("publicKeyJwk", issuerJwk)
                }
            }
            putJsonArray("assertionMethod") { add("#key1") }
            putJsonArray("service") {
                addJsonObject {
                    put("id", "#linkeddomains")
                    put("type", "LinkedDomains")
                    putJsonObject("serviceEndpoint") { putJsonArray("origins") { add("https://$HOST/") } }
                }
                addJsonObject {
                    put("id", "#hub")
                    put("type", "IdentityHub")
                    putJsonObject("serviceEndpoint") { putJsonArray("instances") { add(HUB) } }
                }
            }
        })
        request.url.toString() == HUB && request.method == HttpMethod.Post -> {
            val body = DiwJson.parseToJsonElement(request.body.toByteArray().decodeToString()) as JsonObject
            hubRequests += body
            val list = statusListJwt()
            json(buildJsonObject {
                put("requestId", body.str("requestId"))
                putJsonArray("replies") {
                    addJsonObject {
                        put("messageId", "bafyreid")
                        putJsonObject("status") { put("code", 200) }
                        putJsonArray("entries") {
                            addJsonObject {
                                putJsonObject("descriptor") {
                                    put("method", "CollectionsWrite")
                                    put("schema", SCHEMA)
                                    put("dataFormat", "application/vc+jwt")
                                    put("objectId", LIST_ID)
                                }
                                // As the hub serves it: the JWT, base64 encoded once more.
                                put("data", Base64.getEncoder().encodeToString(list.encodeToByteArray()))
                            }
                        }
                    }
                }
            })
        }
        else -> respond("not found", HttpStatusCode.NotFound)
    }

    private suspend fun statusListJwt(): String {
        val bits = ByteArray(16 * 1024)
        revoked.forEach { i -> bits[i / 8] = (bits[i / 8].toInt() or (0x80 ushr (i % 8))).toByte() }
        val gz = ByteArrayOutputStream().also { out -> GZIPOutputStream(out).use { it.write(bits) } }.toByteArray()
        return signJws(
            buildJsonObject { put("alg", "ES256"); put("typ", "JWT"); put("kid", "$DID#key1") },
            buildJsonObject {
                put("iss", DID)
                put("iat", Clock.System.now().epochSeconds)
                putJsonObject("vc") {
                    putJsonArray("@context") { add("https://www.w3.org/2018/credentials/v1"); add("https://w3id.org/vc/status-list/2021/v1") }
                    putJsonArray("type") { add("VerifiableCredential"); add("StatusList2021Credential") }
                    putJsonObject("credentialSubject") {
                        put("id", "urn:uuid:$LIST_ID")
                        put("type", "RevocationList2021")
                        put("encodedList", gz.toBase64Url())
                    }
                }
            },
            AsymmetricKey.anonymous(issuerKey, Algorithm.ES256),
        )
    }

    /** credentialStatus as Microsoft writes it, with the query base64 encoded into the DID URL. */
    private fun credential(index: Int): JsonObject {
        val queries = DiwJson.encodeToString(JsonArray.serializer(), JsonArray(listOf(buildJsonObject {
            put("method", "CollectionsQuery")
            put("schema", SCHEMA)
            put("objectId", LIST_ID)
        })))
        return buildJsonObject {
            putJsonArray("type") { add("VerifiableCredential"); add("VerifiedEmployee") }
            put("issuer", DID)
            putJsonObject("credentialSubject") { put("displayName", "Megan Bowen") }
            putJsonObject("credentialStatus") {
                put("id", "urn:uuid:$LIST_ID?bit-index=$index")
                put("type", "RevocationList2021Status")
                put("statusListIndex", index)
                put("statusListCredential", "$DID?service=IdentityHub&queries=" + Base64.getEncoder().encodeToString(queries.encodeToByteArray()))
            }
        }
    }

    @Test
    fun identityHubStatusList() = runBlocking<Unit> {
        val http = HttpClient(MockEngine { request -> handle(request) })
        val checker = CredentialStatusChecker(http, TrustRegistry(EphemeralStorage(), EnvironmentPolicy()), didTrust = DidTrust.NONE)

        val valid = checker.w3c.check(credential(12), DID, bypassCache = true)
        assertEquals(RevocationCheckState.VALID, valid.state, "detail: ${valid.detail}")
        assertTrue(valid.trusted, "the list is signed by the issuer DID")
        assertEquals(StatusAssurance.TRUSTED, valid.assurance)
        assertEquals("revocation 0x0", valid.label)

        // The hub is asked anonymously for the list: the issuer DID and the query, nothing about the holder.
        val sent = hubRequests.single()
        assertEquals(DID, sent.str("target"))
        val descriptor = ((sent["messages"] as JsonArray).single() as JsonObject)["descriptor"] as JsonObject
        assertEquals("CollectionsQuery", descriptor.str("method"))
        assertEquals(LIST_ID, descriptor.str("objectId"))

        revoked += 12
        val gone = checker.w3c.check(credential(12), DID, bypassCache = true)
        assertEquals(RevocationCheckState.INVALID, gone.state)
        assertEquals("revocation 0x1", gone.label)
        // Another credential on the same list is unaffected.
        assertEquals(RevocationCheckState.VALID, checker.w3c.check(credential(13), DID, bypassCache = true).state)
    }

    companion object {
        const val HOST = "verifiedid.mock.example"
        const val DID = "did:web:$HOST"
        const val HUB = "https://hub.mock.example/v1.0/00000000-0000-0000-0000-000000000000"
        const val SCHEMA = "https://w3id.org/vc-status-list-2021/v1"
        const val LIST_ID = "cca8bd0a-83c2-4ae1-9f43-e99943cdfa5c"
    }
}

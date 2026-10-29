package diw.testservers

import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.federation.FederationAnchor
import diw.wallet.core.federation.FederationResolver
import diw.wallet.core.federation.MetadataPolicy
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.PresentationPolicy
import diw.wallet.core.oid4vp.RawAuthorizationRequest
import diw.wallet.core.oid4vp.RequestChannel
import diw.wallet.core.oid4vp.RequestValidationException
import diw.wallet.core.oid4vp.RequestValidator
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.ProtocolException
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.storage.ephemeral.EphemeralStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * OpenID Federation 1.0: a Trust Anchor, one Intermediate and a Verifier leaf served from a mock HTTP client. The
 * Verifier's metadata passes through both statements' policies and its request object is checked with the
 * resolved jwks.
 */
class FederationTest {
    private val ta = "https://ta.example"
    private val ia = "https://ia.example"
    private val rp = "https://rp.example"

    private class Party(val key: AsymmetricKey, val kid: String, jwk: JsonObject) {
        val jwks: JsonObject = buildJsonObject { putJsonArray("keys") { add(jwk) } }
    }

    private suspend fun party(kid: String): Party {
        val key = AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), Algorithm.ES256)
        return Party(key, kid, JsonObject(key.publicKey.toJwk() + ("kid" to JsonPrimitive(kid))))
    }

    private val now get() = Clock.System.now().epochSeconds

    private suspend fun statement(signer: Party, claims: JsonObject): String = signJws(
        buildJsonObject { put("alg", "ES256"); put("typ", "entity-statement+jwt"); put("kid", signer.kid) },
        claims,
        signer.key,
    )

    private inner class Federation(val maxPathLength: Long = 1) {
        lateinit var taKey: Party
        lateinit var iaKey: Party
        lateinit var rpKey: Party
        lateinit var requestKey: Party
        val served = HashMap<String, String>()
        lateinit var chain: List<String>

        suspend fun build(): Federation {
            taKey = party("ta-1"); iaKey = party("ia-1"); rpKey = party("rp-1"); requestKey = party("rp-request")
            val taConfig = statement(taKey, buildJsonObject {
                put("iss", ta); put("sub", ta); put("iat", now); put("exp", now + 3600)
                put("jwks", taKey.jwks)
                putJsonObject("metadata") { putJsonObject("federation_entity") { put("federation_fetch_endpoint", "$ta/fetch"); put("organization_name", "Test Anchor") } }
            })
            val taAboutIa = statement(taKey, buildJsonObject {
                put("iss", ta); put("sub", ia); put("iat", now); put("exp", now + 3600)
                put("jwks", iaKey.jwks)
                putJsonObject("metadata_policy") {
                    putJsonObject("openid_credential_verifier") {
                        putJsonObject("response_types") { putJsonArray("subset_of") { add("vp_token") } }
                        putJsonObject("contacts") { putJsonArray("add") { add("ops@ta.example") } }
                    }
                }
                putJsonObject("constraints") { put("max_path_length", maxPathLength); putJsonObject("naming_constraints") { putJsonArray("permitted") { add(".example"); add("rp.example"); add("ia.example") } } }
            })
            val iaConfig = statement(iaKey, buildJsonObject {
                put("iss", ia); put("sub", ia); put("iat", now); put("exp", now + 3600)
                put("jwks", iaKey.jwks)
                putJsonArray("authority_hints") { add(ta) }
                putJsonObject("metadata") { putJsonObject("federation_entity") { put("federation_fetch_endpoint", "$ia/fetch") } }
            })
            val iaAboutRp = statement(iaKey, buildJsonObject {
                put("iss", ia); put("sub", rp); put("iat", now); put("exp", now + 1800)
                put("jwks", rpKey.jwks)
                putJsonObject("metadata_policy") {
                    putJsonObject("openid_credential_verifier") { putJsonObject("logo_uri") { put("default", "https://ia.example/logo.png") } }
                }
            })
            val rpConfig = statement(rpKey, buildJsonObject {
                put("iss", rp); put("sub", rp); put("iat", now); put("exp", now + 3600)
                put("jwks", rpKey.jwks)
                putJsonArray("authority_hints") { add(ia) }
                putJsonObject("metadata") {
                    putJsonObject("openid_credential_verifier") {
                        put("client_name", "Federated Verifier")
                        putJsonArray("response_types") { add("vp_token"); add("code") }
                        put("jwks", requestKey.jwks)
                    }
                }
            })
            served["$ta/.well-known/openid-federation"] = taConfig
            served["$ta/fetch?sub=https%3A%2F%2Fia.example"] = taAboutIa
            served["$ia/.well-known/openid-federation"] = iaConfig
            served["$ia/fetch?sub=https%3A%2F%2Frp.example"] = iaAboutRp
            served["$rp/.well-known/openid-federation"] = rpConfig
            chain = listOf(rpConfig, iaAboutRp, taAboutIa, taConfig)
            return this
        }

        fun http(online: Boolean = true) = HttpClient(MockEngine { request ->
            val body = if (online) served[request.url.toString()] else null
            if (body == null) respond("", HttpStatusCode.NotFound)
            else respond(body, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/entity-statement+jwt"))
        })

        suspend fun anchor(environment: TrustEnvironment = TrustEnvironment.USER, keys: JsonObject? = null) =
            FederationAnchor(ta, (keys ?: taKey.jwks).toString(), "Test Anchor", environment.id, addedAt = 0)
    }

    private suspend fun request(f: Federation, trustChain: List<String>? = null, signer: Party = f.requestKey): RawAuthorizationRequest {
        val clientId = "openid_federation:$rp"
        val payload = buildJsonObject {
            put("client_id", clientId)
            put("response_type", "vp_token")
            put("response_mode", "direct_post")
            put("response_uri", "$rp/callback")
            put("nonce", "a-nonce-that-is-long-enough-1234")
            put("dcql_query", buildJsonObject { put("credentials", buildJsonArray { }) })
        }
        val header = buildJsonObject {
            put("alg", "ES256"); put("typ", "oauth-authz-req+jwt"); put("kid", signer.kid)
            trustChain?.let { c -> put("trust_chain", JsonArray(c.map { JsonPrimitive(it) })) }
        }
        val compact = signJws(header, payload, signer.key)
        return RawAuthorizationRequest(RequestChannel.URI, mapOf("client_id" to clientId), Jws.parse(compact), payload, null, null)
    }

    private fun validator(http: HttpClient, anchors: List<FederationAnchor>) = RequestValidator(
        TrustRegistry(EphemeralStorage(), EnvironmentPolicy()), DidResolver(http), PresentationPolicy(), false,
        federation = FederationResolver(http, { anchors }),
    )

    @Test
    fun resolvedMetadataFollowsEveryPolicy() = runBlocking<Unit> {
        val f = Federation().build()
        val r = FederationResolver(f.http(), { listOf(f.anchor()) }).resolve(rp, FederationResolver.VERIFIER)
        assertEquals(listOf(rp, ia, ta), r.path)
        assertEquals(listOf("vp_token"), r.metadata["response_types"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("ops@ta.example"), r.metadata["contacts"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("https://ia.example/logo.png", r.metadata["logo_uri"]!!.jsonPrimitive.content)
        assertEquals("Federated Verifier", r.displayName)
        assertTrue(r.expiresAt <= now + 1800)
    }

    @Test
    fun federatedVerifierIsAuthenticatedByItsResolvedKeys() = runBlocking<Unit> {
        val f = Federation().build()
        val v = validator(f.http(), listOf(f.anchor())).validate(request(f))
        assertEquals(TrustTier.T2, v.verifier.trust.tier)
        assertTrue(TrustLabel.OPENID_FEDERATION in v.verifier.trust.labels)
        assertEquals("Federated Verifier", v.verifier.displayName)

        val test = validator(f.http(), listOf(f.anchor(TrustEnvironment.TEST))).validate(request(f))
        assertEquals(TrustTier.T3, test.verifier.trust.tier)
        assertTrue(TrustLabel.TEST_ANCHOR in test.verifier.trust.labels)
    }

    @Test
    fun trustChainHeaderWorksOffline() = runBlocking<Unit> {
        val f = Federation().build()
        val v = validator(f.http(online = false), listOf(f.anchor())).validate(request(f, trustChain = f.chain))
        assertEquals(TrustTier.T2, v.verifier.trust.tier)
        assertFailsWith<RequestValidationException> {
            validator(f.http(online = false), listOf(f.anchor())).validate(request(f))
        }
    }

    @Test
    fun requestsAndChainsThatDoNotHoldAreRejected() = runBlocking<Unit> {
        val f = Federation().build()
        // Signed with the federation key instead of a key in the Verifier metadata.
        val wrongSigner = assertFailsWith<RequestValidationException> { validator(f.http(), listOf(f.anchor())).validate(request(f, signer = f.rpKey)) }
        assertTrue("not signed by a key of" in wrongSigner.message.orEmpty(), wrongSigner.message)
        // The configured anchor keys are not the ones that signed the chain.
        val other = party("ta-1").jwks
        val wrongAnchor = assertFailsWith<RequestValidationException> { validator(f.http(), listOf(f.anchor(keys = other))).validate(request(f)) }
        assertTrue("does not verify" in wrongAnchor.message.orEmpty(), wrongAnchor.message)
        // No anchor at all.
        val none = assertFailsWith<RequestValidationException> { validator(f.http(), emptyList()).validate(request(f)) }
        assertTrue("No OpenID Federation Trust Anchor" in none.message.orEmpty(), none.message)
        // The anchor allows no intermediate between itself and the leaf.
        val strict = Federation(maxPathLength = 0).build()
        val tooLong = assertFailsWith<ProtocolException> {
            FederationResolver(strict.http(), { listOf(strict.anchor()) }).resolveChain(strict.chain, FederationResolver.VERIFIER)
        }
        assertTrue("allows at most 0 intermediates" in tooLong.message.orEmpty(), tooLong.message)
    }

    @Test
    fun policiesThatContradictEachOtherFail() {
        val a = buildJsonObject { putJsonObject("client_name") { put("value", "A") } }
        val b = buildJsonObject { putJsonObject("client_name") { put("value", "B") } }
        assertFailsWith<ProtocolException> { MetadataPolicy.merge(a, b, emptySet()) }
        val oneOf = buildJsonObject { putJsonObject("alg") { putJsonArray("one_of") { add("ES256") } } }
        val other = buildJsonObject { putJsonObject("alg") { putJsonArray("one_of") { add("RS256") } } }
        assertFailsWith<ProtocolException> { MetadataPolicy.merge(oneOf, other, emptySet()) }
        val essential = buildJsonObject { putJsonObject("jwks") { put("essential", true) } }
        assertFailsWith<ProtocolException> { MetadataPolicy.apply(MetadataPolicy.merge(JsonObject(emptyMap()), essential, emptySet()), JsonObject(emptyMap())) }
        val crit = buildJsonObject { putJsonObject("alg") { put("regexp", "^ES") } }
        assertFailsWith<ProtocolException> { MetadataPolicy.merge(JsonObject(emptyMap()), crit, setOf("regexp")) }
        assertEquals(JsonObject(emptyMap()), MetadataPolicy.merge(JsonObject(emptyMap()), crit, emptySet())["alg"])
    }
}

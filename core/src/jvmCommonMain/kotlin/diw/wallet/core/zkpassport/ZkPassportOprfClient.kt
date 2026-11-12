package diw.wallet.core.zkpassport

import io.ktor.client.HttpClient
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * The project OPRF on a diw-wallet-server (`oprf` feature, docs/design/zkpassport.md 5.5). The server publishes its
 * key at `/oprf/v1/key` and answers blinded queries at `/oprf/v1/evaluate` with the wallet's server token; it never
 * sees the private nullifier. [publicKey] is the key read by [connect], which the prover checks every answer against.
 */
class ZkPassportOprfClient private constructor(
    private val http: HttpClient,
    private val server: String,
    private val token: String?,
    val keyId: String,
    override val publicKey: JsonObject,
) : ZkPassportProver.Oprf {
    override suspend fun evaluate(blindedQuery: JsonObject): JsonObject {
        val response = try {
            http.post("$server/oprf/v1/evaluate") {
                contentType(ContentType.Application.Json)
                token?.let { bearerAuth(it) }
                setBody(buildJsonObject { put("key_id", keyId); put("blinded_query", blindedQuery) }.toString())
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            throw ZkPassportProver.Failure("oprf_unreachable")
        }
        when {
            response.status == HttpStatusCode.Unauthorized || response.status == HttpStatusCode.Forbidden -> throw ZkPassportProver.Failure("oprf_denied")
            response.status == HttpStatusCode.TooManyRequests -> throw ZkPassportProver.Failure("oprf_rate_limited")
            !response.status.isSuccess() -> throw ZkPassportProver.Failure("oprf_unreachable")
        }
        val answer = runCatching { Json.parseToJsonElement(response.bodyAsText()).jsonObject }.getOrNull()
            ?: throw ZkPassportProver.Failure("oprf_answer")
        // The key must be the one read at connect; the proof is checked against it either way.
        if (answer["pk"]?.let { same(it as? JsonObject, publicKey) } == false) throw ZkPassportProver.Failure("oprf_key_changed")
        return answer
    }

    companion object {
        /** Reads the server's OPRF key; fails with `oprf_unavailable` when the server does not offer the OPRF. */
        suspend fun connect(http: HttpClient, server: String, token: String?): ZkPassportOprfClient {
            val base = server.trimEnd('/')
            val response = try {
                http.get("$base/oprf/v1/key")
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                throw ZkPassportProver.Failure("oprf_unreachable")
            }
            if (!response.status.isSuccess()) throw ZkPassportProver.Failure("oprf_unavailable")
            val o = runCatching { Json.parseToJsonElement(response.bodyAsText()).jsonObject }.getOrNull()
            val keyId = (o?.get("key_id") as? JsonPrimitive)?.contentOrNull
            val pk = o?.get("pk") as? JsonObject
            if (keyId.isNullOrEmpty() || pk == null || coordinate(pk, "x") == null || coordinate(pk, "y") == null) {
                throw ZkPassportProver.Failure("oprf_unavailable")
            }
            return ZkPassportOprfClient(http, base, token, keyId, pk)
        }

        private fun coordinate(o: JsonObject, key: String) =
            (o[key] as? JsonPrimitive)?.contentOrNull?.let { v ->
                if (v.startsWith("0x")) v.drop(2).toBigIntegerOrNull(16) else v.toBigIntegerOrNull()
            }

        /** Same point, whatever the hex or decimal spelling. */
        fun same(a: JsonObject?, b: JsonObject?): Boolean =
            a != null && b != null && coordinate(a, "x") != null && coordinate(a, "x") == coordinate(b, "x") &&
                coordinate(a, "y") != null && coordinate(a, "y") == coordinate(b, "y")
    }
}

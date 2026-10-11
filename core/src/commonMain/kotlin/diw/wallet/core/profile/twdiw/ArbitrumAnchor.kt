package diw.wallet.core.profile.twdiw

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/** Result of checking a trust list entry against the TWDIW registry contract. */
enum class AnchorState {
    /** The registration transaction succeeded on the contract and the current on-chain document equals the API's. */
    VERIFIED,
    /** The entry lists no registration transaction. */
    NOT_ANCHORED,
    /** The chain disagrees with the API (different document, wrong contract, failed or revoked registration). */
    MISMATCH,
    /** No RPC endpoint answered. */
    UNAVAILABLE,
    /** Sandbox or UAT entries are not anchored on the production contract. */
    DEVELOPMENT_SANDBOX,
}

data class AnchorResult(val state: AnchorState, val txHash: String? = null, val blockNumber: Long? = null, val detail: String? = null)

/** A registration transaction listed in a trust list entry (onChainHistory). */
data class OnChainRecord(val net: String?, val contract: String?, val txHash: String, val status: String?, val createdAt: String?)

/**
 * Checks TWDIW DID registrations on Arbitrum One by JSON-RPC: the listed transaction must be a successful call of
 * the registry contract registering this DID and document, and getDocById must return the same document, not revoked.
 * Plain text is stored on chain, so documents are compared byte for byte.
 */
class ArbitrumAnchor(
    private val httpClient: HttpClient,
    private val platform: TwdiwPlatform = TwdiwPlatform.PRODUCTION,
) {
    suspend fun check(did: String, signedDocument: String, history: List<OnChainRecord>): AnchorResult {
        if (platform.test) return AnchorResult(AnchorState.DEVELOPMENT_SANDBOX)
        val records = history.filter { it.contract == null || it.contract.equals(platform.anchorContract, ignoreCase = true) }
        if (records.isEmpty()) return AnchorResult(AnchorState.NOT_ANCHORED, detail = "No registration transaction listed")
        return try {
            val current = getDocById(did)
                ?: return AnchorResult(AnchorState.MISMATCH, detail = "The registry contract has no document for $did")
            if (current.revoked) return AnchorResult(AnchorState.MISMATCH, detail = "The registry marks $did as revoked")
            if (current.signedDocument != signedDocument) {
                return AnchorResult(AnchorState.MISMATCH, detail = "The on-chain document differs from the trust list document")
            }
            var last: AnchorResult? = null
            for (r in records.reversed()) {
                val result = checkTransaction(r.txHash, did)
                if (result.state == AnchorState.VERIFIED) return result
                last = result
            }
            last ?: AnchorResult(AnchorState.NOT_ANCHORED)
        } catch (e: RpcUnavailable) {
            AnchorResult(AnchorState.UNAVAILABLE, detail = e.message)
        }
    }

    private suspend fun checkTransaction(txHash: String, did: String): AnchorResult {
        val tx = rpc("eth_getTransactionByHash", JsonPrimitive(txHash)) as? JsonObject
            ?: return AnchorResult(AnchorState.MISMATCH, txHash, detail = "Transaction not found")
        val receipt = rpc("eth_getTransactionReceipt", JsonPrimitive(txHash)) as? JsonObject
            ?: return AnchorResult(AnchorState.MISMATCH, txHash, detail = "Transaction receipt not found")
        if (!tx.str("to").equals(platform.anchorContract, ignoreCase = true)) {
            return AnchorResult(AnchorState.MISMATCH, txHash, detail = "Transaction is not a call of the registry contract")
        }
        if (receipt.str("status") != "0x1") return AnchorResult(AnchorState.MISMATCH, txHash, detail = "Registration transaction failed")
        val input = Abi.hex(tx.str("input") ?: "")
        if (input.size < 4 || Abi.toHex(input.copyOfRange(0, 4)) != REGISTER_SELECTOR) {
            return AnchorResult(AnchorState.MISMATCH, txHash, detail = "Transaction is not a DID registration")
        }
        val args = input.copyOfRange(4, input.size)
        val registeredDid = runCatching { Abi.string(args, 0) }.getOrNull()
        if (registeredDid != did) return AnchorResult(AnchorState.MISMATCH, txHash, detail = "Transaction registers a different DID")
        val block = tx.str("blockNumber")?.removePrefix("0x")?.toLongOrNull(16)
        return AnchorResult(AnchorState.VERIFIED, txHash, block)
    }

    private data class OnChainDocument(val signedDocument: String, val organisation: String, val revoked: Boolean)

    private suspend fun getDocById(did: String): OnChainDocument? {
        val data = "0x" + GET_DOC_SELECTOR + Abi.toHex(Abi.encodeBytes(did.encodeToByteArray()))
        val call = buildJsonObject { put("to", platform.anchorContract); put("data", data) }
        val result = (rpc("eth_call", call, JsonPrimitive("latest")) as? JsonPrimitive)?.content ?: return null
        val raw = Abi.hex(result)
        // The contract returns one struct: a head word pointing at it (0x20), then its fields relative to that offset.
        val out = if (raw.size >= 32 * 6 && Abi.uintAt(raw, 0) == 32) raw.copyOfRange(32, raw.size) else raw
        if (out.size < 32 * 5) return null
        val doc = Abi.string(out, 0)
        if (doc.isEmpty()) return null
        return OnChainDocument(doc, Abi.string(out, 1), Abi.word(out, 4).any { it != 0.toByte() })
    }

    private class RpcUnavailable(message: String) : Exception(message)

    private suspend fun rpc(method: String, vararg params: JsonElement): JsonElement? {
        var lastError: String? = null
        for (url in platform.arbitrumRpcUrls) {
            try {
                val body = buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", 1)
                    put("method", method)
                    putJsonArray("params") { params.forEach { add(it) } }
                }
                val resp = httpClient.post(url) {
                    contentType(ContentType.Application.Json)
                    setBody(body.toString())
                }
                if (!resp.status.isSuccess()) { lastError = "RPC $url returned ${resp.status.value}"; continue }
                val json = DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject
                if (json["error"] != null) { lastError = "RPC error: ${json["error"]}"; continue }
                return json["result"]
            } catch (e: Exception) {
                lastError = e.message
            }
        }
        throw RpcUnavailable(lastError ?: "No RPC endpoint configured")
    }

    companion object {
        /** register(string did, string signedDidDocument, string organisation, ...) */
        const val REGISTER_SELECTOR = "f6e0d282"
        /** getDocById(bytes) returns the struct (string signedDidDocument, string organisation, orgType, orgGroup, bool revoked) */
        const val GET_DOC_SELECTOR = "fba6fe49"
    }
}

/** Minimal Solidity ABI helpers for the registry contract. */
internal object Abi {
    fun hex(s: String): ByteArray {
        val t = s.removePrefix("0x")
        require(t.length % 2 == 0) { "Odd hex length" }
        return ByteArray(t.length / 2) { t.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun toHex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    fun word(data: ByteArray, index: Int): ByteArray = data.copyOfRange(index * 32, index * 32 + 32)

    /** The head word at byte [offset] as an unsigned integer. */
    fun uintAt(data: ByteArray, offset: Int): Int = uint(data, offset)

    private fun uint(data: ByteArray, offset: Int): Int {
        val w = data.copyOfRange(offset, offset + 32)
        require(w.copyOfRange(0, 28).all { it == 0.toByte() }) { "ABI value out of range" }
        return ((w[28].toInt() and 0xff) shl 24) or ((w[29].toInt() and 0xff) shl 16) or ((w[30].toInt() and 0xff) shl 8) or (w[31].toInt() and 0xff)
    }

    /** The dynamic string (or bytes) whose offset is head word [index]. */
    fun string(data: ByteArray, index: Int): String {
        val offset = uint(data, index * 32)
        val length = uint(data, offset)
        require(offset + 32 + length <= data.size) { "ABI string out of bounds" }
        return data.copyOfRange(offset + 32, offset + 32 + length).decodeToString()
    }

    /** ABI encoding of a single dynamic bytes argument. */
    fun encodeBytes(value: ByteArray): ByteArray {
        val padded = (value.size + 31) / 32 * 32
        val out = ByteArray(64 + padded)
        out[31] = 0x20
        val n = value.size
        out[60] = (n ushr 24).toByte(); out[61] = (n ushr 16).toByte(); out[62] = (n ushr 8).toByte(); out[63] = n.toByte()
        value.copyInto(out, 64)
        return out
    }
}

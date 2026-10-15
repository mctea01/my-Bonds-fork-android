package diw.wallet.core.document.opencerts

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.OpenCertOnline
import diw.wallet.core.util.DiwJson
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlin.time.Clock

/** A TXT record an issuer publishes at its domain: openatts net=ethereum netId=1 addr=0x..., or a DNS-DID key. */
data class OaDnsRecord(val type: String, val net: String?, val netId: String?, val addr: String?, val didKey: String?)

/**
 * The online half of OpenAttestation verification, as oa-verify and opencerts-verify do it, without an Infura key:
 * - issuance status: the document store's isIssued and isRevoked (batched or per intermediate hash), a token
 *   registry's ownerOf, or the DID signature over the Merkle root (secp256k1, recovered to the did:ethr address) with
 *   its revocation store or OCSP responder;
 * - issuer identity: DNS-TXT records (openatts net=ethereum netId addr) or DNS-DID records read over DNS-over-HTTPS,
 *   and the OpenCerts registry of document stores.
 * The Ethereum network comes from the issuer's DNS record (netId), mainnet otherwise; public JSON-RPC endpoints are
 * tried in turn. A query that cannot run leaves the check NOT_CHECKED with the reason, never FAIL.
 */
class OpenAttestationOnline(
    private val http: HttpClient,
    private val rpc: Map<String, List<String>> = DEFAULT_RPC,
    private val dohs: List<String> = DEFAULT_DOH,
    private val registryUrl: String? = OPENCERTS_REGISTRY,
) {
    private class Outcome(val check: Check, val lines: List<String>)

    suspend fun verify(doc: OpenAttestationDocument): OpenCertOnline {
        val records = HashMap<String, List<OaDnsRecord>>()
        suspend fun dns(location: String): List<OaDnsRecord> = records.getOrPut(location.lowercase()) { txt(location) }
        val registry = registryUrl?.let { runCatching { registry(it) }.getOrNull() }
        val identity = identity(doc, ::dns, registry)
        val issuance = issuance(doc, ::dns)
        val registryName = registry?.let { r ->
            doc.issuers.mapNotNull { i -> i.value?.let { v -> r.entries.firstOrNull { it.key.equals(v, ignoreCase = true) }?.value } }.firstOrNull()
        }
        return OpenCertOnline(Clock.System.now().epochSeconds, issuance.check, issuance.lines, identity.check, identity.lines, registryName)
    }

    // ---------------------------------------------------------------- issuer identity

    private suspend fun identity(doc: OpenAttestationDocument, dns: suspend (String) -> List<OaDnsRecord>, registry: Map<String, String>?): Outcome {
        val lines = ArrayList<String>()
        var anyValid = false
        var unreachable = false
        for (issuer in doc.issuers) {
            val who = issuer.name ?: "發行者"
            val inRegistry = registry?.entries?.firstOrNull { e -> issuer.value != null && e.key.equals(issuer.value, ignoreCase = true) }
            if (inRegistry != null) {
                anyValid = true
                lines.add("$who：文件庫列在 OpenCerts 官方登錄（${inRegistry.value}）")
            }
            val location = issuer.identityLocation
            when (issuer.identityType) {
                "DNS-TXT" -> if (location != null && issuer.value != null) {
                    val found = try {
                        dns(location).filter { it.type == "openatts" && it.net == "ethereum" && it.addr.equals(issuer.value, ignoreCase = true) }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        unreachable = true
                        lines.add("$who：無法查詢 $location 的 DNS 紀錄（${e.message ?: e::class.simpleName}）")
                        null
                    }
                    if (found != null) {
                        if (found.isNotEmpty()) {
                            anyValid = true
                            lines.add("$who：$location 的 DNS TXT 紀錄指向這個文件庫（網路 ${netName(found.first().netId)}）")
                        } else lines.add("$who：$location 的 DNS 紀錄沒有這個文件庫，網域無法證明發行者身分")
                    }
                }
                "DNS-DID" -> if (location != null && issuer.identityKey != null) {
                    val found = try {
                        dns(location).any { it.didKey.equals(issuer.identityKey, ignoreCase = true) }
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        unreachable = true
                        lines.add("$who：無法查詢 $location 的 DNS 紀錄（${e.message ?: e::class.simpleName}）")
                        null
                    }
                    if (found == true) {
                        anyValid = true
                        lines.add("$who：$location 的 DNS 紀錄列出簽署金鑰 ${issuer.identityKey}")
                    } else if (found == false) lines.add("$who：$location 的 DNS 紀錄沒有簽署金鑰 ${issuer.identityKey}")
                }
                else -> if (inRegistry == null) lines.add("$who：沒有 DNS 身分證明（${issuer.identityType ?: "未提供"}），也不在 OpenCerts 登錄")
            }
        }
        if (registry == null && registryUrl != null) lines.add("無法讀取 OpenCerts 官方登錄")
        val check = when {
            anyValid -> Check.PASS
            unreachable -> Check.NOT_CHECKED
            else -> Check.FAIL
        }
        return Outcome(check, lines)
    }

    // ---------------------------------------------------------------- issuance and revocation

    private suspend fun issuance(doc: OpenAttestationDocument, dns: suspend (String) -> List<OaDnsRecord>): Outcome {
        val root = doc.merkleRoot ?: return Outcome(Check.FAIL, listOf("文件沒有 Merkle root"))
        val target = doc.targetHash ?: return Outcome(Check.FAIL, listOf("文件沒有 target hash"))
        val lines = ArrayList<String>()
        val results = ArrayList<Check>()
        if (doc.issuers.isEmpty()) return Outcome(Check.FAIL, listOf("文件沒有發行者"))
        for (issuer in doc.issuers) {
            val who = issuer.name ?: "發行者"
            val result = try {
                when (issuer.method) {
                    OaMethod.DOCUMENT_STORE -> documentStore(issuer, root, target, doc.proofs, chainFor(issuer, dns), who, lines)
                    OaMethod.TOKEN_REGISTRY -> tokenRegistry(issuer, root, chainFor(issuer, dns), who, lines)
                    OaMethod.DID -> didSigned(doc, issuer, root, target, who, lines)
                    OaMethod.NONE -> { lines.add("$who：沒有文件庫、權杖登錄或 DID，無法查驗是否確實發行"); Check.FAIL }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                lines.add("$who：無法查詢（${e.message ?: e::class.simpleName}）")
                Check.NOT_CHECKED
            }
            results.add(result)
        }
        val check = when {
            results.any { it == Check.FAIL } -> Check.FAIL
            results.all { it == Check.PASS } -> Check.PASS
            else -> Check.NOT_CHECKED
        }
        return Outcome(check, lines)
    }

    /** The chain of the issuer's DNS-TXT record for its contract, mainnet when there is none. */
    private suspend fun chainFor(issuer: OaIssuer, dns: suspend (String) -> List<OaDnsRecord>): String {
        val location = issuer.identityLocation ?: return "1"
        if (issuer.identityType != "DNS-TXT") return "1"
        val records = runCatching { dns(location) }.getOrDefault(emptyList())
        return records.firstOrNull { it.type == "openatts" && it.addr.equals(issuer.value, ignoreCase = true) }?.netId ?: "1"
    }

    private suspend fun documentStore(issuer: OaIssuer, root: String, target: String, proofs: List<String>, chain: String, who: String, lines: MutableList<String>): Check {
        val store = issuer.value ?: return Check.FAIL
        val batchable = runCatching { abiBool(call(chain, store, SUPPORTS_INTERFACE + word(BATCHABLE_INTERFACE.padEnd(64, '0')))) }.getOrDefault(false)
        val issued = try {
            abiBool(call(chain, store, if (batchable) batchCall(IS_ISSUED_BATCH, root, target, proofs) else IS_ISSUED + word(root)))
        } catch (e: RpcRevert) {
            lines.add("$who：文件庫 $store 在 ${netName(chain)} 上無法呼叫（${e.message}）")
            return Check.FAIL
        }
        if (!issued) {
            lines.add("$who：文件庫 $store（${netName(chain)}）沒有發行這份文件")
            return Check.FAIL
        }
        val revoked = if (batchable) abiBool(call(chain, store, batchCall(IS_REVOKED_BATCH, root, target, proofs)))
        else OpenAttestationDocument.intermediateHashes(target, proofs).any { h -> abiBool(call(chain, store, IS_REVOKED + word(h))) }
        if (revoked) {
            lines.add("$who：文件庫 $store（${netName(chain)}）已撤銷這份文件")
            return Check.FAIL
        }
        lines.add("$who：文件庫 $store（${netName(chain)}）已發行且未撤銷")
        return Check.PASS
    }

    private suspend fun tokenRegistry(issuer: OaIssuer, root: String, chain: String, who: String, lines: MutableList<String>): Check {
        val registry = issuer.value ?: return Check.FAIL
        return try {
            val owner = "0x" + call(chain, registry, OWNER_OF + word(root)).removePrefix("0x").takeLast(40)
            lines.add("$who：權杖登錄 $registry（${netName(chain)}）已鑄造這份文件，持有者 $owner")
            Check.PASS
        } catch (e: RpcRevert) {
            lines.add("$who：權杖登錄 $registry（${netName(chain)}）沒有這份文件（${e.message}）")
            Check.FAIL
        }
    }

    private suspend fun didSigned(doc: OpenAttestationDocument, issuer: OaIssuer, root: String, target: String, who: String, lines: MutableList<String>): Check {
        val key = issuer.identityKey ?: issuer.value?.let { v -> doc.didSignatures.firstOrNull { it.key.startsWith(v, ignoreCase = true) }?.key }
        val sig = doc.didSignatures.firstOrNull { key != null && it.key.equals(key, ignoreCase = true) } ?: doc.didSignatures.singleOrNull()
        if (sig == null) {
            lines.add("$who：沒有 DID 簽章")
            return Check.FAIL
        }
        val address = ethrAddress(sig.key)
        if (address == null) {
            lines.add("$who：只支援 did:ethr 金鑰（${sig.key}）")
            return Check.NOT_CHECKED
        }
        // ethers verifyMessage: EIP-191 personal message over the 32 bytes of the Merkle root.
        val message = DocCryptoUtil.unhex(root.removePrefix("0x"))
        val hash = DocCrypto.keccak256("\u0019Ethereum Signed Message:\n32".encodeToByteArray() + message)
        val recovered = runCatching { DocCrypto.ecRecoverAddress(hash, DocCryptoUtil.unhex(sig.signature.removePrefix("0x"))) }.getOrNull()
        if (recovered == null || !DocCryptoUtil.hex(recovered).equals(address, ignoreCase = true)) {
            lines.add("$who：Merkle root 不是由 ${sig.key} 簽署")
            return Check.FAIL
        }
        lines.add("$who：Merkle root 由 ${sig.key} 簽署")
        return when (issuer.revocationType) {
            null, "NONE" -> { lines.add("$who：發行者未設撤銷機制"); Check.PASS }
            "REVOCATION_STORE" -> {
                val store = issuer.revocationLocation ?: return Check.FAIL
                val revoked = OpenAttestationDocument.intermediateHashes(target, doc.proofs).any { h -> abiBool(call("1", store, IS_REVOKED + word(h))) }
                if (revoked) { lines.add("$who：撤銷登錄 $store 已撤銷這份文件"); Check.FAIL } else { lines.add("$who：撤銷登錄 $store 未撤銷"); Check.PASS }
            }
            "OCSP_RESPONDER" -> {
                val location = issuer.revocationLocation ?: return Check.FAIL
                for (h in OpenAttestationDocument.intermediateHashes(target, doc.proofs)) {
                    val resp = http.get(location.trimEnd('/') + "/0x" + h)
                    if (!resp.status.isSuccess()) throw IllegalStateException("OCSP 回應 ${resp.status.value}")
                    val o = DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject ?: throw IllegalStateException("OCSP 回應格式不正確")
                    if ((o["revoked"] as? JsonPrimitive)?.contentOrNull == "true") {
                        lines.add("$who：OCSP 服務 $location 回報已撤銷（原因碼 ${(o["reasonCode"] as? JsonPrimitive)?.contentOrNull ?: "未提供"}）")
                        return Check.FAIL
                    }
                }
                lines.add("$who：OCSP 服務 $location 回報未撤銷")
                Check.PASS
            }
            else -> { lines.add("$who：不支援的撤銷方式 ${issuer.revocationType}"); Check.NOT_CHECKED }
        }
    }

    // ---------------------------------------------------------------- DNS

    /** TXT records of [name] over DNS-over-HTTPS (JSON API), trying each resolver in turn. */
    suspend fun txt(name: String): List<OaDnsRecord> {
        var last: Exception? = null
        for (doh in dohs) {
            try {
                val resp = http.get(doh) {
                    parameter("name", name)
                    parameter("type", "TXT")
                    header(HttpHeaders.Accept, "application/dns-json")
                }
                if (!resp.status.isSuccess()) throw IllegalStateException("DNS 查詢回應 ${resp.status.value}")
                val o = DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject ?: throw IllegalStateException("DNS 回應格式不正確")
                val answers = (o["Answer"] as? JsonArray).orEmpty().mapNotNull { a ->
                    val r = a as? JsonObject ?: return@mapNotNull null
                    if ((r["type"] as? JsonPrimitive)?.contentOrNull != "16") return@mapNotNull null
                    (r["data"] as? JsonPrimitive)?.contentOrNull
                }
                return answers.mapNotNull { parseRecord(it) }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: IllegalStateException("沒有可用的 DNS 查詢服務")
    }

    // ---------------------------------------------------------------- Ethereum

    private class RpcRevert(message: String) : Exception(message)

    /** eth_call on [chain]: the hex result, [RpcRevert] when the contract reverts or is missing. */
    private suspend fun call(chain: String, to: String, data: String): String {
        val endpoints = rpc[chain] ?: throw IllegalStateException("不支援的以太坊網路 ${netName(chain)}")
        var last: Exception? = null
        for (url in endpoints) {
            try {
                val body = buildJsonObject {
                    put("jsonrpc", "2.0")
                    put("id", 1)
                    put("method", "eth_call")
                    put("params", buildJsonArray {
                        add(buildJsonObject { put("to", to); put("data", data) })
                        add(JsonPrimitive("latest"))
                    })
                }
                val resp = http.post(url) {
                    contentType(ContentType.Application.Json)
                    setBody(body.toString())
                }
                if (!resp.status.isSuccess()) throw IllegalStateException("RPC 回應 ${resp.status.value}")
                val o = DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject ?: throw IllegalStateException("RPC 回應格式不正確")
                (o["error"] as? JsonObject)?.let { err ->
                    val message = (err["message"] as? JsonPrimitive)?.contentOrNull ?: "execution reverted"
                    if (message.contains("revert", ignoreCase = true)) throw RpcRevert(message)
                    throw IllegalStateException(message)
                }
                val result = (o["result"] as? JsonPrimitive)?.contentOrNull ?: throw IllegalStateException("RPC 沒有結果")
                // A call to an address without code returns 0x.
                if (result == "0x") throw RpcRevert("合約不存在")
                return result
            } catch (e: RpcRevert) {
                throw e
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: IllegalStateException("沒有可用的以太坊節點")
    }

    private suspend fun registry(url: String): Map<String, String> {
        val resp = http.get(url)
        if (!resp.status.isSuccess()) throw IllegalStateException("登錄回應 ${resp.status.value}")
        val issuers = (DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject)["issuers"] as JsonObject
        return issuers.mapValues { (_, v) -> ((v as? JsonObject)?.get("name") as? JsonPrimitive)?.contentOrNull ?: "" }
    }

    companion object {
        const val OPENCERTS_REGISTRY = "https://www.opencerts.io/static/registry.json"

        val DEFAULT_DOH = listOf("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")

        /** Public JSON-RPC endpoints by chain id (no API key). */
        val DEFAULT_RPC = mapOf(
            "1" to listOf("https://ethereum-rpc.publicnode.com", "https://cloudflare-eth.com"),
            "11155111" to listOf("https://ethereum-sepolia-rpc.publicnode.com"),
            "137" to listOf("https://polygon-bor-rpc.publicnode.com"),
            "80002" to listOf("https://polygon-amoy-bor-rpc.publicnode.com"),
        )

        private val NETWORKS = mapOf("1" to "以太坊主網", "11155111" to "Sepolia 測試網", "137" to "Polygon", "80002" to "Polygon Amoy 測試網", "3" to "Ropsten 測試網（已停止）", "5" to "Goerli 測試網（已停止）")

        fun netName(id: String?): String = NETWORKS[id ?: "1"] ?: "鏈 $id"

        private fun selector(signature: String): String = "0x" + DocCryptoUtil.hex(DocCrypto.keccak256(signature.encodeToByteArray())).take(8)

        private val SUPPORTS_INTERFACE = selector("supportsInterface(bytes4)")
        private const val BATCHABLE_INTERFACE = "dcfd0745"
        private val IS_ISSUED = selector("isIssued(bytes32)")
        private val IS_REVOKED = selector("isRevoked(bytes32)")
        private val IS_ISSUED_BATCH = selector("isIssued(bytes32,bytes32,bytes32[])")
        private val IS_REVOKED_BATCH = selector("isRevoked(bytes32,bytes32,bytes32[])")
        private val OWNER_OF = selector("ownerOf(uint256)")

        /** A 32 byte ABI word of a hex value (left padded). */
        private fun word(hex: String): String = hex.removePrefix("0x").lowercase().padStart(64, '0')

        private fun batchCall(selector: String, root: String, target: String, proofs: List<String>): String =
            selector + word(root) + word(target) + word("60") + word(proofs.size.toString(16)) + proofs.joinToString("") { word(it) }

        private fun abiBool(result: String): Boolean = result.removePrefix("0x").trimStart('0').let { it == "1" }

        /** The address of a did:ethr key: did:ethr:0x..., did:ethr:<network>:0x..., with or without #fragment. */
        fun ethrAddress(key: String): String? {
            if (!key.startsWith("did:ethr:")) return null
            val last = key.substringBefore('#').substringAfterLast(':')
            return last.removePrefix("0x").takeIf { it.length == 40 && it.all { c -> c.isDigit() || c.lowercaseChar() in 'a'..'f' } }
        }

        /**
         * One TXT record: "openatts net=ethereum netId=1 addr=0x..." (dnsprove), or "openatts a=dns-did; p=did:ethr:...;
         * v=1.0;" for DNS-DID. Quotes the resolver keeps around the text are removed.
         */
        fun parseRecord(data: String): OaDnsRecord? {
            val text = data.trim().removeSurrounding("\"").replace("\" \"", "")
            if (!text.startsWith("openatts")) return null
            if ("a=dns-did" in text) {
                val p = text.split(';').map { it.trim() }.firstOrNull { it.startsWith("p=") }?.removePrefix("p=") ?: return null
                return OaDnsRecord("openatts", null, null, null, p)
            }
            val kv = text.removePrefix("openatts").trim().split(Regex("\\s+")).mapNotNull { p -> p.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
            return OaDnsRecord("openatts", kv["net"], kv["netId"], kv["addr"], null)
        }
    }
}

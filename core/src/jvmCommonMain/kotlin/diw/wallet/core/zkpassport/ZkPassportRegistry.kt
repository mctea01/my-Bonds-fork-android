package diw.wallet.core.zkpassport

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.readRawBytes
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.io.File
import java.io.IOException
import java.util.zip.GZIPInputStream

/**
 * zkPassport's registries: circuit manifests and packaged circuits from its CDN, and root validity from the root
 * registry contract over Ethereum JSON-RPC. Manifests and verification keys are cached under [cache] so a version
 * seen once verifies offline except for the registry calls; nothing fetched is trusted before the native checker
 * hashed it against the registry.
 */
class ZkPassportRegistry(private val http: HttpClient, private val cache: File) {
    class Unreachable(val code: String) : IOException(code)

    private fun base(chain: Long) = if (chain == ZkPassport.MAINNET) MAINNET_CIRCUITS else TESTNET_CIRCUITS

    private suspend fun bytes(response: HttpResponse, code: String): ByteArray {
        if (!response.status.isSuccess()) throw Unreachable(code)
        val raw = response.readRawBytes()
        if (raw.size > MAX_DOWNLOAD) throw Unreachable(code)
        // The CDN stores gzip objects and sends them compressed whether or not the client asked for it.
        return if (raw.size > 2 && raw[0] == 0x1f.toByte() && raw[1] == 0x8b.toByte()) {
            GZIPInputStream(raw.inputStream()).use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(65536)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    out.write(buffer, 0, n)
                    if (out.size() > MAX_DOWNLOAD) throw Unreachable(code)
                }
                out.toByteArray()
            }
        } else raw
    }

    /**
     * The CDN answers with Content-Encoding gzip whatever was asked. Asking for gzip ourselves keeps OkHttp (Android)
     * from decoding it transparently, which breaks the body on these responses; [bytes] inflates it instead.
     */
    private suspend fun fetch(url: String, code: String): ByteArray =
        try {
            bytes(http.get(url) { header(HttpHeaders.AcceptEncoding, "gzip") }, code)
        } catch (e: Unreachable) {
            throw e
        } catch (e: Exception) {
            throw Unreachable(code)
        }

    private fun cached(name: String): File = File(cache, name).also { cache.mkdirs() }

    /** The manifest of circuit [version], reduced to the version, root and key hash of each circuit. */
    suspend fun manifest(chain: Long, version: String): JsonObject {
        require(Regex("[0-9A-Za-z.+-]{1,32}").matches(version))
        val file = cached("manifest-$chain-$version.json")
        if (file.isFile) runCatching { return Json.parseToJsonElement(file.readText()).jsonObject }
        val full = Json.parseToJsonElement(fetch("${base(chain)}/by-version/$version/manifest.json", "manifest_unavailable").decodeToString()).jsonObject
        val circuits = full["circuits"] as? JsonObject ?: throw Unreachable("manifest_unavailable")
        return buildJsonObject {
            put("version", full["version"] ?: JsonPrimitive(version))
            put("root", full["root"] ?: JsonPrimitive(""))
            putJsonObject("circuits") {
                for ((name, c) in circuits) {
                    val hash = (c as? JsonObject)?.get("hash")?.let { it as? JsonPrimitive }?.contentOrNull ?: continue
                    putJsonObject(name) { put("hash", hash) }
                }
            }
        }
    }

    /** The base64 verification key of the packaged circuit with key hash [hash]. */
    suspend fun vkey(chain: Long, hash: String): String {
        require(Regex("0x[0-9a-fA-F]{1,64}").matches(hash))
        val file = cached("vkey-$chain-${hash.lowercase()}.b64")
        if (file.isFile) return file.readText()
        val packaged = Json.parseToJsonElement(fetch("${base(chain)}/by-hash/$hash.json", "circuit_unavailable").decodeToString()).jsonObject
        return (packaged["vkey"] as? JsonPrimitive)?.contentOrNull ?: throw Unreachable("circuit_unavailable")
    }

    /** Keeps what a verification accepted, so the same version verifies without the CDN later. */
    fun remember(chain: Long, version: String, manifest: JsonObject, vkeys: Map<String, String>, hashes: Map<String, String>) {
        runCatching {
            cached("manifest-$chain-$version.json").writeText(manifest.toString())
            for ((name, vkey) in vkeys) hashes[name]?.let { cached("vkey-$chain-${it.lowercase()}.b64").writeText(vkey) }
        }
    }

    /** Drops cached data for [version] after it failed to hash to the registry. */
    fun forget(chain: Long, version: String) {
        runCatching { cached("manifest-$chain-$version.json").delete() }
    }

    /**
     * The CSCA keys of the certificate package for registry [root], once the native checker hashed the package to
     * that root ([check] returns its summary). Cached by root, so a root seen once needs no download.
     */
    suspend fun certificates(chain: Long, root: String, check: (String) -> String): JsonObject {
        require(Regex("0x[0-9a-f]{64}").matches(root))
        val file = cached("certificates-$chain-$root.json")
        if (file.isFile) runCatching { return Json.parseToJsonElement(file.readText()).jsonObject }
        val base = if (chain == ZkPassport.MAINNET) MAINNET_CERTIFICATES else TESTNET_CERTIFICATES
        val raw = fetch("$base/$root.json", "certificates_unavailable").decodeToString()
        val summary = Json.parseToJsonElement(runCatching { check(raw) }.getOrElse { throw Unreachable("certificates_root") }).jsonObject
        if ((summary["root"] as? JsonPrimitive)?.contentOrNull?.lowercase() != root) throw Unreachable("certificates_root")
        runCatching { file.writeText(summary.toString()) }
        return summary
    }

    /**
     * A registry file by [url], cached by its address: certificate packages are named by root, manifests by version
     * and packaged circuits by key hash, so a copy never goes stale. Only zkPassport's own HTTPS hosts are fetched.
     */
    suspend fun file(url: String, code: String): String {
        val host = runCatching { java.net.URI(url) }.getOrNull()?.takeIf { it.scheme == "https" }?.host.orEmpty()
        if (host != "zkpassport.id" && !host.endsWith(".zkpassport.id")) throw Unreachable(code)
        val file = fileFor(url)
        if (file.isFile) runCatching { return file.readText() }
        val text = fetch(url, code).decodeToString()
        runCatching { file.writeText(text) }
        return text
    }

    private fun fileFor(url: String): File = cached(
        "file-" + java.security.MessageDigest.getInstance("SHA-256").digest(url.encodeToByteArray())
            .joinToString("") { "%02x".format(it.toInt() and 255) },
    )

    /** Drops the cached copy of [url] after its content failed a check. */
    fun forgetFile(url: String) {
        runCatching { fileFor(url).delete() }
    }

    /** `latestRoot(registryId)` on the root registry, as 0x and 64 hex digits. */
    suspend fun latestRoot(chain: Long, rpc: String?, registry: Int): String {
        val result = call(chain, rpc, LATEST_ROOT + word(registry.toString(16)))
        val hex = result.removePrefix("0x").lowercase()
        if (hex.length != 64 || hex.any { it !in "0123456789abcdef" } || hex.all { it == '0' }) throw Unreachable("registry_unreachable")
        return "0x$hex"
    }

    private fun word(hex: String) = hex.removePrefix("0x").lowercase().padStart(64, '0')

    /** `isRootValid(registryId, root, timestamp)` on the root registry. */
    suspend fun rootValid(chain: Long, rpc: String?, registry: Int, root: String, timestamp: Long): Boolean {
        val data = IS_ROOT_VALID + word(registry.toString(16)) + word(root) + word(timestamp.toString(16))
        val result = call(chain, rpc, data)
        return result.removePrefix("0x").toBigIntegerOrNull(16)?.let { it == java.math.BigInteger.ONE } == true
    }

    /** An `eth_call` to the root registry; the hex result. */
    private suspend fun call(chain: Long, rpc: String?, data: String): String {
        val body = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", 1)
            put("method", "eth_call")
            put("params", buildJsonArray {
                add(buildJsonObject { put("to", ROOT_REGISTRY); put("data", data) })
                add(JsonPrimitive("latest"))
            })
        }
        val url = rpc?.takeIf { it.isNotBlank() } ?: if (chain == ZkPassport.MAINNET) MAINNET_RPC else SEPOLIA_RPC
        val response = try {
            http.post(url) { contentType(ContentType.Application.Json); setBody(body.toString()) }
        } catch (e: Exception) {
            throw Unreachable("registry_unreachable")
        }
        val o = runCatching { Json.parseToJsonElement(bytes(response, "registry_unreachable").decodeToString()).jsonObject }
            .getOrElse { throw Unreachable("registry_unreachable") }
        return (o["result"] as? JsonPrimitive)?.contentOrNull ?: throw Unreachable("registry_unreachable")
    }

    companion object {
        const val ROOT_REGISTRY = "0x1D0000020038d6E40E1d98e09fA1bb3A7DAA8B70"
        const val IS_ROOT_VALID = "0x2aae4296"
        const val LATEST_ROOT = "0xc3bc16e8"
        const val CERTIFICATE_REGISTRY = 1
        const val CIRCUIT_REGISTRY = 2
        const val MAINNET_RPC = ZkPassport.MAINNET_RPC
        const val SEPOLIA_RPC = ZkPassport.SEPOLIA_RPC
        const val MAINNET_CIRCUITS = "https://circuits2.zkpassport.id/mainnet"
        const val TESTNET_CIRCUITS = "https://circuits2.zkpassport.id/testnet"
        const val VERIFIER_API = "https://verifier.zkpassport.id/verify"
        const val MAINNET_CERTIFICATES = "https://certificates.zkpassport.id/mainnet"
        const val TESTNET_CERTIFICATES = "https://certificates.zkpassport.id/testnet"
        private const val MAX_DOWNLOAD = 32 * 1024 * 1024
    }
}

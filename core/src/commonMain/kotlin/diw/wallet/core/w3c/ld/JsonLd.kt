package diw.wallet.core.w3c.ld

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.w3c.LdCanonicalizer
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsBytes
import io.ktor.http.Url
import io.ktor.http.isSuccess
import kotlin.concurrent.Volatile
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/** Raised by the platform engine when a context it needs is not among the documents it was given. */
class MissingContextException(val url: String) : Exception("JSON-LD context $url is not loaded")

/** The platform JSON-LD 1.1 processor (expansion, compaction, deserialization to RDF), offline and synchronous. */
internal expect object JsonLdEngine {
    /** [contexts] returns a loaded context document for a URL, or null (then [MissingContextException] is thrown). */
    fun expand(document: JsonElement, contexts: (String) -> String?): JsonArray
    fun compact(document: JsonElement, context: JsonElement, contexts: (String) -> String?): JsonObject
    fun toRdf(document: JsonElement, contexts: (String) -> String?): List<Quad>
}

/**
 * Where JSON-LD context documents come from: the bundled [LdContexts], then contexts fetched earlier in this process,
 * then (only when [remote] is set) an HTTPS fetch. Fetching tells the context host that a credential using it is
 * processed, so the bundled set covers the W3C and security vocabularies.
 */
class LdContextLoader(
    private val remote: HttpClient? = null,
    private val extra: Map<String, String> = emptyMap(),
    private val maxBytes: Int = 1 shl 20,
) {
    private val mutex = Mutex()
    @Volatile
    private var fetched: Map<String, String> = emptyMap()

    fun cached(url: String): String? = extra[url] ?: LdContexts.BUILT_IN[url] ?: fetched[url]

    suspend fun load(url: String): String {
        cached(url)?.let { return it }
        val client = remote ?: throw ProtocolException("unsupported_context", "JSON-LD context $url is not bundled and remote contexts are off")
        val parsed = runCatching { Url(url) }.getOrNull()
        if (parsed == null || parsed.protocol.name != "https" || parsed.host.isBlank() || parsed.user != null) {
            throw ProtocolException("unsupported_context", "JSON-LD context $url must be an https URL")
        }
        return mutex.withLock {
            cached(url) ?: run {
                val response = client.get(url) { header("Accept", "application/ld+json, application/json") }
                if (!response.status.isSuccess()) throw ProtocolException("unsupported_context", "JSON-LD context $url returned ${response.status.value}")
                val bytes = response.bodyAsBytes()
                if (bytes.size > maxBytes) throw ProtocolException("unsupported_context", "JSON-LD context $url is too large")
                val text = bytes.decodeToString()
                runCatching { kotlinx.serialization.json.Json.parseToJsonElement(text) as JsonObject }.getOrNull()
                    ?: throw ProtocolException("unsupported_context", "JSON-LD context $url is not a JSON object")
                fetched = LinkedHashMap(fetched).apply {
                    if (size >= 64) remove(keys.first())
                    put(url, text)
                }
                text
            }
        }
    }

    companion object {
        /** Bundled contexts only. */
        val Offline = LdContextLoader()

        /** The loader [JsonLd.Default] uses; the app replaces it to allow fetching contexts that are not bundled. */
        var default: LdContextLoader = Offline
    }
}

/** JSON-LD operations that load the contexts they need through [loader] before running the offline engine. */
class JsonLd(private val loader: LdContextLoader? = null) {
    private val contexts: LdContextLoader get() = loader ?: LdContextLoader.default

    suspend fun expand(document: JsonElement): JsonArray = run { JsonLdEngine.expand(document, it) }

    suspend fun compact(document: JsonElement, context: JsonElement): JsonObject = run { JsonLdEngine.compact(document, context, it) }

    suspend fun toRdf(document: JsonElement): List<Quad> = run { JsonLdEngine.toRdf(document, it) }

    suspend fun canonicalize(document: JsonElement): Rdfc10.Result = Rdfc10.canonicalize(toRdf(document))

    private suspend fun <T> run(block: ((String) -> String?) -> T): T {
        val loaded = HashMap<String, String>()
        val source = contexts
        repeat(MAX_CONTEXTS) {
            try {
                return block { url -> loaded[url] ?: source.cached(url) }
            } catch (e: MissingContextException) {
                if (e.url in loaded) throw ProtocolException("unsupported_context", "JSON-LD context ${e.url} could not be used")
                loaded[e.url] = source.load(e.url)
            } catch (e: ProtocolException) {
                throw e
            } catch (e: Exception) {
                throw ProtocolException("invalid_jsonld", "JSON-LD processing failed: ${e.message ?: e::class.simpleName}", e)
            }
        }
        throw ProtocolException("unsupported_context", "The document needs too many JSON-LD contexts")
    }

    companion object {
        private const val MAX_CONTEXTS = 32
        val Default = JsonLd()
    }
}

/** [LdCanonicalizer] over [JsonLd] and RDFC-1.0, used by the RDFC Data Integrity cryptosuites. */
class RdfcCanonicalizer(private val jsonLd: JsonLd = JsonLd.Default) : LdCanonicalizer {
    override suspend fun canonicalize(document: JsonObject): String = jsonLd.canonicalize(document).text()

    companion object {
        val Default = RdfcCanonicalizer()
    }
}

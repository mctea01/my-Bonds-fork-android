package diw.wallet.core.w3c.ld

import com.apicatalog.jsonld.JsonLdError
import com.apicatalog.jsonld.JsonLdErrorCode
import com.apicatalog.jsonld.JsonLdOptions
import com.apicatalog.jsonld.api.CompactionApi
import com.apicatalog.jsonld.api.ExpansionApi
import com.apicatalog.jsonld.api.ToRdfApi
import com.apicatalog.jsonld.document.JsonDocument
import com.apicatalog.jsonld.loader.DocumentLoader
import com.apicatalog.rdf.RdfResource
import com.apicatalog.rdf.RdfValue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import java.io.StringReader
import java.net.URI

/**
 * Titanium JSON-LD (Apache-2.0). Contexts come only from [contexts]: the options are built with an explicit document
 * loader, so Titanium's HTTP and file loaders are never created.
 */
internal actual object JsonLdEngine {
    actual fun expand(document: JsonElement, contexts: (String) -> String?): JsonArray = call(contexts) { options ->
        val result = ExpansionApi(parse(document)).options(options).get()
        Json.parseToJsonElement(result.toString()) as JsonArray
    }

    actual fun compact(document: JsonElement, context: JsonElement, contexts: (String) -> String?): JsonObject = call(contexts) { options ->
        val ctx = parse(buildJsonObject { put("@context", context) })
        val result = CompactionApi(parse(document), ctx).options(options).get()
        Json.parseToJsonElement(result.toString()) as JsonObject
    }

    actual fun toRdf(document: JsonElement, contexts: (String) -> String?): List<Quad> = call(contexts) { options ->
        ToRdfApi(parse(document)).options(options).get().toList().map { q ->
            Quad(
                subject = resource(q.subject),
                predicate = Iri(q.predicate.value),
                obj = value(q.`object`),
                graph = q.graphName.orElse(null)?.let(::resource),
            )
        }
    }

    private fun <T> call(contexts: (String) -> String?, block: (JsonLdOptions) -> T): T {
        var missing: String? = null
        val loader = DocumentLoader { url, _ ->
            val key = url.toString()
            val text = contexts(key) ?: run {
                missing = key
                throw JsonLdError(JsonLdErrorCode.LOADING_DOCUMENT_FAILED, "context not loaded")
            }
            JsonDocument.of(StringReader(text)).also { it.documentUrl = URI.create(key) }
        }
        val options = JsonLdOptions(loader).apply {
            isOrdered = false
            isProduceGeneralizedRdf = false
            // Safe mode: a member the contexts do not define would be dropped from the signed RDF while staying in the
            // JSON a verifier reads, so it fails instead.
            undefinedTermsPolicy = JsonLdOptions.ProcessingPolicy.Fail
        }
        return try {
            block(options)
        } catch (e: JsonLdError) {
            missing?.let { throw MissingContextException(it) }
            throw IllegalArgumentException("${e.code}: ${e.message}", e)
        }
    }

    private fun parse(element: JsonElement): JsonDocument = JsonDocument.of(StringReader(element.toString()))

    private fun resource(r: RdfResource): RdfTerm = if (r.isBlankNode) BlankNode(r.value.removePrefix("_:")) else Iri(r.value)

    private fun value(v: RdfValue): RdfTerm = when {
        v.isLiteral -> v.asLiteral().let { l ->
            val lang = l.language.orElse(null)
            Literal(l.value, if (lang != null) RDF_LANG_STRING else l.datatype ?: XSD_STRING, lang)
        }
        v.isBlankNode -> BlankNode(v.value.removePrefix("_:"))
        else -> Iri(v.value)
    }
}

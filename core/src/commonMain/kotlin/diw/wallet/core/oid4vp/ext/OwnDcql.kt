package diw.wallet.core.oid4vp.ext

import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

data class DcqlClaim(val id: String?, val path: List<JsonElement>, val values: List<JsonElement>?, val intentToRetain: Boolean)

data class DcqlCredentialQuery(
    val id: String,
    val format: String,
    val multiple: Boolean,
    val meta: JsonObject,
    val claims: List<DcqlClaim>?,
    val claimSets: List<List<String>>?,
    val requireHolderBinding: Boolean,
)

data class DcqlCredentialSet(val options: List<List<String>>, val required: Boolean)

data class DcqlQueryModel(val credentials: List<DcqlCredentialQuery>, val sets: List<DcqlCredentialSet>) {
    companion object {
        fun parse(json: JsonObject): DcqlQueryModel {
            val creds = json.arr("credentials")?.filterIsInstance<JsonObject>()?.map { q ->
                DcqlCredentialQuery(
                    id = q.str("id") ?: throw ProtocolException("invalid_request", "DCQL credential query without id"),
                    format = q.str("format") ?: throw ProtocolException("invalid_request", "DCQL credential query without format"),
                    multiple = q.bool("multiple") ?: false,
                    meta = q.obj("meta") ?: JsonObject(emptyMap()),
                    claims = q.arr("claims")?.filterIsInstance<JsonObject>()?.map { c ->
                        DcqlClaim(
                            c.str("id"),
                            c.arr("path")?.toList() ?: listOfNotNull(c.str("namespace")?.let { JsonPrimitive(it) }, c.str("claim_name")?.let { JsonPrimitive(it) }),
                            c.arr("values")?.toList(),
                            c.bool("intent_to_retain") ?: false,
                        )
                    },
                    claimSets = q.arr("claim_sets")?.mapNotNull { set -> (set as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } },
                    requireHolderBinding = q.bool("require_cryptographic_holder_binding") ?: true,
                )
            } ?: throw ProtocolException("invalid_request", "dcql_query without credentials")
            val sets = json.arr("credential_sets")?.filterIsInstance<JsonObject>()?.map { s ->
                DcqlCredentialSet(s.arr("options")?.mapNotNull { o -> (o as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content } }.orEmpty(), s.bool("required") ?: true)
            }.orEmpty()
            return DcqlQueryModel(creds, sets)
        }
    }
}

/** A credential matching a DCQL credential query, with the claims it will disclose (member paths from the credential JSON root). */
data class DcqlMatch(val query: DcqlCredentialQuery, val credential: WalletCredential, val claims: List<DcqlClaim>, val memberPaths: List<List<String>>)

/**
 * DCQL (OpenID4VP 1.0 section 6) for the credential kinds the Multipaz engine does not handle: W3C credentials
 * (jwt_vc_json, ldp_vc and SD-JWT wrapped), and SD-JWT VC or mdoc in requests that also ask for those.
 */
object OwnDcql {
    fun match(model: DcqlQueryModel, credentials: List<WalletCredential>): Map<String, List<DcqlMatch>> =
        model.credentials.associate { q -> q.id to credentials.mapNotNull { matchOne(q, it) } }

    fun matchOne(q: DcqlCredentialQuery, c: WalletCredential): DcqlMatch? {
        if (q.format !in c.formats) return null
        if (q.requireHolderBinding && !c.keyBound) return null
        when (q.format) {
            "dc+sd-jwt", "vc+sd-jwt" -> q.meta.arr("vct_values")?.let { v ->
                val vct = c.vct ?: c.types.lastOrNull()
                if (v.none { (it as? JsonPrimitive)?.content == vct }) return null
            }
            "mso_mdoc" -> q.meta.str("doctype_value")?.let { if (it != c.docType) return null }
            else -> q.meta.arr("type_values")?.let { sets ->
                val ok = sets.any { set -> (set as? JsonArray)?.all { t -> (t as? JsonPrimitive)?.content.let { name -> c.types.any { it == name || it.endsWith("#$name") || name?.endsWith("#$it") == true } } } == true }
                if (!ok) return null
            }
        }
        val claims = q.claims ?: return DcqlMatch(q, c, emptyList(), listOf(emptyList()))
        val found = claims.associateWith { claim -> resolve(c, claim) }
        val chosen: List<DcqlClaim> = if (q.claimSets.isNullOrEmpty()) {
            if (found.values.any { it == null }) return null
            claims
        } else {
            val byId = claims.associateBy { it.id }
            q.claimSets.firstNotNullOfOrNull { set ->
                val members = set.mapNotNull { byId[it] }
                if (members.size == set.size && members.all { found[it] != null }) members else null
            } ?: return null
        }
        return DcqlMatch(q, c, chosen, chosen.mapNotNull { found[it] })
    }

    /** Member path of [claim] in [c] when present (and matching values), from the credential JSON root; null when absent. */
    private fun resolve(c: WalletCredential, claim: DcqlClaim): List<String>? {
        val roots = buildList {
            if (c.w3c != null && c.w3c !== c.json) add(c.w3c to (if (c.json["vc"] != null) listOf("vc") else emptyList()))
            add(c.json to emptyList<String>())
        }
        for ((root, prefix) in roots) {
            val values = select(root, claim.path)
            if (values.isEmpty()) continue
            if (claim.values != null && values.none { v -> claim.values.any { it is JsonPrimitive && v is JsonPrimitive && it.content == v.content } }) continue
            return prefix + claim.path.takeWhile { it is JsonPrimitive && it.isString }.map { (it as JsonPrimitive).content }
        }
        return null
    }

    fun select(root: JsonElement, path: List<JsonElement>): List<JsonElement> {
        var current = listOf(root)
        for (p in path) {
            current = current.flatMap { node ->
                when {
                    p is JsonNull -> (node as? JsonArray)?.toList().orEmpty()
                    p is JsonPrimitive && p.isString -> listOfNotNull((node as? JsonObject)?.get(p.content))
                    p is JsonPrimitive -> listOfNotNull(p.intOrNull?.let { (node as? JsonArray)?.getOrNull(it) })
                    else -> emptyList()
                }
            }
        }
        return current
    }

    /** Matches to present: per credential_sets (or every query when there are none), first candidate of each query unless [chosen] says otherwise. */
    fun select(model: DcqlQueryModel, candidates: Map<String, List<DcqlMatch>>, chosen: Map<String, Int> = emptyMap()): List<DcqlMatch> {
        fun pick(id: String): List<DcqlMatch>? {
            val list = candidates[id].orEmpty()
            if (list.isEmpty()) return null
            val q = model.credentials.first { it.id == id }
            return if (q.multiple && chosen[id] == null) list else listOf(list.getOrNull(chosen[id] ?: 0) ?: list.first())
        }
        if (model.sets.isEmpty()) {
            return model.credentials.flatMap { q -> pick(q.id) ?: throw ProtocolException("access_denied", "No stored credential satisfies '${q.id}'") }
        }
        val out = mutableListOf<DcqlMatch>()
        for (set in model.sets) {
            val option = set.options.firstOrNull { opt -> opt.all { pick(it) != null } }
            if (option == null) {
                if (set.required) throw ProtocolException("access_denied", "No stored credentials satisfy a required credential set")
                continue
            }
            option.forEach { out += pick(it)!! }
        }
        return out.distinctBy { it.query.id to it.credential.credential.identifier }
    }
}

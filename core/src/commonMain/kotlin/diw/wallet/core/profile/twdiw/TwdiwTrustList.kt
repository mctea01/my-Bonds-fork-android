package diw.wallet.core.profile.twdiw

import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.Jws
import diw.wallet.core.trust.DidTrustSource
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** An organisation registered in the TWDIW trust list (frontend /api/did). */
@Serializable
data class TwdiwTrustEntry(
    val did: String,
    /** Self-signed DID document (compact JWS) as registered. */
    val signedDocument: String,
    val name: String?,
    val nameEn: String?,
    val taxId: String?,
    val issuerMetadataBaseUrl: String?,
    val serviceBaseUrl: String?,
    /** 1 and 2 (issuer / verifier side as the platform labels them); both lists are merged. */
    val orgTypes: Set<Int>,
    val x509Type: String?,
    val updatedAt: String?,
    val onChain: List<StoredOnChain>,
) {
    /** Hosts the organisation registered (issuer metadata and service base URLs). */
    val hosts: Set<String>
        get() = listOfNotNull(issuerMetadataBaseUrl, serviceBaseUrl).mapNotNull { TwdiwHosts.canonicalHost(it) }.toSet()

    val displayName: String get() = name ?: nameEn ?: did
}

@Serializable
data class StoredOnChain(val net: String? = null, val contract: String? = null, val txHash: String, val status: String? = null, val createdAt: String? = null)

/** Verified state of an entry, as kept for offline use. */
@Serializable
data class TwdiwTrustSnapshot(
    val entry: TwdiwTrustEntry,
    val anchor: String,
    val txHash: String?,
    val blockNumber: Long?,
    val documentVerified: Boolean,
    val checkedAt: Long,
)

/** Host comparison rules for the TWDIW gates: https only, exact host, no userinfo, default port, ASCII, no trailing dot. */
object TwdiwHosts {
    fun canonicalHost(url: String): String? {
        val u = runCatching { Url(url.trim()) }.getOrNull() ?: return null
        if (u.protocol.name != "https") return null
        if (u.user != null || u.password != null) return null
        if (u.port != 443) return null
        val h = u.host
        if (h.isEmpty() || h.endsWith(".") || h.any { it.code > 127 } || h.startsWith("xn--") || h.contains(".xn--")) return null
        val raw = url.lowercase()
        if ("%2e" in raw || "/../" in raw || raw.endsWith("/..")) return null
        return h.lowercase()
    }
}

/**
 * The TWDIW trust list: organisations registered by the Ministry of Digital Affairs, each a DID with a
 * self-signed DID document anchored on Arbitrum One.
 *
 * A DID is official (T1, production) only when it is listed with status 1, its self-signed document verifies
 * with the DID's own key, and the registration is verified on chain. A listed DID whose anchor cannot be checked
 * (no transaction, RPC unavailable) is T2 with the reason; a chain mismatch or revoked registration is T4.
 * Decisions are not cached across [cacheTtl]; verified entries are snapshotted to [storage] for offline use and
 * marked as such.
 */
class TwdiwTrustList(
    private val httpClient: HttpClient,
    private val platform: TwdiwPlatform = TwdiwPlatform.PRODUCTION,
    private val anchor: ArbitrumAnchor = ArbitrumAnchor(httpClient, platform),
    private val storage: Storage? = null,
    private val cacheTtl: Duration = 10.minutes,
) : DidTrustSource {
    private data class Cached(val snapshot: TwdiwTrustSnapshot?, val until: Instant)

    private val cache = mutableMapOf<String, Cached>()
    private var allCache: Pair<List<TwdiwTrustEntry>, Instant>? = null
    private val dids = DidResolver(httpClient)

    override suspend fun decide(did: String, role: TrustRole): TrustDecision? {
        val snap = verified(did) ?: return null
        return decisionFor(snap)
    }

    fun decisionFor(snap: TwdiwTrustSnapshot): TrustDecision {
        val env = if (platform.test) TrustEnvironment.TEST else TrustEnvironment.PRODUCTION
        val name = snap.entry.displayName
        val offline = Clock.System.now().toEpochMilliseconds() - snap.checkedAt > cacheTtl.inWholeMilliseconds
        val reasons = mutableListOf<String>()
        if (offline) reasons += "Offline snapshot of the TWDIW trust list taken at ${Instant.fromEpochMilliseconds(snap.checkedAt)}"
        if (!snap.documentVerified) {
            reasons += "The self-signed DID document of ${snap.entry.did} does not verify"
            return TrustDecision(TrustTier.T4, env, false, name, setOf(TrustLabel.UNKNOWN_ANCHOR), reasons)
        }
        val state = AnchorState.valueOf(snap.anchor)
        return when {
            platform.test -> TrustDecision(TrustTier.T3, env, false, name, setOf(TrustLabel.TEST_ANCHOR), reasons + "TWDIW test trust list")
            state == AnchorState.VERIFIED -> TrustDecision(TrustTier.T1, env, true, name, emptySet(), reasons)
            state == AnchorState.MISMATCH -> TrustDecision(TrustTier.T4, env, false, name, setOf(TrustLabel.UNKNOWN_ANCHOR),
                reasons + "The TWDIW trust list entry does not match its Arbitrum registration")
            else -> TrustDecision(TrustTier.T2, env, false, name, emptySet(),
                reasons + "Listed in the TWDIW trust list; Arbitrum anchor ${state.name.lowercase()}")
        }
    }

    /** The checked entry for [did], or null when the DID is not listed. Falls back to the stored snapshot offline. */
    suspend fun verified(did: String, bypassCache: Boolean = false): TwdiwTrustSnapshot? {
        val now = Clock.System.now()
        cache[did]?.takeIf { !bypassCache && it.until > now }?.let { return it.snapshot }
        val entry = try {
            fetchEntry(did)
        } catch (e: Exception) {
            return loadSnapshot(did)
        }
        val snap = entry?.let { check(it) }
        cache[did] = Cached(snap, now + cacheTtl)
        if (snap != null) saveSnapshot(snap)
        return snap
    }

    /** Whether [host] is registered for [did] (response_uri / request_uri gates); null when the DID is unknown. */
    suspend fun hostRegistered(did: String, host: String): Boolean? {
        val snap = verified(did) ?: return null
        val h = host.lowercase()
        return h in snap.entry.hosts || (platform.test && h in TwdiwPlatform.SANDBOX_HOSTS)
    }

    /** Whether [url]'s host belongs to any listed organisation (or a sandbox when testing). */
    suspend fun isListedHost(url: String): Boolean {
        val host = TwdiwHosts.canonicalHost(url) ?: return false
        if (platform.test && host in TwdiwPlatform.SANDBOX_HOSTS) return true
        return all().any { host in it.hosts }
    }

    /** Organisations listed for [host]; one host may serve several organisations. */
    suspend fun entriesForHost(host: String): List<TwdiwTrustEntry> = all().filter { host.lowercase() in it.hosts }

    /**
     * The whole list. The API clamps page size to 20 but computes the offset from the requested size, so pages of 20
     * are read until an empty page, for both organisation types, merged by DID.
     */
    suspend fun all(bypassCache: Boolean = false): List<TwdiwTrustEntry> {
        val now = Clock.System.now()
        allCache?.takeIf { !bypassCache && it.second > now }?.let { return it.first }
        val merged = linkedMapOf<String, TwdiwTrustEntry>()
        for (orgType in listOf(1, 2)) {
            var page = 0
            while (page < MAX_PAGES) {
                val body = getJson("${platform.frontendUrl}/api/did?size=$PAGE_SIZE&page=$page&orgType=$orgType&status=1") ?: break
                val items = (body.obj("data")?.arr("dids") ?: body.arr("data") ?: JsonArray(emptyList())).filterIsInstance<JsonObject>()
                if (items.isEmpty()) break
                for (o in items) {
                    val e = parseEntry(o, orgType) ?: continue
                    merged[e.did] = merged[e.did]?.let { it.copy(orgTypes = it.orgTypes + e.orgTypes) } ?: e
                }
                page++
            }
        }
        val list = merged.values.toList()
        allCache = list to now + cacheTtl
        return list
    }

    private suspend fun check(entry: TwdiwTrustEntry): TwdiwTrustSnapshot {
        val documentVerified = verifyDocument(entry)
        val result = if (documentVerified) {
            anchor.check(entry.did, entry.signedDocument, entry.onChain.map { OnChainRecord(it.net, it.contract, it.txHash, it.status, it.createdAt) })
        } else AnchorResult(AnchorState.MISMATCH, detail = "Document signature invalid")
        return TwdiwTrustSnapshot(entry, result.state.name, result.txHash, result.blockNumber, documentVerified, Clock.System.now().toEpochMilliseconds())
    }

    /** The registered document is a JWS signed by the DID's own key, and its id is the DID. */
    private suspend fun verifyDocument(entry: TwdiwTrustEntry): Boolean = runCatching {
        val jws = Jws.parse(entry.signedDocument)
        val method = dids.resolveKey(entry.did, null)
        jws.verify(method.key)
        val payload = jws.payload
        val docId = payload.str("id") ?: payload.obj("didDocument")?.str("id") ?: payload.str("iss")
        docId == null || docId == entry.did
    }.getOrDefault(false)

    private suspend fun fetchEntry(did: String): TwdiwTrustEntry? {
        val body = getJson("${platform.frontendUrl}/api/did/${did.encodeURLPathPart().replace(":", "%3A")}") ?: return null
        if (body.str("code") != null && body.str("code") != "0") return null
        val data = body.obj("data") ?: return null
        val status = (data["status"] as? JsonPrimitive)?.content
        if (status != null && status != "1") return null
        return parseEntry(data, null)?.takeIf { it.did == did }
    }

    private suspend fun getJson(url: String): JsonObject? {
        val resp = httpClient.get(url) {
            header(HttpHeaders.CacheControl, "no-cache, no-store")
            header(HttpHeaders.Accept, "application/json")
        }
        if (resp.status.value == 404) return null
        if (!resp.status.isSuccess()) error("TWDIW trust list returned ${resp.status.value}")
        return DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject
    }

    private fun parseEntry(o: JsonObject, orgType: Int?): TwdiwTrustEntry? {
        val did = o.str("id") ?: return null
        if (!did.startsWith("did:")) return null
        val org = o.obj("org")
        val types = buildSet {
            orgType?.let { add(it) }
            (o["orgType"] as? JsonPrimitive)?.content?.toIntOrNull()?.let { add(it) }
        }
        val history = (o.arr("onChainHistory") ?: JsonArray(emptyList())).filterIsInstance<JsonObject>().mapNotNull { h ->
            StoredOnChain(h.str("net"), h.str("scAddress"), h.str("txHash") ?: return@mapNotNull null, h.str("status"), h.str("createdAt"))
        }
        return TwdiwTrustEntry(
            did = did,
            signedDocument = o.str("did") ?: return null,
            name = org?.str("name"),
            nameEn = org?.str("name_en"),
            taxId = org?.str("taxId"),
            issuerMetadataBaseUrl = org?.str("issuerMetadataBaseURL"),
            serviceBaseUrl = org?.str("serviceBaseURL"),
            orgTypes = types,
            x509Type = o.str("x509_type"),
            updatedAt = o.str("updatedAt"),
            onChain = history,
        )
    }

    private suspend fun saveSnapshot(snap: TwdiwTrustSnapshot) {
        val s = storage ?: return
        runCatching {
            val t = s.getTable(TABLE)
            val bytes = DiwJson.encodeToString(TwdiwTrustSnapshot.serializer(), snap).encodeToByteString()
            if (t.get(snap.entry.did) == null) t.insert(snap.entry.did, bytes) else t.update(snap.entry.did, bytes)
        }
    }

    private suspend fun loadSnapshot(did: String): TwdiwTrustSnapshot? {
        val s = storage ?: return null
        return runCatching {
            s.getTable(TABLE).get(did)?.let { DiwJson.decodeFromString(TwdiwTrustSnapshot.serializer(), it.decodeToString()) }
        }.getOrNull()
    }

    /** Snapshots stored for offline use. */
    suspend fun snapshots(): List<TwdiwTrustSnapshot> {
        val s = storage ?: return emptyList()
        val t = s.getTable(TABLE)
        return t.enumerate().mapNotNull { k ->
            runCatching { t.get(k)?.let { DiwJson.decodeFromString(TwdiwTrustSnapshot.serializer(), it.decodeToString()) } }.getOrNull()
        }
    }

    companion object {
        const val PAGE_SIZE = 20
        private const val MAX_PAGES = 50
        private val TABLE = StorageTableSpec("DiwTwdiwTrust", supportPartitions = false, supportExpiration = false)
    }
}

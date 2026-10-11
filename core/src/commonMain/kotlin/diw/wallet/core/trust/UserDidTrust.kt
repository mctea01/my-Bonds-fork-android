package diw.wallet.core.trust

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec

/** A DID the user chose to trust, for the roles they chose. */
@Serializable
data class UserTrustedDid(
    val did: String,
    val name: String,
    /** [TrustRole.id] values. */
    val roles: List<String>,
    val addedAt: Long,
)

/**
 * DIDs the user trusts themselves, beside the national list and domain linkage: an organisation outside TWDIW,
 * a company's own issuer, a test partner. A listed DID is the user's own anchor (USER environment, T3), never
 * official.
 */
class UserDidTrust(private val storage: Storage) : DidTrustSource {
    private val serializer = ListSerializer(UserTrustedDid.serializer())
    private var cached: List<UserTrustedDid>? = null

    suspend fun all(): List<UserTrustedDid> = cached ?: run {
        val raw = storage.getTable(table).get(KEY)
        val list = raw?.let { runCatching { DiwJson.decodeFromString(serializer, it.decodeToString()) }.getOrNull() }.orEmpty()
        list.also { cached = it }
    }

    /** Adds or replaces the entry for [did]. */
    suspend fun put(did: String, name: String, roles: Set<TrustRole>, addedAt: Long) {
        require(did.startsWith("did:") && did.length > 8) { "Not a DID: $did" }
        val entry = UserTrustedDid(did.trim(), name.trim().ifEmpty { did.trim() }, roles.map { it.id }.sorted(), addedAt)
        save(all().filter { it.did != entry.did } + entry)
    }

    suspend fun remove(did: String) = save(all().filter { it.did != did })

    private suspend fun save(list: List<UserTrustedDid>) {
        val t = storage.getTable(table)
        val bytes = DiwJson.encodeToString(serializer, list).encodeToByteString()
        if (t.get(KEY) == null) t.insert(KEY, bytes) else t.update(KEY, bytes)
        cached = list
    }

    override suspend fun decide(did: String, role: TrustRole): TrustDecision? {
        val entry = all().firstOrNull { it.did == did && role.id in it.roles } ?: return null
        return TrustDecision(
            tier = TrustTier.T3,
            environment = TrustEnvironment.USER,
            official = false,
            anchorName = entry.name,
            labels = setOf(TrustLabel.USER_ANCHOR),
            reasons = listOf("Trusted by the user as ${role.id}"),
        )
    }

    companion object {
        private val table = StorageTableSpec(name = "DiwUserDids", supportPartitions = false, supportExpiration = false)
        private const val KEY = "dids"
    }
}

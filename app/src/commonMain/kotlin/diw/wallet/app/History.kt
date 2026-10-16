package diw.wallet.app

import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec

/** What a history entry records. */
@Serializable
enum class HistoryKind {
    /** Documents received from an issuer. */
    ISSUED,

    /** Claims shared with a verifier (online, over the DC API, at a counter or offline to a Bonds verifier). */
    PRESENTED,

    /** The user refused to share. */
    DECLINED,

    /** This wallet checked someone else's presentation. */
    VERIFIED,

    /** A held document's status, or its issuer's trust, changed on a background check. */
    STATUS,

    /** The user signed a file (citizen certificate card, PKCS#12 or the wallet's own key). */
    SIGNED,
}

/**
 * One interaction with another party, as the EUDI wallet's transaction log keeps it: who, when, which documents
 * and which claims. Only claim names are kept, never their values.
 */
@Serializable
data class HistoryEntry(
    val id: String,
    val epochSeconds: Long,
    val kind: HistoryKind,
    /** Issuer or verifier; for [HistoryKind.VERIFIED] the holder. */
    val party: String,
    /** Trust tier of [party] when it was decided (T1 to T4), null when none was decided. */
    val tier: String? = null,
    /** The party was trusted only in the test environment. */
    val test: Boolean = false,
    val documents: List<String> = emptyList(),
    /** Claim names in the user's language. */
    val claims: List<String> = emptyList(),
    /** Purpose, channel or service, e.g. the counter service or the Bonds purpose. */
    val note: String? = null,
    /** Null when the interaction completed, otherwise why it did not. */
    val failure: String? = null,
    /** For [HistoryKind.STATUS]: the new state (a RevocationCheckState name), or TRUST for an issuer trust change. */
    val status: String? = null,
)

/** The history log in wallet storage, newest first, capped at [MAX] entries. */
class HistoryLog(private val storage: Storage) {
    private val serializer = ListSerializer(HistoryEntry.serializer())

    suspend fun load(): List<HistoryEntry> {
        val raw = storage.getTable(table).get(KEY) ?: return emptyList()
        return runCatching { DiwJson.decodeFromString(serializer, raw.decodeToString()) }.getOrDefault(emptyList())
    }

    suspend fun save(entries: List<HistoryEntry>) {
        val t = storage.getTable(table)
        val bytes = DiwJson.encodeToString(serializer, entries.take(MAX)).encodeToByteString()
        if (t.get(KEY) == null) t.insert(KEY, bytes) else t.update(KEY, bytes)
    }

    companion object {
        /** One spec per table name and process: storage rejects a second spec object for the same table. */
        private val table = StorageTableSpec(name = "DiwHistory", supportPartitions = false, supportExpiration = false)
        private const val KEY = "entries"
        const val MAX = 300
    }
}

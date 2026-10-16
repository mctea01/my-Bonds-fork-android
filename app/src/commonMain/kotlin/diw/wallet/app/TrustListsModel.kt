package diw.wallet.app

import diw.wallet.core.trust.TrustListKind
import diw.wallet.core.trust.TrustListLoader
import diw.wallet.core.trust.TrustListSnapshot
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock

/**
 * The public trust lists (AATL, EUTL) the wallet follows for document signers and time-stamp authorities. Verified
 * snapshots are kept in storage for offline use and put in the trust registry at start; a list is downloaded again
 * (conditionally) when it is older than [REFRESH_SECONDS] or past its announced next update. A failed download keeps
 * the snapshot in use and is shown with the list.
 */
class TrustListsModel(private val model: WalletModel) {
    /** What the settings show for one list. */
    data class ListState(
        val kind: TrustListKind,
        val services: Int = 0,
        val fetchedAt: Long? = null,
        val issued: Long? = null,
        val nextUpdate: Long? = null,
        val signer: String? = null,
        val partErrors: List<String> = emptyList(),
        val error: String? = null,
        val running: Boolean = false,
    )

    val states = MutableStateFlow(TrustListKind.entries.associateWith { ListState(it) })

    /** National lists may move behind redirects. It shares the wallet client's engine and lives as long as it. */
    private val client by lazy { model.http.config { followRedirects = true } }

    private val lock = Mutex()
    private val jobs = mutableMapOf<TrustListKind, Job>()

    private fun enabled(kind: TrustListKind): Boolean = when (kind) {
        TrustListKind.AATL -> model.settings.aatlTrustList
        TrustListKind.EUTL -> model.settings.eutlTrustList
    }

    /** Puts the stored snapshots in use. */
    suspend fun load() {
        val t = model.storage.getTable(table)
        for (kind in TrustListKind.entries) {
            val snapshot = runCatching { Blobs.get(t, kind.id) }.getOrNull()?.let { TrustListSnapshot.decode(it) } ?: continue
            model.trust.trustLists.install(snapshot)
            update(kind) { stateOf(kind, snapshot) }
        }
    }

    /** Downloads the enabled lists that are due, in the background. */
    fun refreshDue() {
        if (!model.platform.refreshTrustListsInBackground) return
        val now = Clock.System.now().epochSeconds
        for (kind in TrustListKind.entries) {
            if (!enabled(kind)) continue
            val s = model.trust.trustLists.snapshot(kind)
            val due = s == null || now - s.fetchedAt > REFRESH_SECONDS || (s.nextUpdate != null && now > s.nextUpdate!! && now - s.fetchedAt > RETRY_SECONDS)
            if (due) refresh(kind)
        }
    }

    /** Downloads [kind] now (conditionally when a snapshot is stored). */
    fun refresh(kind: TrustListKind) {
        if (jobs[kind]?.isActive == true) return
        jobs[kind] = model.scope.launch {
            update(kind) { it.copy(running = true, error = null) }
            try {
                val previous = model.trust.trustLists.snapshot(kind)
                val loader = TrustListLoader(client, parallelism = 2)
                val snapshot = when (kind) {
                    TrustListKind.AATL -> loader.aatl(previous)
                    TrustListKind.EUTL -> loader.eutl(previous)
                }
                lock.withLock { Blobs.put(model.storage.getTable(table), kind.id, snapshot.encode()) }
                model.trust.trustLists.install(snapshot)
                update(kind) { stateOf(kind, snapshot) }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                update(kind) { it.copy(running = false, error = e.message ?: e::class.simpleName) }
            }
        }
    }

    /** Stops using [kind] and deletes its stored snapshot (the setting decides whether it is downloaded again). */
    fun clear(kind: TrustListKind) = model.scope.launch {
        jobs[kind]?.cancel()
        lock.withLock { Blobs.delete(model.storage.getTable(table), kind.id) }
        model.trust.trustLists.remove(kind)
        update(kind) { ListState(kind) }
    }

    private fun stateOf(kind: TrustListKind, s: TrustListSnapshot) = ListState(
        kind = kind,
        services = s.services.size,
        fetchedAt = s.fetchedAt,
        issued = s.issued ?: s.parts.mapNotNull { it.issued }.maxOrNull(),
        nextUpdate = s.nextUpdate,
        signer = s.signer,
        partErrors = s.errors,
    )

    private fun update(kind: TrustListKind, f: (ListState) -> ListState) {
        states.value = states.value + (kind to f(states.value[kind] ?: ListState(kind)))
    }

    companion object {
        /** Lists are downloaded again after a week (most change monthly; a revoked service matters sooner). */
        const val REFRESH_SECONDS = 7L * 24 * 3600
        /** After a list's announced next update has passed, a day between attempts. */
        const val RETRY_SECONDS = 24L * 3600
        private val table = StorageTableSpec(name = "DiwTrustLists", supportPartitions = false, supportExpiration = false)
    }
}

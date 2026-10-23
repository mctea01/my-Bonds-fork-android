package diw.wallet.app

import diw.wallet.core.zk.ZkTemplatePack
import diw.wallet.core.zktls.ZkTlsProfiles
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock

/**
 * The zkTLS and zkPDF page templates published with each release ([ZkTemplatePack]). The last verified pack is kept
 * in storage and installed at start, so templates work offline; a new one is downloaded when the stored one is older
 * than [REFRESH_SECONDS]. The highest version ever installed is kept apart, so neither an older download nor a
 * restored copy of storage can bring back a template that was withdrawn.
 */
class ZkTemplatesModel(private val model: WalletModel) {
    data class State(
        val version: Long? = null,
        val issuedAt: Long? = null,
        val pages: Int = 0,
        val documents: Int = 0,
        val checkedAt: Long? = null,
        val error: String? = null,
        val running: Boolean = false,
    ) {
        /** False until a release key is pinned in this build: no pack can be accepted then. */
        val keyConfigured: Boolean get() = ZkTemplatePack.TRUSTED_KEYS.isNotEmpty()
    }

    val state = MutableStateFlow(State())

    /** Release downloads redirect to GitHub's object storage. */
    private val client by lazy { model.http.config { followRedirects = true } }
    private var job: Job? = null

    /** Installs the stored pack. */
    suspend fun load() {
        val t = model.storage.getTable(table)
        val checked = runCatching { Blobs.get(t, CHECKED)?.decodeToString()?.toLong() }.getOrNull()
        state.value = state.value.copy(checkedAt = checked)
        val jws = runCatching { Blobs.get(t, PACK) }.getOrNull()?.decodeToString() ?: return
        val pack = runCatching { ZkTemplatePack.verify(jws, ZkTemplatePack.trustedKeys(), highest()) }.getOrNull() ?: return
        install(pack)
    }

    /** Downloads the pack in the background when the stored one is due. */
    fun refreshDue() {
        if (!model.platform.refreshTrustListsInBackground || !state.value.keyConfigured) return
        val checked = state.value.checkedAt
        if (checked == null || Clock.System.now().epochSeconds - checked > REFRESH_SECONDS) refresh()
    }

    /** Downloads the release's pack now. */
    fun refresh() {
        if (job?.isActive == true) return
        job = model.scope.launch {
            state.value = state.value.copy(running = true, error = null)
            try {
                val response = client.get(ZkTemplatePack.RELEASE_URL)
                if (!response.status.isSuccess()) throw IllegalStateException("下載失敗（HTTP ${response.status.value}）")
                val jws = response.bodyAsText()
                val pack = ZkTemplatePack.verify(jws, ZkTemplatePack.trustedKeys(), highest())
                val t = model.storage.getTable(table)
                if (pack.version > (state.value.version ?: 0)) {
                    Blobs.put(t, PACK, jws.encodeToByteArray())
                    Blobs.put(t, HIGHEST, pack.version.toString().encodeToByteArray())
                    install(pack)
                }
                val now = Clock.System.now().epochSeconds
                Blobs.put(t, CHECKED, now.toString().encodeToByteArray())
                state.value = state.value.copy(checkedAt = now, running = false)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                state.value = state.value.copy(running = false, error = e.message ?: e::class.simpleName)
            }
        }
    }

    private suspend fun highest(): Long = runCatching {
        Blobs.get(model.storage.getTable(table), HIGHEST)?.decodeToString()?.toLong()
    }.getOrNull() ?: 0

    private fun install(pack: ZkTemplatePack) {
        ZkTlsProfiles.install(pack)
        state.value = state.value.copy(
            version = pack.version,
            issuedAt = pack.issuedAt.epochSeconds,
            pages = pack.zktls.size,
            documents = pack.zkpdf.size,
        )
    }

    companion object {
        /** Templates change rarely; a day between checks. */
        const val REFRESH_SECONDS = 24L * 3600
        private const val PACK = "pack"
        private const val HIGHEST = "highest"
        private const val CHECKED = "checked"
        private val table = StorageTableSpec(name = "DiwZkTemplates", supportPartitions = false, supportExpiration = false)
    }
}

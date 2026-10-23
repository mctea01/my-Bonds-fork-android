package diw.wallet.app

import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zk.ZkTemplatePack
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsProfiles
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock

/**
 * The zkTLS and zkPDF page templates published with each release ([ZkTemplatePack]), read from every source in
 * [ZkTemplatePack.SOURCES] (the nightly release, and a release the maintainer fills by hand for when nightly is
 * missing or broken); the newest pack that verifies wins. The last verified pack is kept
 * in storage and installed at start, so templates work offline; a new one is downloaded when the stored one is older
 * than [REFRESH_SECONDS]. The highest version ever installed is kept apart, so neither an older download nor a
 * restored copy of storage can bring back a template that was withdrawn.
 *
 * A pack can also be imported from a file (the release's zk-templates.jwt, or the CI artifact ZIP holding it), with the
 * same checks. In the test environment unsigned page descriptions can be imported too: they are kept apart from the
 * pack, offered only in the test environment and sent inside the request, so the holder sees them as test pages.
 */
class ZkTemplatesModel(private val model: WalletModel) {
    data class State(
        val version: Long? = null,
        val issuedAt: Long? = null,
        val pages: Int = 0,
        val documents: Int = 0,
        val checkedAt: Long? = null,
        /** The source the installed pack came from (a [ZkTemplatePack.SOURCES] name, or a file). */
        val source: String? = null,
        val error: String? = null,
        val running: Boolean = false,
        /** Outcome of the last file import. */
        val notice: String? = null,
        /** Unsigned pages imported for testing. */
        val testPages: List<ZkTlsProfile> = emptyList(),
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
        val local = runCatching { Blobs.get(t, TEST_PAGES)?.decodeToString()?.let(::profiles) }.getOrNull().orEmpty()
        val source = runCatching { Blobs.get(t, SOURCE)?.decodeToString() }.getOrNull()
        state.value = state.value.copy(checkedAt = checked, testPages = local, source = source)
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
                val minimum = highest()
                val problems = mutableListOf<String>()
                var best: Triple<String, String, ZkTemplatePack>? = null
                for ((name, url) in ZkTemplatePack.SOURCES) {
                    try {
                        val response = client.get(url)
                        if (!response.status.isSuccess()) throw IllegalStateException("HTTP ${response.status.value}")
                        val jws = response.bodyAsText()
                        val pack = ZkTemplatePack.verify(jws, ZkTemplatePack.trustedKeys(), minimum)
                        if (best == null || pack.version > best.third.version) best = Triple(name, jws, pack)
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        problems += "$name：" + (e.message ?: e::class.simpleName)
                    }
                }
                val found = best ?: throw IllegalStateException("下載失敗（${problems.joinToString("；")}）")
                val t = model.storage.getTable(table)
                if (found.third.version > (state.value.version ?: 0)) store(found.second, found.third, found.first)
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

    /** Imports the files the user picks: signed packs, and in the test environment unsigned page descriptions. */
    fun importFiles() {
        // Marked before the picker opens, so a second tap (or a call right after the last import ended) is decided
        // by the state alone, not by whether the previous job has finished completing.
        if (state.value.running) return
        state.value = state.value.copy(running = true, error = null, notice = null)
        job = model.scope.launch {
            var notice: String? = null
            try {
                notice = importPicked(model.platform.pickFiles())
            } finally {
                state.value = state.value.copy(running = false, notice = notice)
            }
        }
    }

    /** What importing [picked] did, for the settings page; null when nothing was picked. */
    private suspend fun importPicked(picked: List<PickedFile>): String? {
        if (picked.isEmpty()) return null
        val notes = mutableListOf<String>()
        val pages = mutableListOf<ZkTlsProfile>()
        for (f in picked) {
            try {
                for ((name, bytes) in entries(f.name, f.bytes)) {
                    val text = bytes.decodeToString().trim().removePrefix("\uFEFF")
                    if (text.startsWith("ey")) notes += importPack(text)
                    else pages += pagesOf(name, text)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                notes += "${f.name}：" + (e.message ?: e::class.simpleName)
            }
        }
        if (pages.isNotEmpty()) notes += addTestPages(pages)
        return notes.joinToString("\n").ifEmpty { "檔案中沒有版型" }
    }

    /** Removes the pages imported for testing. */
    fun clearTestPages() {
        model.scope.launch {
            runCatching { Blobs.delete(model.storage.getTable(table), TEST_PAGES) }
            state.value = state.value.copy(testPages = emptyList(), notice = "已清除測試查驗頁")
        }
    }

    /** The files of a picked file: the entries of a ZIP (a downloaded CI artifact), else the file itself. */
    private fun entries(name: String, bytes: ByteArray): List<Pair<String, ByteArray>> {
        if (bytes.size > MAX_FILE) throw IllegalArgumentException("檔案過大")
        if (bytes.size < 4 || bytes[0] != 'P'.code.toByte() || bytes[1] != 'K'.code.toByte()) return listOf(name to bytes)
        return DocumentSigning.unzip(bytes).filter { (n, b) -> b.isNotEmpty() && (n.endsWith(".jwt") || n.endsWith(".json")) && b.size <= MAX_FILE }
            .map { (n, b) -> n.substringAfterLast('/') to b }
    }

    private suspend fun importPack(jws: String): String {
        val pack = ZkTemplatePack.verify(jws, ZkTemplatePack.trustedKeys(), highest())
        val current = state.value.version ?: 0
        if (pack.version <= current) return "版型包 ${pack.version} 不比已安裝的版本新，未變更"
        store(jws, pack, "檔案")
        return "已安裝版型包：${pack.zktls.size} 個查驗頁、${pack.zkpdf.size} 個文件版型"
    }

    /** Page descriptions in a JSON file: one page, the test server's {"profiles": [...]} or an unsigned pack payload. */
    private fun pagesOf(name: String, text: String): List<ZkTlsProfile> {
        if (!model.settings.testEnvironment) throw ProtocolException("invalid_templates", "未簽章的查驗頁只能在測試環境匯入")
        val o = runCatching { DiwJson.parseToJsonElement(text) as JsonObject }.getOrNull()
            ?: throw ProtocolException("invalid_templates", "$name 不是版型包或查驗頁描述檔")
        val list = (o["profiles"] ?: o["zktls"]) as? JsonArray
        return list?.map { (it as? JsonObject)?.let(ZkTlsProfile::parse) ?: throw ProtocolException("invalid_templates", "$name 的查驗頁格式錯誤") }
            ?: listOf(ZkTlsProfile.parse(o))
    }

    private suspend fun addTestPages(pages: List<ZkTlsProfile>): String {
        val signed = ZkTlsProfiles.installed.map { it.id }.toSet()
        val (clash, fresh) = pages.partition { it.id in signed }
        val merged = state.value.testPages.filter { old -> fresh.none { it.id == old.id } } + fresh
        val array = buildJsonArray { merged.forEach { add(DiwJson.encodeToJsonElement(ZkTlsProfile.serializer(), it)) } }
        Blobs.put(model.storage.getTable(table), TEST_PAGES, array.toString().encodeToByteArray())
        state.value = state.value.copy(testPages = merged)
        return buildString {
            append("已匯入 ${fresh.size} 個測試查驗頁")
            if (clash.isNotEmpty()) append("；${clash.joinToString("、") { it.id }} 與已簽章的查驗頁同名，未匯入")
        }
    }

    private fun profiles(text: String): List<ZkTlsProfile> =
        (DiwJson.parseToJsonElement(text) as JsonArray).mapNotNull { (it as? JsonObject)?.let { o -> runCatching { ZkTlsProfile.parse(o) }.getOrNull() } }

    private suspend fun store(jws: String, pack: ZkTemplatePack, source: String) {
        val t = model.storage.getTable(table)
        Blobs.put(t, PACK, jws.encodeToByteArray())
        Blobs.put(t, HIGHEST, pack.version.toString().encodeToByteArray())
        Blobs.put(t, SOURCE, source.encodeToByteArray())
        install(pack)
        state.value = state.value.copy(source = source)
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
        private const val TEST_PAGES = "testPages"
        private const val SOURCE = "source"
        private const val MAX_FILE = 1 shl 20
        private val table = StorageTableSpec(name = "DiwZkTemplates", supportPartitions = false, supportExpiration = false)
    }
}

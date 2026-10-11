package diw.wallet.app.desktop

import diw.wallet.app.NfcReaderList
import diw.wallet.app.NfcReaderOption
import kotlinx.coroutines.ExecutorCoroutineDispatcher
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.NfcIsoTag
import org.multipaz.nfc.NfcScanOptions
import org.multipaz.nfc.NfcTagLostException
import org.multipaz.nfc.NfcTagReader
import org.multipaz.nfc.ResponseApdu
import java.io.File
import java.util.concurrent.Executors
import javax.smartcardio.Card
import javax.smartcardio.CardException
import javax.smartcardio.CardTerminal
import javax.smartcardio.CommandAPDU
import javax.smartcardio.TerminalFactory
import kotlin.coroutines.CoroutineContext

/**
 * Contactless readers on a computer through PC/SC (javax.smartcardio): ACR122U, ACR1252U, Identiv uTrust, HID
 * OMNIKEY and other readers that expose an ISO 14443-4 (ISO-DEP) target as a card. A phone presenting an mdoc by
 * card emulation is such a target, so the computer can read it as an ISO/IEC 18013-5 reader. PC/SC readers poll for
 * cards; they cannot emulate one, so a computer reads wallets but does not present to a reader this way.
 */
object PcscReaders {
    @Volatile private var configured = false

    /** The PC/SC readers connected now, or why there are none. */
    fun list(): NfcReaderList {
        configure()
        return try {
            NfcReaderList(terminals().map { NfcReaderOption(it.name, external = true, reader = PcscTagReader(it)) })
                .let { if (it.readers.isEmpty()) it.copy(problem = "沒有找到 PC/SC 讀卡機，請接上非接觸式（NFC）讀卡機。") else it }
        } catch (e: Throwable) {
            if (e is VirtualMachineError) throw e
            NfcReaderList(emptyList(), reason(e))
        }
    }

    private fun terminals(): List<CardTerminal> = try {
        TerminalFactory.getDefault().terminals().list()
    } catch (e: CardException) {
        val text = describe(e)
        when {
            "SCARD_E_NO_READERS_AVAILABLE" in text -> emptyList()
            // Windows stops the smart card service while no reader is attached; the JVM keeps the dead context.
            STALE_CONTEXT.any { it in text } && resetContext() -> TerminalFactory.getInstance("PC/SC", null).terminals().list()
            else -> throw e
        }
    }

    /**
     * Drops the JVM's cached PC/SC context so a new factory establishes a fresh one. Needs
     * --add-opens java.smartcardio/sun.security.smartcardio=ALL-UNNAMED, which the packaged app passes; false when
     * that is not possible.
     */
    private fun resetContext(): Boolean = runCatching {
        val field = Class.forName("sun.security.smartcardio.PCSCTerminals").getDeclaredField("contextId")
        field.isAccessible = true
        field.setLong(null, 0L)
        true
    }.getOrDefault(false)

    @Synchronized
    private fun configure() {
        if (configured) return
        // The ISO/IEC 18013-5 NFC transfer handles 61XX itself with GET RESPONSE; the JDK must not do it first.
        System.setProperty("sun.security.smartcardio.t0GetResponse", "false")
        System.setProperty("sun.security.smartcardio.t1GetResponse", "false")
        // Debian, Ubuntu and Fedora keep libpcsclite where the JDK does not look.
        if (System.getProperty("os.name").orEmpty().lowercase().contains("linux") && System.getProperty(LIBRARY) == null) {
            LINUX_LIBRARIES.firstOrNull { File(it).exists() }?.let { System.setProperty(LIBRARY, it) }
        }
        configured = true
    }

    private fun reason(e: Throwable): String {
        val text = describe(e)
        val windows = System.getProperty("os.name").orEmpty().lowercase().contains("windows")
        return when {
            STALE_CONTEXT.any { it in text } ->
                if (windows) "Windows 的智慧卡服務沒有執行。請接上讀卡機，再重新開啟 App。"
                else "PC/SC 服務（pcscd）沒有執行。請啟動 pcscd（例如 sudo systemctl start pcscd）後再試。"
            e is UnsatisfiedLinkError || "library" in text.lowercase() || "PlatformPCSC" in text ->
                "找不到 PC/SC 函式庫。Linux 請安裝 pcscd 與 libpcsclite1（或 pcsc-lite-libs）。"
            else -> "無法使用 PC/SC 讀卡機：$text"
        }
    }

    internal fun describe(e: Throwable): String = generateSequence(e) { it.cause }.mapNotNull { it.message }.joinToString("; ")

    private const val LIBRARY = "sun.security.smartcardio.library"
    private val STALE_CONTEXT = listOf("SCARD_E_NO_SERVICE", "SCARD_E_SERVICE_STOPPED", "SCARD_E_INVALID_HANDLE")
    private val LINUX_LIBRARIES = listOf(
        "/usr/lib/x86_64-linux-gnu/libpcsclite.so.1",
        "/usr/lib/aarch64-linux-gnu/libpcsclite.so.1",
        "/usr/lib/arm-linux-gnueabihf/libpcsclite.so.1",
        "/usr/lib64/libpcsclite.so.1",
        "/usr/lib/libpcsclite.so.1",
        "/lib/x86_64-linux-gnu/libpcsclite.so.1",
    )
}

/**
 * One PC/SC reader as a Multipaz [NfcTagReader]: waits for a target in the field, connects, and hands it to the
 * caller. Every PC/SC call of a scan runs on one thread of its own, since some PC/SC stacks expect that.
 */
class PcscTagReader(private val terminal: CardTerminal) : NfcTagReader {
    override val external = true
    override val dialogAlwaysShown = false
    override val dialogNeverShown = true

    override suspend fun <T : Any> scan(
        message: String?,
        tagInteractionFunc: suspend (tag: NfcIsoTag) -> T?,
        options: NfcScanOptions,
        context: CoroutineContext,
    ): T {
        val io = Executors.newSingleThreadExecutor { r -> Thread(r, "pcsc-" + terminal.name).apply { isDaemon = true } }.asCoroutineDispatcher()
        try {
            while (true) {
                currentCoroutineContext().ensureActive()
                if (!withContext(io) { terminal.waitForCardPresent(POLL_MS) }) continue
                val card = withContext(io) { runCatching { terminal.connect("*") }.getOrNull() }
                if (card == null) {
                    awaitRemoval(io)
                    continue
                }
                val tag = PcscIsoTag(card, io)
                val result = try {
                    tagInteractionFunc(tag)
                } catch (e: NfcTagLostException) {
                    null
                } catch (e: Throwable) {
                    tag.close()
                    throw e
                }
                if (result != null) return result
                // Not what the caller looks for, or gone: wait for it to leave before polling again.
                tag.close()
                awaitRemoval(io)
            }
        } finally {
            io.close()
        }
    }

    private suspend fun awaitRemoval(io: ExecutorCoroutineDispatcher) {
        while (true) {
            currentCoroutineContext().ensureActive()
            val gone = withContext(io) { runCatching { terminal.waitForCardAbsent(POLL_MS) }.getOrDefault(true) }
            if (gone) return
        }
    }

    private companion object {
        const val POLL_MS = 300L
    }
}

/** A connected ISO-DEP target. Short APDUs only, which every PC/SC contactless reader supports. */
private class PcscIsoTag(private val card: Card, private val io: ExecutorCoroutineDispatcher) : NfcIsoTag() {
    private val channel = card.basicChannel
    @Volatile private var closed = false

    override val maxTransceiveLength: Int get() = 261

    override suspend fun transceive(command: CommandApdu): ResponseApdu {
        if (closed) throw NfcTagLostException("The tag was closed")
        val bytes = command.encode()
        val answer = try {
            withContext(io) { channel.transmit(CommandAPDU(bytes)).bytes }
        } catch (e: CardException) {
            throw NfcTagLostException("Tag lost: " + PcscReaders.describe(e), e)
        } catch (e: IllegalStateException) {
            throw NfcTagLostException("Tag lost: " + e.message, e)
        }
        return ResponseApdu.decode(answer)
    }

    override suspend fun close() {
        if (closed) return
        closed = true
        runCatching { withContext(io) { card.disconnect(false) } }.onFailure { runCatching { card.disconnect(false) } }
    }

    override suspend fun updateDialogMessage(message: String) {}
}

package diw.prover

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.FileZkAssetStore
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.ZkPdfNativeEngine
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import java.nio.file.Files
import kotlin.system.exitProcess

private const val USAGE = """Usage: zk-prover-server --assets <dir> [--bind 127.0.0.1] [--port 8787] [--token-file <file>]

Proves zkPDF requests from DIW Wallet with the same native library as the desktop app.
  --assets      directory with the installed zkPDF assets (native/circuits/tools/fetch_assets.py --output <dir>)
  --bind        address to listen on (default 127.0.0.1; use a TLS reverse proxy for access from the Internet)
  --port        port (default 8787)
  --token-file  file holding the access token; otherwise the DIW_PROVER_TOKEN environment variable
The token must have at least 24 characters. Add the server in the wallet under Settings, 零知識證明."""

fun main(args: Array<String>) {
    fun option(name: String): String? = args.indexOf(name).takeIf { it >= 0 }?.let { args.getOrNull(it + 1) }
    if ("--help" in args || "-h" in args) { println(USAGE); return }
    val assets = option("--assets")?.let(::File) ?: fail("--assets is required")
    if (!assets.isDirectory) fail("Asset directory not found")
    val token = (option("--token-file")?.let { File(it).readText().trim() } ?: System.getenv("DIW_PROVER_TOKEN")?.trim())
        ?: fail("Set DIW_PROVER_TOKEN or --token-file")
    if (token.length < ProverService.MIN_TOKEN) fail("The access token must have at least ${ProverService.MIN_TOKEN} characters")
    val bind = option("--bind") ?: "127.0.0.1"
    val port = option("--port")?.toIntOrNull()?.takeIf { it in 1..65535 } ?: 8787

    val nativeDirectory = Files.createTempDirectory("zk-prover").toFile().apply { deleteOnExit() }
    if (ZkNative.load(nativeDirectory) !is ZkResult.Ok) fail("The zero-knowledge native library cannot be loaded on this platform")
    val client = HttpClient(Java)
    val engine = ZkPdfNativeEngine(FileZkAssetStore.bundled(assets, client))
    val service = ProverService(engine, token, CoroutineScope(SupervisorJob() + Dispatchers.Default))
    val ready = service.ready()
    if (ready.isEmpty()) fail("No complete zkPDF composition in $assets")
    println("zk-prover-server: ${ready.joinToString()} ready on http://$bind:$port")
    embeddedServer(Netty, port = port, host = bind) { prover(service) }.start(wait = true)
}

private fun fail(message: String): Nothing {
    System.err.println(message)
    System.err.println()
    System.err.println(USAGE)
    exitProcess(2)
}

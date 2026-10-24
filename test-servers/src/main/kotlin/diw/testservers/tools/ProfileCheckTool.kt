package diw.testservers.tools

import diw.wallet.core.util.DiwJson
import diw.wallet.core.zktls.ZkTlsCheck
import diw.wallet.core.zktls.ZkTlsHolder
import diw.wallet.core.zktls.ZkTlsPlanner
import diw.wallet.core.zktls.ZkTlsProfile
import diw.wallet.core.zktls.ZkTlsSessionRequest
import diw.wallet.core.zktls.ZkTlsTransport
import kotlinx.serialization.json.JsonObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import kotlin.system.exitProcess

/**
 * Checks a zkTLS verification page profile against the real site, on the developer's own machine, before it goes
 * into templates/zktls. It sends exactly the request the wallet would send (ZkTlsPlanner) over TLS 1.2 limited to the
 * cipher suites TLSNotary handles, then applies the holder's reveal plan and the verifier's check to the response.
 *
 * The inputs are read from the console (private ones without echo) and never written anywhere. Field values and the
 * status text are shown only with --show; the response is written only with --save, to a file the developer keeps
 * out of the repository (it holds the query result).
 *
 * Usage: ProfileCheckTool <profile.json> [--show] [--save <file>]
 */
object ProfileCheckTool {
    /** The suites TLSNotary's TLS 1.2 client offers. */
    private val SUITES = arrayOf("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")

    @JvmStatic
    fun main(args: Array<String>) {
        val path = args.firstOrNull { !it.startsWith("--") && args.indexOf(it).let { i -> i == 0 || args[i - 1] != "--save" } }
            ?: usage()
        val show = "--show" in args
        val save = args.indexOf("--save").takeIf { it >= 0 }?.let { args.getOrNull(it + 1) ?: usage() }?.let(::File)

        val profile = try {
            ZkTlsProfile.parse(DiwJson.parseToJsonElement(File(path).readText(Charsets.UTF_8)) as JsonObject)
        } catch (e: Exception) {
            fail("描述檔無法讀取：${e.message}")
        }
        println("查驗頁：${profile.title}（${profile.id}）・${profile.host}:${profile.port}")
        if (profile.prepare.type != "none") {
            println("注意：這個查驗頁需要先開網頁（${profile.prepare.type}），工具無法代為取得 cookie 或圖形驗證碼，結果可能是錯誤頁。")
        }

        val inputs = profile.request.inputs.associate { input ->
            val prompt = input.label + (if (input.isPrivate) "（不顯示）" else "") + "："
            val console = System.console()
            val value = when {
                console != null && input.isPrivate -> console.readPassword(prompt)?.let { String(it) }
                console != null -> console.readLine(prompt)
                else -> { print(prompt); readlnOrNull() }
            }?.trim().orEmpty()
            input.name to value
        }
        val request = try {
            ZkTlsPlanner.request(profile, inputs)
        } catch (e: Exception) {
            fail("輸入不符合描述檔：${e.message}")
        }
        println("請求：${request.size} / ${profile.limits.maxSent} 位元組")

        val (received, tls) = try {
            fetch(profile, request)
        } catch (e: javax.net.ssl.SSLHandshakeException) {
            fail("TLS 交握失敗（網站可能不支援 TLS 1.2 的 ECDHE AES-128-GCM，或憑證不受這台電腦信任）：${e.message}")
        } catch (e: Exception) {
            fail("連線失敗：${e.message}")
        }
        println("TLS：${tls.protocol}・${tls.cipherSuite}")
        tls.chain.forEachIndexed { i, c ->
            println("  憑證 $i：${c.subjectX500Principal.name}・SHA-256 ${sha256(c.encoded)}")
        }
        val head = received.decodeToString(0, minOf(received.size, headEnd(received))).lines()
        println("回應：${head.firstOrNull().orEmpty()}・${received.size} / ${profile.limits.maxRecv} 位元組")
        head.drop(1).filter { it.contains(':') }.map { it.substringBefore(':').trim() to it.substringAfter(':').trim() }
            .filter { (k, _) -> k.lowercase() in setOf("content-type", "content-encoding", "transfer-encoding", "content-length") }
            .forEach { (k, v) -> println("  $k: $v") }
        val problems = mutableListOf<String>()
        if (received.size > profile.limits.maxRecv) problems += "回應超過接收上限，zkTLS 會失敗；請提高 limits.maxRecv（最多 ${ZkTlsProfile.MAX_RECV}）"
        if (head.any { it.lowercase().startsWith("content-encoding:") && !it.lowercase().contains("identity") }) {
            problems += "回應經過壓縮，無法部分揭露"
        }

        save?.let {
            it.writeBytes(received)
            println("已把完整回應存到 ${it.absolutePath}（含查詢結果，請勿放進 repo）")
        }

        val fields = profile.fields.map { it.name }
        val plan = ZkTlsPlanner.receivedReveal(profile, fields, received)
        val sent = ZkTlsPlanner.sentReveal(profile, request)
        val seen = ZkTlsHolder.masked(profile.host, tls.chain.map { it.encoded }, System.currentTimeMillis() / 1000, request, received, sent, plan.received)
        val session = ZkTlsSessionRequest.create(listOf(ZkTlsTransport.Lan("192.168.0.1", 1)), ByteArray(32), profile, fields, "profile check")
        val outcome = ZkTlsCheck.check(session, profile, seen)

        println()
        println("狀態規則：" + when {
            plan.status == null -> "沒有對到"
            outcome.found -> "對到，符合成功條件" + (if (show) "「${outcome.statusText}」" else "（${outcome.statusText?.length} 字）")
            else -> "對到，但不符合成功條件" + (if (show) "「${outcome.statusText}」" else "（${outcome.statusText?.length} 字）")
        })
        profile.fields.forEach { f ->
            val range = plan.fields[f.name]
            val value = outcome.fields[f.name]
            println("欄位 ${f.label}（${f.name}）：" + when {
                range == null -> "沒有對到"
                value == null -> "揭露 ${range.end - range.start} 位元組，但查驗方讀不出值"
                show -> "「$value」，揭露 ${range.end - range.start} 位元組"
                else -> "讀出 ${value.length} 字，揭露 ${range.end - range.start} 位元組"
            })
        }
        val revealed = plan.received.sumOf { it.end - it.start }
        println("揭露：${plan.received.size} 段共 $revealed 位元組（回應的 ${if (received.isEmpty()) 0 else revealed * 100 / received.size}%）")
        problems += outcome.problems
        println()
        if (outcome.passed && problems.isEmpty()) {
            println("結果：通過。描述檔可放進 templates/zktls。")
        } else {
            println("結果：未通過")
            (problems + outcome.missing.map { "沒有讀出欄位 $it" }).distinct().forEach { println("- $it") }
            exitProcess(1)
        }
    }

    private class Tls(val protocol: String, val cipherSuite: String, val chain: List<X509Certificate>)

    private fun fetch(profile: ZkTlsProfile, request: ByteArray): Pair<ByteArray, Tls> {
        val context = SSLContext.getInstance("TLSv1.2").apply { init(null, null, null) }
        val socket = context.socketFactory.createSocket(profile.host, profile.port) as SSLSocket
        socket.use { s ->
            s.soTimeout = 60_000
            s.enabledProtocols = arrayOf("TLSv1.2")
            s.enabledCipherSuites = SUITES.filter { it in s.supportedCipherSuites }.toTypedArray()
            s.sslParameters = s.sslParameters.apply {
                serverNames = listOf(SNIHostName(profile.host))
                endpointIdentificationAlgorithm = "HTTPS"
            }
            s.startHandshake()
            val session = s.session
            val tls = Tls(session.protocol, session.cipherSuite, session.peerCertificates.map { it as X509Certificate })
            s.outputStream.apply { write(request); flush() }
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(16384)
            val cap = profile.limits.maxRecv * 4L
            while (true) {
                val n = s.inputStream.read(buffer)
                if (n < 0) break
                out.write(buffer, 0, n)
                if (out.size() > cap) break
            }
            return out.toByteArray() to tls
        }
    }

    private fun headEnd(bytes: ByteArray): Int {
        for (i in 0 until bytes.size - 3) {
            if (bytes[i] == '\r'.code.toByte() && bytes[i + 1] == '\n'.code.toByte() && bytes[i + 2] == '\r'.code.toByte() && bytes[i + 3] == '\n'.code.toByte()) return i
        }
        return bytes.size
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

    private fun usage(): Nothing {
        System.err.println("Usage: ProfileCheckTool <profile.json> [--show] [--save <file>]")
        exitProcess(2)
    }

    private fun fail(message: String): Nothing {
        System.err.println(message)
        exitProcess(1)
    }
}

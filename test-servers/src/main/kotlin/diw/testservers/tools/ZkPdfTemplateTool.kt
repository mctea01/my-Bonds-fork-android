package diw.testservers.tools

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.pdf.PdfDict
import diw.wallet.core.document.pdf.PdfException
import diw.wallet.core.document.pdf.PdfFile
import diw.wallet.core.document.pdf.PdfNumber
import diw.wallet.core.document.pdf.PdfRef
import diw.wallet.core.document.pdf.PdfStream
import diw.wallet.core.document.pdf.PdfTextExtractor
import diw.wallet.core.document.zkpdf.PdfZkSupport
import diw.wallet.core.document.zkpdf.ZkPdfEvidence
import diw.wallet.core.document.zkpdf.ZkPdfFieldRule
import diw.wallet.core.document.zkpdf.ZkPdfLayout
import diw.wallet.core.document.zkpdf.ZkPdfLexer
import diw.wallet.core.document.zkpdf.ZkPdfNormalize
import diw.wallet.core.document.zkpdf.ZkPdfPlanner
import diw.wallet.core.document.zkpdf.ZkPdfProfile
import diw.wallet.core.document.zkpdf.ZkPdfProofs
import diw.wallet.core.document.zkpdf.ZkPdfVerifier
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.zk.ZkPdfStatement
import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.FileZkAssetStore
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.ZkPdfNativeEngine
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import kotlinx.coroutines.runBlocking
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.io.File
import java.nio.file.Files
import java.text.Normalizer
import kotlin.system.exitProcess
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Checks a zkPDF document template against a real signed PDF on the developer's machine, without printing the
 * document's content unless asked. The PDF and the values never leave the machine and are never committed.
 *
 * Usage:
 * - `ZkPdfTemplateTool <pdf> --outline [--reveal 標籤1,標籤2 | --reveal @labels.txt]`: the text records of page 1 in
 *   order, each as its shape only (中 for a Han character, 9 for a digit, a/A for Latin letters, punctuation kept),
 *   whether its text is unique on the page, and the exact text of records equal to one of the --reveal candidates
 *   (a file holds one candidate per line, for shells that cannot pass Han characters). Use it to find labels.
 * - `ZkPdfTemplateTool <pdf> --template <json> [--show] [--prove <assets dir>] [--root <cer>]`: plans the template,
 *   lists each field as provable (with the value's shape, or the value with --show) or not and why, the windows,
 *   and with --prove runs the real native proof and the full verifier (the signer's chain is trusted only if it
 *   reaches a root given with --root).
 *
 * Both list what stays public in the masked file the verifier receives: the images and forms of the page and the
 * shape of their text. A template must keep every image that carries personal data private, or not be published.
 */
object ZkPdfTemplateTool {
    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) usage()
        val pdf = File(args[0]).takeIf { it.isFile }?.readBytes() ?: usage()
        fun option(name: String) = args.indexOf(name).takeIf { it >= 0 }?.let { args.getOrNull(it + 1) ?: usage() }
        try {
            when {
                option("--template") != null -> runBlocking {
                    check(pdf, File(option("--template")!!), "--show" in args, option("--prove")?.let(::File), option("--root")?.let(::File))
                }
                "--outline" in args -> outline(pdf, labels(option("--reveal")))
                else -> usage()
            }
        } catch (e: PdfException) {
            println("這份 PDF 不符合 zkPDF 的要求（單頁、只能有一個文件簽章、ByteRange 只空出簽章內容、單一內容串流、字型有 ToUnicode），" +
                "或版型的私密圖片不存在")
            exitProcess(1)
        }
    }

    private fun usage(): Nothing {
        System.err.println("Usage: ZkPdfTemplateTool <pdf> --outline [--reveal a,b | --reveal @file] | --template <json> [--show] [--prove <assets dir>] [--root <cer>]")
        exitProcess(2)
    }

    /** Candidate labels: a comma list (trimmed), or a file with one per line kept as written, spaces included. */
    private fun labels(option: String?): List<String> = when {
        option == null -> emptyList()
        option.startsWith("@") -> File(option.drop(1)).readLines(Charsets.UTF_8).map { it.removeSuffix("\r") }
        else -> option.split(',').map { it.trim() }
    }.filter { it.isNotBlank() }

    /** Shape of [text] that keeps its structure and hides its content. */
    fun shape(text: String): String = buildString {
        text.forEach { c ->
            append(
                when {
                    c in '一'..'鿿' || c in '㐀'..'䶿' -> '中'
                    c.isDigit() -> '9'
                    c in 'a'..'z' -> 'a'
                    c in 'A'..'Z' -> 'A'
                    c.isLetter() -> '字'
                    else -> c
                },
            )
        }
    }

    /** [text] with every character outside printable ASCII and the common Han block written as a JSON escape. */
    fun escape(text: String): String = buildString {
        text.forEach { c -> if (c.code in 0x20..0x7e || c in '一'..'鿿') append(c) else append("\\u%04x".format(c.code)) }
    }

    private fun nfkc(text: String): String = Normalizer.normalize(text, Normalizer.Form.NFKC)

    private val probe = ZkPdfProfile("probe.outline/1", "outline", emptyList(),
        listOf(ZkPdfFieldRule("x", "x", listOf("\u0000"), listOf("\u0001"), ZkPdfNormalize.TEXT)))

    private fun texts(pdf: ByteArray, layout: ZkPdfLayout): List<Pair<String, String?>> {
        val signed = PdfZkSupport.signedRevision(pdf, layout.byteRange)
        val content = signed.decode(signed.getObject(layout.windows.first().objectNumber) as PdfStream)
        return ZkPdfLexer.records(content).map { r -> r.font.decodeToString() to ZkPdfPlanner.decodeRecord(r, layout.decoders) }
    }

    private fun outline(pdf: ByteArray, reveal: List<String>) {
        val pages = runCatching { PdfTextExtractor.pages(PdfFile(pdf)).size }.getOrNull()
        if (pages != null && pages != 1) println("這份 PDF 有 $pages 頁；zkPDF v1 只接受單頁文件，因為第 2 頁起會原樣留在查驗方收到的檔案中")
        val layout = ZkPdfPlanner.layout(pdf, probe)
        val window = layout.windows.first()
        println("ByteRange ${layout.byteRange.joinToString(" ")}，內容視窗 ${window.length} bytes（${window.blocks} 區塊）" +
            if (window.keyStream != null) "，RC4 加密" else "")
        val texts = texts(pdf, layout)
        val counts = texts.groupingBy { it.second }.eachCount()
        val folded = reveal.map(::nfkc).toSet()
        println("第 1 頁共 ${texts.size} 個文字運算子，${layout.decoders.size} 個字型")
        texts.forEachIndexed { i, (font, text) ->
            val unique = if (text != null && counts[text] == 1) "唯一" else "重複"
            val shown = when {
                text == null -> "（無法解碼）"
                text in reveal -> "「$text」"
                nfkc(text) in folded -> "「${escape(text)}」（與標籤相容但字碼不同）"
                else -> shape(text)
            }
            println("%4d  %-6s %s  %s".format(i, font, unique, shown))
        }
        publicParts(pdf, layout)
    }

    /** The images and forms that stay readable in the masked file, and the shape of the text those forms draw. */
    private fun publicParts(pdf: ByteArray, layout: ZkPdfLayout) {
        val masked = ZkPdfProofs.masked(pdf.copyOf(layout.byteRange[2] + layout.byteRange[3]), layout)
        val file = PdfFile(masked)
        val private = layout.windows.filter { it.role == "opaque" }.map { it.objectNumber }.toSet()
        val page = PdfTextExtractor.pages(file).first()
        val xobjects = file.dict(file.dict(page["Resources"])?.get("XObject"))?.entries.orEmpty()
        println("查驗方收到的遮蔽檔中，第 1 頁的圖片與表單：" + if (xobjects.isEmpty()) "無" else "")
        for ((name, ref) in xobjects) {
            val stream = file.resolveOrNull(ref) as? PdfStream ?: continue
            val number = (ref as? PdfRef)?.num
            when (stream.dict.name("Subtype")) {
                "Image" -> {
                    val width = (stream.dict["Width"] as? PdfNumber)?.int
                    val height = (stream.dict["Height"] as? PdfNumber)?.int
                    println("  圖片 $name（物件 $number，${width}×${height}，${stream.data.size} bytes）：" + if (number in private) "私密" else "公開")
                }
                "Form" -> {
                    val drawn = PdfDict(page.entries + ("Contents" to PdfStream(PdfDict(emptyMap()), "/$name Do".encodeToByteArray())))
                    val text = runCatching { PdfTextExtractor.pageText(file, drawn) }.getOrNull()
                    val lines = text?.lines()?.map { it.trim() }?.filter { it.isNotEmpty() }
                    println("  表單 $name（物件 $number）公開的文字：" + when {
                        lines == null -> "無法解讀"
                        lines.isEmpty() -> "無"
                        else -> lines.joinToString(" / ") { shape(it) }
                    })
                }
            }
        }
    }

    private suspend fun check(pdf: ByteArray, templateFile: File, show: Boolean, assets: File?, root: File?) {
        val profile = ZkPdfProfile.parse(DiwJson.parseToJsonElement(templateFile.readText(Charsets.UTF_8)) as JsonObject)
        val plan = ZkPdfPlanner.plan(pdf, profile)
        println("版型 ${profile.id}「${profile.title}」：${plan.slots.size}/${profile.fields.size} 個欄位可證明，${plan.anchors.size} 個錨點，" +
            "${plan.layout.windows.size} 個私密視窗（${plan.layout.windows.joinToString("、") { "${it.role} ${it.length} bytes" }}）")
        profile.fields.forEach { f ->
            val slot = plan.slots.firstOrNull { it.claim == f.claim }
            when {
                slot != null -> println("  可證明  ${f.label}（${f.claim}）：" + if (show) slot.value else shape(slot.value))
                else -> println("  無法證明 ${f.label}（${f.claim}）：${plan.unavailable[f.claim]}")
            }
        }
        publicParts(pdf, plan.layout)
        if (assets == null || plan.slots.isEmpty()) return
        val dir = Files.createTempDirectory("zkpdf-native").toFile()
        val client = HttpClient(Java)
        try {
            if (ZkNative.load(dir) !is ZkResult.Ok) { println("無法載入零知識原生程式庫"); return }
            val engine = ZkPdfNativeEngine(FileZkAssetStore.bundled(assets, client))
            val composition = ZkPdfStatement.DESKTOP
            if (!engine.ready(composition, true)) { println("電路檔不完整：$assets"); return }
            // A throwaway key: the check proves the template, not a credential, so no real binding is needed.
            val jwk = buildJsonObject { put("kty", "EC"); put("crv", "P-256"); put("x", "dGVtcGxhdGUtY2hlY2steA"); put("y", "dGVtcGxhdGUtY2hlY2steQ") }
            val started = Clock.System.now()
            val created = when (val r = ZkPdfProofs.create(pdf, plan, jwk, composition, engine, { kind, done, total -> println("  證明 $kind $done/$total") })) {
                is ZkResult.Ok -> r.value
                is ZkResult.Failed -> { println("證明失敗：${r.reason}"); return }
                ZkResult.Cancelled -> return
            }
            println("證明完成：${created.evidence.segments.size} 段，${(Clock.System.now() - started).inWholeSeconds} 秒，遮蔽檔 ${created.evidence.masked.size} bytes，" +
                "證據 ${created.evidence.toJson().toString().length} 字元")
            val disclosed = created.disclosures().toMap()
            val result = ZkPdfVerifier.verify(disclosed.getValue(ZkPdfEvidence.CLAIM) as JsonObject, disclosed, jwk, { if (it == profile.id) profile else null },
                engine, trust(root))
            println("查驗：${result.check}，${result.summary}")
            result.fields.forEach { println("  ${it.label}：${it.check}，${it.detail}") }
            if (result.check == Check.FAIL) exitProcess(1)
        } finally {
            client.close()
            dir.deleteRecursively()
        }
    }

    private suspend fun trust(root: File?): DocumentTrustSource {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy(testEnvironmentEnabled = true))
        root?.let {
            registry.addAnchor(TrustRole.DOCUMENT, TrustEnvironment.USER, X509Cert(ByteString(it.readBytes())), it.name, official = false, source = "template-check")
        }
        return object : DocumentTrustSource {
            override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant): TrustDecision = registry.decide(role, chain, at)
            override suspend fun fetchIssuerCertificates(url: String) = emptyList<ByteArray>()
        }
    }
}

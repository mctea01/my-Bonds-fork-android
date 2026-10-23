package diw.testservers.zkpdf

import diw.testservers.TestPki
import diw.wallet.core.document.pdf.*
import diw.wallet.core.document.sign.*
import diw.wallet.core.util.QrEncoder
import kotlinx.serialization.json.*
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.encryption.AccessPermission
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayOutputStream
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Calendar
import java.util.Date
import java.util.TimeZone
import java.util.zip.DeflaterOutputStream
import kotlin.time.Instant

/** Public, fictional fixtures only. Deterministic keys here must never be used outside tests. */
object SyntheticDocuments {
    const val FIXED_MILLIS = 1792108800000L
    val fixedTime = Instant.fromEpochMilliseconds(FIXED_MILLIS)
    const val MAX_PLAIN = 40960
    val studentText = listOf("仿在學證明", "合成測試", "姓名", "林測試", "學號", "SYN20260001", "出生日期", "2004-02-29", "科系", "資訊工程", "列印日期", "2026-10-16", "不可作為真實文件")
    val travelText = listOf("仿出入境記錄", "合成測試", "姓名", "林測試", "證件號", "SYN0000001", "出生日期", "2004-02-29", "序號", "1", "入境", "2026-09-08", "口岸", "測試北", "航班", "SYN001", "列印日期", "2026-10-16", "不可作為真實文件")
    private val bc = BouncyCastleProvider()
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun pem(label: String, bytes: ByteArray) = "-----BEGIN $label-----\n" + Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(bytes) + "\n-----END $label-----\n"
    private fun keys(label: String): KeyPair = KeyPairGenerator.getInstance("EC", bc).apply {
        val random = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(hash("diw-zkpdf-synthetic-v1/$label".toByteArray())) }
        initialize(ECGenParameterSpec("secp256r1"), random)
    }.generateKeyPair()

    class Material(val pki: TestPki, val signer: DocumentSigner)

    /** Load reproducible test certificates through the same TestPki path as the test servers. */
    suspend fun material(): Material {
        val dir = Files.createTempDirectory("diw-synthetic-pki-").toFile()
        try {
            val keyMap = listOf("iaca", "ds", "reader-root", "wallet-provider-root", "wallet-provider").associateWith(::keys)
            val names = keyMap.keys.associateWith { "C=TW,O=DIW MY WALLET TEST,CN=DIW SYNTHETIC ${it.uppercase()}" }
            for ((index, name) in keyMap.keys.withIndex()) {
                val parent = when (name) { "ds" -> "iaca"; "wallet-provider" -> "wallet-provider-root"; else -> name }
                val isCa = parent == name
                val certificate = JcaX509v3CertificateBuilder(
                    X500Name(names.getValue(parent)), BigInteger.valueOf(1000L + index),
                    Date(1577836800000L), Date(2208988800000L), X500Name(names.getValue(name)), keyMap.getValue(name).public,
                ).apply {
                    val extensions = JcaX509ExtensionUtils()
                    addExtension(Extension.subjectKeyIdentifier, false, extensions.createSubjectKeyIdentifier(keyMap.getValue(name).public))
                    addExtension(Extension.authorityKeyIdentifier, false, extensions.createAuthorityKeyIdentifier(keyMap.getValue(parent).public))
                    addExtension(Extension.basicConstraints, true, BasicConstraints(isCa))
                    addExtension(Extension.keyUsage, true, KeyUsage(if (isCa) KeyUsage.keyCertSign or KeyUsage.cRLSign else KeyUsage.digitalSignature))
                }.build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(bc)
                    .setSecureRandom(SecureRandom.getInstance("SHA1PRNG").apply {
                        setSeed(hash("diw-zkpdf-synthetic-certificate-v1/$name".toByteArray()))
                    }).build(keyMap.getValue(parent).private))
                File(dir, "$name.pem").writeText(pem("CERTIFICATE", certificate.encoded))
                File(dir, "$name.key.pem").writeText(pem("PRIVATE KEY", keyMap.getValue(name).private.encoded))
            }
            val pki = TestPki.create(dir)
            val signer = object : DocumentSigner {
                override val certificateChain = listOf(pki.documentSigner.certChain.certificates.first().encoded.toByteArray(), pki.iacaCert.encoded.toByteArray())
                override val keyType = SignerKeyType.EC_P256
                override val source = SignerSource.PKCS12
                override suspend fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDDSA", bc).run {
                    initSign(keyMap.getValue("ds").private); update(data); sign()
                }
            }
            return Material(pki, signer)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun compressed(bytes: ByteArray) = ByteArrayOutputStream().also { out -> DeflaterOutputStream(out).use { it.write(bytes) } }.toByteArray()

    class Fonts(val directory: File) {
        val metadata = Json.parseToJsonElement(File(directory, "mapping.json").readText()).jsonObject
        val cid = metadata.getValue("cid").jsonObject.mapValues { it.value.jsonPrimitive.int }
        val widths = metadata.getValue("widths").jsonObject.mapValues { it.value.jsonPrimitive.int }
        val bytes = File(directory, "NotoSansCJKsc-Regular-subset.cff").readBytes().also {
            require(hex(hash(it)) == metadata.getValue("subset_sha256").jsonPrimitive.content) { "Synthetic font hash mismatch" }
        }
        fun encode(text: String) = text.map { cid.getValue(it.toString()) }.joinToString("") { "%04X".format(it) }
    }

    private fun content(fonts: Fonts, travel: Boolean, variant: String): String = buildString {
        val lines = if (travel) travelText else studentText
        if (variant == "actual-text") append("/Span << /ActualText <FEFF540862106E2C8A66> >> BDC\n")
        for ((i, text) in lines.withIndex()) {
            val latin = !travel && text.all { it.code in 32..126 }
            val value = if (latin) "($text)" else "<${fonts.encode(text)}>"
            append("BT /${if (latin) "FLatin" else "FHanzi"} 14 Tf 1 0 0 1 55 ${790 - i * 30} Tm [$value] TJ ET\n")
        }
        if (variant == "actual-text") append("EMC\n")
        if (!travel) append("q 80 0 0 80 450 50 cm /Qr Do Q\n")
        if (variant == "inline-image") append("q BI /W 1 /H 1 /BPC 8 /CS /G ID \u0000 EI Q\n")
        if (variant == "oversized") while (length <= MAX_PLAIN) append("% deterministic synthetic padding\n")
    }

    fun unsigned(fonts: Fonts, travel: Boolean, variant: String = "normal"): ByteArray {
        val out = PdfOutput()
        out.append("%PDF-1.7\n")
        out.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R >>")
        out.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        val image = if (travel) "" else "/XObject << /Qr 10 0 R >>"
        out.obj(3, 0, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /FLatin 5 0 R /FHanzi 6 0 R >> $image >> >>")
        out.stream(4, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), compressed(content(fonts, travel, variant).toByteArray()))
        // Helvetica is the PDF standard-14 font: no third-party font bytes are distributed for this resource.
        out.obj(5, 0, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        out.obj(6, 0, "<< /Type /Font /Subtype /Type0 /BaseFont /ZKPDFX+NotoSansCJKsc-Regular /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 8 0 R >>")
        val widths = fonts.widths.entries.sortedBy { it.key.toInt() }.joinToString(" ") { "${it.key} [${it.value}]" }
        out.obj(7, 0, "<< /Type /Font /Subtype /CIDFontType0 /BaseFont /ZKPDFX+NotoSansCJKsc-Regular /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor 11 0 R /DW 1000 /W [$widths] >>")
        val mappings = fonts.cid.entries.sortedBy { it.value }.chunked(80).joinToString("\n") { entries ->
            "${entries.size} beginbfchar\n" + entries.joinToString("\n") { "<${"%04X".format(it.value)}> <${"%04X".format(it.key.single().code)}>" } + "\nendbfchar"
        }
        val cmap = "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Synthetic-UCS def /CMapType 2 def\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n$mappings\nendcmap CMapName currentdict /CMap defineresource pop end end\n"
        out.stream(8, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), compressed(cmap.toByteArray()))
        out.stream(9, 0, PdfDict.of("Subtype" to PdfName("CIDFontType0C"), "Filter" to PdfName("FlateDecode")), compressed(fonts.bytes))
        val qr = QrEncoder.encode("https://synthetic.diw.invalid/verify/SYN20260001?k=0123456789abcdef", forceMask = 0)
        val size = qr.size + 8
        val pixels = ByteArray(size * size) { index ->
            val x = index % size - 4; val y = index / size - 4
            if (x in 0 until qr.size && y in 0 until qr.size && qr[x, y]) 0 else 255.toByte()
        }
        out.stream(10, 0, PdfDict.of("Type" to PdfName("XObject"), "Subtype" to PdfName("Image"), "Width" to PdfNumber.of(size), "Height" to PdfNumber.of(size), "ColorSpace" to PdfName("DeviceGray"), "BitsPerComponent" to PdfNumber.of(8), "Filter" to PdfName("FlateDecode")), compressed(pixels))
        out.obj(11, 0, "<< /Type /FontDescriptor /FontName /ZKPDFX+NotoSansCJKsc-Regular /Flags 4 /FontBBox [-1000 -1000 3000 3000] /ItalicAngle 0 /Ascent 1160 /Descent -288 /CapHeight 733 /StemV 80 /FontFile3 9 0 R >>")
        out.xrefTable(PdfDict.of("Size" to PdfNumber.of(12), "Root" to PdfRef(1, 0), "ID" to PdfArray(List(2) { PdfString(hash("diw-zkpdf-synthetic-id-v1".toByteArray()).copyOf(16), true) })), true)
        return out.bytes()
    }

    private fun encrypt(bytes: ByteArray): ByteArray = Loader.loadPDF(bytes).use { document ->
        document.documentId = FIXED_MILLIS
        document.protect(StandardProtectionPolicy("synthetic-owner-only", "", AccessPermission()).apply {
            encryptionKeyLength = 128; isPreferAES = false
        })
        ByteArrayOutputStream().also { document.save(it) }.toByteArray()
    }

    /** PDFBox supplies a fixed-ID external-signing container; core produces and self-verifies the PAdES CMS. */
    private suspend fun signWithContainer(bytes: ByteArray, signer: DocumentSigner): ByteArray = Loader.loadPDF(bytes).use { document ->
        document.documentId = FIXED_MILLIS
        val signature = PDSignature().apply {
            setFilter(PDSignature.FILTER_ADOBE_PPKLITE)
            setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED)
            signDate = Calendar.getInstance(TimeZone.getTimeZone("UTC")).apply { timeInMillis = FIXED_MILLIS }
        }
        document.addSignature(signature)
        val output = ByteArrayOutputStream()
        val signing = document.saveIncrementalForExternalSigning(output)
        val data = signing.content.use { it.readBytes() }
        signing.setSignature(DocumentSigning.cms(data, signer, encapsulate = false, pades = true, timestamper = null))
        output.toByteArray()
    }

    suspend fun generate(fonts: Fonts, material: Material): LinkedHashMap<String, ByteArray> {
        val result = linkedMapOf<String, ByteArray>()
        for (variant in listOf("normal", "inline-image", "actual-text", "oversized")) {
            val name = if (variant == "normal") "student.pdf" else "student-$variant.pdf"
            result[name] = signWithContainer(unsigned(fonts, false, variant), material.signer)
        }
        result["travel-rc4.pdf"] = signWithContainer(encrypt(unsigned(fonts, true)), material.signer)
        result["student-modified.pdf"] = ZkPdfFixture.replaceContent(result.getValue("student.pdf"))
        result["test-root.cer"] = material.pki.iacaCert.encoded.toByteArray()
        return result
    }
}

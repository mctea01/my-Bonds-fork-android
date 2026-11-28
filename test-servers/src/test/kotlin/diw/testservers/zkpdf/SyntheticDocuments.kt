package diw.testservers.zkpdf

import diw.testservers.TestPki
import diw.wallet.core.document.pdf.*
import diw.wallet.core.document.sign.*
import diw.wallet.core.util.QrEncoder
import kotlinx.serialization.json.*
import org.apache.pdfbox.Loader
import org.apache.pdfbox.pdmodel.PDPage
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
        shared(out, fonts)
        out.xrefTable(PdfDict.of("Size" to PdfNumber.of(12), "Root" to PdfRef(1, 0), "ID" to PdfArray(List(2) { PdfString(hash("diw-zkpdf-synthetic-id-v1".toByteArray()).copyOf(16), true) })), true)
        return out.bytes()
    }

    /** The Latin and CID fonts, their ToUnicode map and font file, and the QR image: objects 5 to 11. */
    private fun shared(out: PdfOutput, fonts: Fonts) {
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
    }

    /** Text that only page 3 of [multiPage] draws, so a test can show that it never reaches the verifier. */
    const val HIDDEN_NAME = "林測試"
    const val HIDDEN_LATIN = "SYN0000001"

    /**
     * Three pages, signed: the student page, the travel page, and a page that draws text through two content
     * streams, a form XObject, a thumbnail and a free-text annotation appearance. Not a committed fixture.
     * [variant] `annotation-text` gives the annotation a text value; `shared-unused` lists the form of page 3 in the
     * resources of page 1 as well, and `shared-drawn` also draws it on page 1; `soft-mask` adds a graphics state on
     * page 3 whose soft mask group draws text; `structure` adds a structure element with actual text, and `outline`
     * a bookmark to page 3; `shading` paints page 3 with a shading and a shading pattern whose stream data carries
     * text, and `marked-content` gives page 3 a marked-content property with actual text; `ink` adds an ink
     * annotation whose coordinates stay in its dictionary, `attachment` a file attachment annotation, and
     * `field-default` a text field whose default value is text, `caption` a push button with a caption, and
     * `thumbnail-mask` gives page 1 a thumbnail with a soft mask image.
     */
    fun unsignedMultiPage(fonts: Fonts, variant: String = "normal"): ByteArray {
        val out = PdfOutput()
        val fontResources = "/Font << /FLatin 5 0 R /FHanzi 6 0 R >>"
        fun flate(text: String) = compressed(text.toByteArray())
        out.append("%PDF-1.7\n")
        val extra = when (variant) {
            "structure" -> " /StructTreeRoot 23 0 R /MarkInfo << /Marked true >>"
            "outline" -> " /Outlines 25 0 R"
            else -> ""
        }
        out.obj(1, 0, "<< /Type /Catalog /Pages 2 0 R$extra >>")
        out.obj(2, 0, "<< /Type /Pages /Kids [3 0 R 12 0 R 14 0 R] /Count 3 >>")
        val shared = if (variant.startsWith("shared")) " /Fm 17 0 R" else ""
        val thumbMask = variant == "thumbnail-mask"
        out.obj(3, 0, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R${if (thumbMask) " /Thumb 21 0 R" else ""} /Resources << $fontResources /XObject << /Qr 10 0 R$shared >> >> >>")
        val first = content(fonts, false, "normal") + if (variant == "shared-drawn") "q 1 0 0 1 0 -400 cm /Fm Do Q\n" else ""
        out.stream(4, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), compressed(first.toByteArray()))
        shared(out, fonts)
        out.obj(12, 0, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 13 0 R /Resources << $fontResources >> >>")
        out.stream(13, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), compressed(content(fonts, true, "normal").toByteArray()))
        val mask = variant == "soft-mask"
        val shading = variant == "shading"
        val marked = variant == "marked-content"
        val states = when {
            mask -> " /ExtGState << /Gs 21 0 R >>"
            shading -> " /Shading << /Sh 21 0 R >> /Pattern << /Pt 22 0 R >>"
            marked -> " /Properties << /Mc << /ActualText ($HIDDEN_LATIN) >> >>"
            else -> ""
        }
        val annotation = if (variant in setOf("ink", "attachment", "field-default", "caption")) " 21 0 R" else ""
        out.obj(14, 0, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents [15 0 R 16 0 R] /Thumb 18 0 R /Annots [19 0 R$annotation] /Resources << $fontResources /XObject << /Fm 17 0 R >>$states >> >>")
        out.stream(15, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), flate("BT /FHanzi 14 Tf 1 0 0 1 55 790 Tm <${fonts.encode(HIDDEN_NAME)}> Tj ET\n"))
        val painted = when {
            mask -> "/Gs gs\n"
            shading -> "q /Sh sh Q\nq /Pattern cs /Pt scn 0 0 595 100 re f Q\n"
            marked -> "/Span /Mc BDC EMC\n"
            else -> ""
        }
        out.stream(16, 0, PdfDict.of("Filter" to PdfName("FlateDecode")), flate(painted + "q 1 0 0 1 0 -60 cm /Fm Do Q\n"))
        val form = PdfDict.of("Type" to PdfName("XObject"), "Subtype" to PdfName("Form"), "Filter" to PdfName("FlateDecode"),
            "BBox" to PdfArray(listOf(PdfNumber.of(0), PdfNumber.of(0), PdfNumber.of(595), PdfNumber.of(842))))
        out.stream(17, 0, form, flate("BT /FLatin 14 Tf 1 0 0 1 55 700 Tm ($HIDDEN_LATIN) Tj ET\n"))
        out.stream(18, 0, PdfDict.of("Width" to PdfNumber.of(1), "Height" to PdfNumber.of(1), "ColorSpace" to PdfName("DeviceGray"),
            "BitsPerComponent" to PdfNumber.of(8), "Filter" to PdfName("FlateDecode")), compressed(byteArrayOf(127)))
        val note = if (variant == "annotation-text") HIDDEN_LATIN else ""
        out.obj(19, 0, "<< /Type /Annot /Subtype /FreeText /Rect [55 600 300 630] /Contents ($note) /DA (/FLatin 12 Tf 0 g) /AP << /N 20 0 R >> >>")
        out.stream(20, 0, PdfDict.of("Type" to PdfName("XObject"), "Subtype" to PdfName("Form"), "Filter" to PdfName("FlateDecode"),
            "BBox" to PdfArray(listOf(PdfNumber.of(0), PdfNumber.of(0), PdfNumber.of(245), PdfNumber.of(30)))),
            flate("BT /FLatin 12 Tf 2 10 Td ($HIDDEN_LATIN) Tj ET\n"))
        if (mask) {
            out.obj(21, 0, "<< /Type /ExtGState /SMask << /Type /Mask /S /Luminosity /G 22 0 R >> >>")
            out.stream(22, 0, PdfDict.of("Type" to PdfName("XObject"), "Subtype" to PdfName("Form"), "Filter" to PdfName("FlateDecode"),
                "BBox" to PdfArray(listOf(PdfNumber.of(0), PdfNumber.of(0), PdfNumber.of(595), PdfNumber.of(842))),
                "Group" to PdfDict.of("S" to PdfName("Transparency"))),
                flate("BT /FLatin 14 Tf 1 0 0 1 55 500 Tm ($HIDDEN_LATIN) Tj ET\n"))
        }
        if (shading) {
            // Free-form shadings whose vertex data spells the hidden text: stream data like any other.
            fun mesh() = PdfDict.of("ShadingType" to PdfNumber.of(4), "ColorSpace" to PdfName("DeviceGray"),
                "BitsPerCoordinate" to PdfNumber.of(8), "BitsPerComponent" to PdfNumber.of(8), "BitsPerFlag" to PdfNumber.of(8),
                "Decode" to PdfArray(listOf(0, 595, 0, 842, 0, 1).map { PdfNumber.of(it) }), "Filter" to PdfName("FlateDecode"))
            out.stream(21, 0, mesh(), compressed(HIDDEN_LATIN.toByteArray()))
            out.obj(22, 0, "<< /Type /Pattern /PatternType 2 /Shading 23 0 R >>")
            out.stream(23, 0, mesh(), compressed(HIDDEN_LATIN.reversed().toByteArray()))
        }
        if (variant == "ink") out.obj(21, 0, "<< /Type /Annot /Subtype /Ink /Rect [55 400 300 430] /InkList [[60 405 80 425 100 405]] >>")
        if (thumbMask) {
            out.stream(21, 0, PdfDict.of("Width" to PdfNumber.of(1), "Height" to PdfNumber.of(1), "ColorSpace" to PdfName("DeviceGray"),
                "BitsPerComponent" to PdfNumber.of(8), "SMask" to PdfRef(22, 0), "Filter" to PdfName("FlateDecode")), compressed(byteArrayOf(127)))
            out.stream(22, 0, PdfDict.of("Type" to PdfName("XObject"), "Subtype" to PdfName("Image"), "Width" to PdfNumber.of(10), "Height" to PdfNumber.of(1),
                "ColorSpace" to PdfName("DeviceGray"), "BitsPerComponent" to PdfNumber.of(8), "Filter" to PdfName("FlateDecode")), compressed(HIDDEN_LATIN.toByteArray()))
        }
        if (variant == "caption") out.obj(21, 0, "<< /Type /Annot /Subtype /Widget /FT /Btn /Ff 65536 /T (b) /Rect [55 400 300 430] /MK << /CA ($HIDDEN_LATIN) >> >>")
        if (variant == "field-default") out.obj(21, 0, "<< /Type /Annot /Subtype /Widget /FT /Tx /T (f) /Rect [55 400 300 430] /DV ($HIDDEN_LATIN) >>")
        if (variant == "attachment") {
            out.obj(21, 0, "<< /Type /Annot /Subtype /FileAttachment /Rect [55 400 70 415] /FS << /Type /Filespec /F (a.txt) /EF << /F 22 0 R >> >> >>")
            out.stream(22, 0, PdfDict.of("Type" to PdfName("EmbeddedFile"), "Filter" to PdfName("FlateDecode")), compressed(HIDDEN_LATIN.toByteArray()))
        }
        if (variant == "structure") {
            out.obj(23, 0, "<< /Type /StructTreeRoot /K 24 0 R >>")
            out.obj(24, 0, "<< /Type /StructElem /S /P /P 23 0 R /Pg 14 0 R /ActualText ($HIDDEN_LATIN) /K 0 >>")
        }
        if (variant == "outline") {
            out.obj(25, 0, "<< /Type /Outlines /First 26 0 R /Last 26 0 R /Count 1 >>")
            out.obj(26, 0, "<< /Title ($HIDDEN_LATIN) /Parent 25 0 R /Dest [14 0 R /Fit] >>")
        }
        val size = when (variant) { "ink", "field-default", "caption" -> 22; "soft-mask", "attachment", "thumbnail-mask" -> 23; "shading" -> 24; "structure" -> 25; "outline" -> 27; else -> 21 }
        out.xrefTable(PdfDict.of("Size" to PdfNumber.of(size), "Root" to PdfRef(1, 0), "ID" to PdfArray(List(2) { PdfString(hash("diw-zkpdf-synthetic-id-v1".toByteArray()).copyOf(16), true) })), true)
        return out.bytes()
    }

    suspend fun multiPage(fonts: Fonts, material: Material, variant: String = "normal"): ByteArray =
        signWithContainer(unsignedMultiPage(fonts, variant), material.signer)

    /**
     * The three pages with an update before signing that changes page 3: `rewritten` writes its first content stream
     * again under the same object number, `replaced` gives the page a new content stream and leaves the old one
     * unreferenced. Either way the earlier text stays in the signed bytes. `cleared` starts from an annotation with
     * text on page 3 and writes it again without, which keeps the text in the earlier version as well; `catalog`
     * writes the catalog again with one more entry, which keeps nothing that the newest version lacks.
     */
    suspend fun updatedBeforeSigning(fonts: Fonts, material: Material, variant: String): ByteArray {
        val base = unsignedMultiPage(fonts, if (variant == "cleared") "annotation-text" else "normal")
        val latin = String(CharArray(base.size) { (base[it].toInt() and 255).toChar() })
        val previous = Regex("startxref\\s+(\\d+)").findAll(latin).last().groupValues[1]
        val id = Regex("/ID\\s*(\\[[^\\]]*\\])").findAll(latin).last().groupValues[1]
        val out = ByteArrayOutputStream().apply { write(base) }
        val offsets = sortedMapOf<Int, Int>()
        fun obj(num: Int, body: ByteArray) {
            offsets[num] = out.size()
            out.write("$num 0 obj\n".toByteArray()); out.write(body); out.write("\nendobj\n".toByteArray())
        }
        val data = compressed("BT /FLatin 14 Tf 1 0 0 1 55 790 Tm (Updated) Tj ET\n".toByteArray())
        val stream = "<< /Length ${data.size} /Filter /FlateDecode >>\nstream\n".toByteArray() + data + "\nendstream".toByteArray()
        val fontResources = "/Font << /FLatin 5 0 R /FHanzi 6 0 R >>"
        when (variant) {
            "rewritten" -> obj(15, stream)
            "cleared" -> obj(19, "<< /Type /Annot /Subtype /FreeText /Rect [55 600 300 630] /Contents () /DA (/FLatin 12 Tf 0 g) /AP << /N 20 0 R >> >>".toByteArray())
            "catalog" -> obj(1, "<< /Type /Catalog /Pages 2 0 R /PageMode /UseNone >>".toByteArray())
            else -> {
            obj(21, stream)
            obj(14, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents [21 0 R 16 0 R] /Thumb 18 0 R /Annots [19 0 R] /Resources << $fontResources /XObject << /Fm 17 0 R >> >> >>".toByteArray())
            }
        }
        val xref = out.size()
        out.write("xref\n0 1\n0000000000 65535 f \n".toByteArray())
        for ((num, offset) in offsets) out.write("$num 1\n${"%010d".format(offset)} 00000 n \n".toByteArray())
        val size = if (variant == "replaced") 22 else 21
        out.write("trailer\n<< /Size $size /Root 1 0 R /Prev $previous /ID $id >>\nstartxref\n$xref\n%%EOF\n".toByteArray())
        return signWithContainer(out.toByteArray(), material.signer)
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

    /** The student document with a blank second page, signed; not a committed fixture. */
    suspend fun twoPages(fonts: Fonts, material: Material): ByteArray {
        val unsigned = Loader.loadPDF(unsigned(fonts, false)).use { document ->
            document.documentId = FIXED_MILLIS
            document.addPage(PDPage())
            ByteArrayOutputStream().also { document.save(it) }.toByteArray()
        }
        return signWithContainer(unsigned, material.signer)
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

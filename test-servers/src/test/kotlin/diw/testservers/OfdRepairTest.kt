package diw.testservers

import diw.wallet.core.document.XmlTree
import diw.wallet.core.document.ofd.OfdObject
import diw.wallet.core.document.ofd.OfdPackage
import diw.wallet.core.document.ofd.OfdText
import diw.wallet.core.document.sign.DocumentSigning
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * OFD files whose producer wrote wrong element and attribute names (the values and the nesting kept): the reader
 * rebuilds them to what a well written file gives. The pages here are made up; the wrong names are of the kinds
 * seen in a real file.
 */
class OfdRepairTest {
    private val ns = "xmlns:ofd=\"http://www.ofdspec.org/2016\""

    private fun png(): ByteArray = ByteArrayOutputStream().also { ImageIO.write(BufferedImage(2, 2, BufferedImage.TYPE_INT_RGB), "png", it) }.toByteArray()

    private fun ofd(content: String, res: String): ByteArray = DocumentSigning.zip(
        listOf(
            "OFD.xml" to "<ofd:OFD $ns Version=\"1.0\" DocType=\"OFD\"><ofd:DocBody><ofd:DocInfo><ofd:DocID>r</ofd:DocID></ofd:DocInfo>" +
                "<ofd:DocRoot>Doc_0/Document.xml</ofd:DocRoot></ofd:DocBody></ofd:OFD>",
            "Doc_0/Document.xml" to "<ofd:Document $ns><ofd:Pages><ofd:Page ID=\"1\" BaseLoc=\"Pages/Page_0/Content.xml\"/></ofd:Pages>" +
                "<ofd:CommonData><ofd:MaxUnitID>99</ofd:MaxUnitID><ofd:PageArea><ofd:PhysicalBox>0 0 200 100</ofd:PhysicalBox></ofd:PageArea>" +
                "<ofd:PublicRes>PublicRes.xml</ofd:PublicRes><ofd:DocumentRes>DocumentRes.xml</ofd:DocumentRes></ofd:CommonData></ofd:Document>",
            "Doc_0/PublicRes.xml" to "<ofd:Res $ns BaseLoc=\"Res\"><ofd:Fonts>" +
                "<ofd:Font FontName=\"DiwTest\" FamilyName=\"DiwTest\" ID=\"7\"><ofd:FontFile>diw-test.ttf</ofd:FontFile></ofd:Font>" +
                "<ofd:Font FontName=\"DiwOther\" FamilyName=\"DiwOther\" ID=\"9\"><ofd:FontFile>diw-test.otf</ofd:FontFile></ofd:Font>" +
                "</ofd:Fonts></ofd:Res>",
            "Doc_0/DocumentRes.xml" to res,
            // The Content ID and the Clips placement are what the producer of the real file writes in every file.
            "Doc_0/Pages/Page_0/Content.xml" to "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- page -->\n<ofd:Page $ns><ofd:Area><ofd:PhysicalBox>0 0 200 100</ofd:PhysicalBox></ofd:Area>" +
                "<ofd:Content ID=\"1\"><ofd:Layer ID=\"2\">$content</ofd:Layer></ofd:Content></ofd:Page>",
        ).map { it.first to it.second.encodeToByteArray() } +
            ("Doc_0/Res/diw-test.ttf" to javaClass.getResourceAsStream("/documents/fonts/diw-test.ttf")!!.readBytes()) +
            ("Doc_0/Res/diw-test.otf" to javaClass.getResourceAsStream("/documents/fonts/diw-test.otf")!!.readBytes()) +
            ("Doc_0/Res/Image-40.png" to png()),
    )

    private val res = "<ofd:Res $ns BaseLoc=\"Res\"><ofd:MultiMedias><ofd:MultiMedia Type=\"Image\" ID=\"40\" Format=\"png\">" +
        "<ofd:MediaFile>Image-40.png</ofd:MediaFile></ofd:MultiMedia></ofd:MultiMedias></ofd:Res>"

    private fun text(id: Int, x: Int, y: Int, font: Int, s: String, red: Boolean = false): String {
        val n = s.codePointCount(0, s.length)
        val delta = if (n > 1) " DeltaX=\"" + List(n - 1) { "3.175" }.joinToString(" ") + "\"" else ""
        return "<ofd:TextObject ID=\"$id\" Boundary=\"$x $y 60.5 3.1750\" Size=\"3.174999952316284\" CTM=\"1 0 0 1 0 0\" Fill=\"true\" Font=\"$font\">" +
            "<ofd:FillColor Value=\"${if (red) "127 0 0" else "0 0 0"}\" Alpha=\"255\" />" +
            "<ofd:CGTransform GlyphCount=\"$n\" CodeCount=\"$n\" CodePosition=\"0\"><ofd:Glyphs>${List(n) { 1 + it % 3 }.joinToString(" ")}</ofd:Glyphs></ofd:CGTransform>" +
            "<ofd:TextCode X=\"0\" Y=\"2.7285\"$delta>$s</ofd:TextCode></ofd:TextObject>"
    }

    private fun line(id: Int, x: Int, y: Int): String =
        "<ofd:PathObject ID=\"$id\" Boundary=\"$x $y 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\">" +
            "<ofd:StrokeColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:Clips TransFlag=\"false\" />" +
            "<ofd:AbbreviatedData>M 0.1323 0.1323 L 94.1323 0.1323</ofd:AbbreviatedData></ofd:PathObject>"

    private val image = "<ofd:ImageObject ID=\"39\" Boundary=\"150 80 3.5278 3.5278\" CTM=\"3.5278 0 0 3.5278 0 0\" ResourceID=\"40\" />"

    /** A page as a well written file has it: lines and texts of two fonts, an image at the end. */
    private val clean = buildString {
        for (i in 0 until 10) append(line(10 + i, 5, 10 + i * 4))
        append(text(20, 10, 20, 7, "购买方信息", red = true))
        append(text(21, 10, 24, 9, "甲乙丙丁有限公司"))
        append(text(22, 10, 28, 7, "名称", red = true))
        append(text(23, 10, 32, 9, "AB中"))
        append(text(24, 10, 36, 9, "12.50"))
        append(text(25, 10, 40, 7, "合计", red = true))
        append(text(26, 10, 44, 9, "*"))
        append(text(27, 10, 48, 9, "戊己庚辛"))
        append(text(28, 10, 52, 7, "备注", red = true))
        append(text(29, 10, 56, 9, "壬癸"))
        append(text(30, 10, 60, 9, "X"))
        append(text(31, 10, 64, 7, "项目名称", red = true))
        append(text(32, 10, 68, 9, "Z"))
        append(image)
    }

    private fun String.swap(old: String, new: String): String {
        assertEquals(1, split(old).size - 1, "one place to change: $old")
        return replace(old, new)
    }

    /** The same page with names written wrong, each of a kind seen in a real file. */
    private val broken = clean
        // A Boundary under the name of an attribute of another element.
        .swap("ID=\"21\" Boundary=", "ID=\"21\" CodeCount=")
        // An ID that could be an Alpha, a Boundary named after an element, a Font named CodePosition, Glyphs named DeltaX.
        .swap("<ofd:TextObject ID=\"22\" Boundary=\"10 28 60.5 3.1750\"", "<ofd:TextObject Alpha=\"22\" ofd:TextObject=\"10 28 60.5 3.1750\"")
        .swap("Font=\"7\"><ofd:FillColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:CGTransform GlyphCount=\"2\" CodeCount=\"2\" CodePosition=\"0\"><ofd:Glyphs>1 2</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175\">名称",
            "CodePosition=\"7\"><ofd:FillColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:CGTransform GlyphCount=\"2\" CodeCount=\"2\" CodePosition=\"0\"><DeltaX>1 2</DeltaX></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175\">名称")
        // A CTM named ID, which took the place of the ID.
        .swap("<ofd:TextObject ID=\"23\" Boundary=\"10 32 60.5 3.1750\" Size=\"3.174999952316284\" CTM=", "<ofd:TextObject Boundary=\"10 32 60.5 3.1750\" Size=\"3.174999952316284\" ID=")
        // A Size that is gone, a TextCode named after an attribute.
        .swap("ID=\"24\" Boundary=\"10 36 60.5 3.1750\" Size=\"3.174999952316284\"", "ID=\"24\" Boundary=\"10 36 60.5 3.1750\"")
        .swap("<ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175 3.175 3.175 3.175\">12.50</ofd:TextCode>", "<LineWidth X=\"0\" Y=\"2.7285\" DeltaX=\"3.175 3.175 3.175 3.175\">12.50</LineWidth>")
        // A Font named GlyphCount, a FillColor named Color with its Value named Fill, a Y named after an element.
        .swap("Font=\"7\"><ofd:FillColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:CGTransform GlyphCount=\"2\" CodeCount=\"2\" CodePosition=\"0\"><ofd:Glyphs>1 2</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175\">合计",
            "GlyphCount=\"7\"><ofd:Color Fill=\"127 0 0\" Alpha=\"255\" /><ofd:CGTransform GlyphCount=\"2\" CodeCount=\"2\" CodePosition=\"0\"><ofd:Glyphs>1 2</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" ofd:Color=\"2.7285\" DeltaX=\"3.175\">合计")
        // A CGTransform named ID, an X that could be an Alpha.
        .swap("<ofd:CGTransform GlyphCount=\"1\" CodeCount=\"1\" CodePosition=\"0\"><ofd:Glyphs>1</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\">*</ofd:TextCode>",
            "<ID GlyphCount=\"1\" CodeCount=\"1\" CodePosition=\"0\"><ofd:Glyphs>1</ofd:Glyphs></ID><ofd:TextCode Alpha=\"0\" Y=\"2.7285\">*</ofd:TextCode>")
        // A CGTransform's CodePosition named Alpha and its Glyphs named Value.
        .swap("CodePosition=\"0\"><ofd:Glyphs>1 2 3 1</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175 3.175 3.175\">戊己庚辛",
            "Alpha=\"0\"><Value>1 2 3 1</Value></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175 3.175 3.175\">戊己庚辛")
        // A Fill named after an element; a FillColor's Value named Font.
        .swap("ID=\"28\" Boundary=\"10 52 60.5 3.1750\" Size=\"3.174999952316284\" CTM=\"1 0 0 1 0 0\" Fill=\"true\" Font=\"7\"><ofd:FillColor Value=",
            "ID=\"28\" Boundary=\"10 52 60.5 3.1750\" Size=\"3.174999952316284\" CTM=\"1 0 0 1 0 0\" ofd:FillColor=\"true\" Font=\"7\"><ofd:FillColor Font=")
        // A CGTransform named FillColor after the FillColor, a TextCode named Y.
        .swap("<ofd:CGTransform GlyphCount=\"2\" CodeCount=\"2\" CodePosition=\"0\"><ofd:Glyphs>1 2</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175\">壬癸</ofd:TextCode>",
            "<ofd:FillColor GlyphCount=\"2\" CodeCount=\"2\" CodePosition=\"0\"><ofd:Glyphs>1 2</ofd:Glyphs></ofd:FillColor><Y X=\"0\" Y=\"2.7285\" DeltaX=\"3.175\">壬癸</Y>")
        // A CGTransform named Y that lost its CodeCount and has its CodePosition named Glyphs, its Glyphs named ID; a TextCode named GlyphCount.
        .swap("<ofd:CGTransform GlyphCount=\"1\" CodeCount=\"1\" CodePosition=\"0\"><ofd:Glyphs>1</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\">X</ofd:TextCode>",
            "<Y GlyphCount=\"1\" ofd:Glyphs=\"0\"><ID>1</ID></Y><GlyphCount X=\"0\" Y=\"2.7285\">X</GlyphCount>")
        // A Font that could be an Alpha.
        .swap("Fill=\"true\" Font=\"7\"><ofd:FillColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:CGTransform GlyphCount=\"4\" CodeCount=\"4\" CodePosition=\"0\"><ofd:Glyphs>1 2 3 1</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175 3.175 3.175\">项目名称",
            "Fill=\"true\" Alpha=\"7\"><ofd:FillColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:CGTransform GlyphCount=\"4\" CodeCount=\"4\" CodePosition=\"0\"><ofd:Glyphs>1 2 3 1</ofd:Glyphs></ofd:CGTransform><ofd:TextCode X=\"0\" Y=\"2.7285\" DeltaX=\"3.175 3.175 3.175\">项目名称")
        // Paths: a Boundary named Font; a LineWidth named ID in place of the ID with the colour's Value named FontFile.
        .swap("ID=\"11\" Boundary=", "ID=\"11\" Font=")
        .swap("<ofd:PathObject ID=\"12\" Boundary=\"5 18 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=",
            "<ofd:PathObject Boundary=\"5 18 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" ID=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor ofd:FontFile=")
        // A Boundary that could not be an Alpha, a Stroke named FontName, the colour's Alpha named ID.
        .swap("<ofd:PathObject ID=\"13\" Boundary=\"5 22 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=\"127 0 0\" Alpha=\"255\" />",
            "<ofd:PathObject ID=\"13\" Alpha=\"5 22 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" FontName=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=\"127 0 0\" ID=\"255\" />")
        // A MiterLimit named Join in place of the Join; the path data named Y; a colour that lost its Value.
        .swap("<ofd:PathObject ID=\"14\" Boundary=\"5 26 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:Clips TransFlag=\"false\" /><ofd:AbbreviatedData>M 0.1323 0.1323 L 94.1323 0.1323</ofd:AbbreviatedData>",
            "<ofd:PathObject ID=\"14\" Boundary=\"5 26 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"3.5278000831604004\"><ofd:StrokeColor Alpha=\"255\" /><ofd:Rule TransFlag=\"false\" /><Y>M 0.1323 0.1323 L 94.1323 0.1323</Y>")
        // A Join named CodeCount, a Fill that could not be an Alpha, a Cap named X, a MiterLimit named after an element.
        .swap("<ofd:PathObject ID=\"15\" Boundary=\"5 30 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=",
            "<ofd:PathObject ID=\"15\" Boundary=\"5 30 94.2646 0.2646\" Rule=\"Even-Odd\" Alpha=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" X=\"Butt\" CodeCount=\"Miter\" ofd:Color=")
        // A PathObject named Color with its ID named GlyphCount and its Cap named ID; one named after an attribute.
        .swap("<ofd:PathObject ID=\"16\" Boundary=\"5 34 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:Clips TransFlag=\"false\" /><ofd:AbbreviatedData>M 0.1323 0.1323 L 94.1323 0.1323</ofd:AbbreviatedData></ofd:PathObject>",
            "<ofd:Color GlyphCount=\"16\" Boundary=\"5 34 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" ID=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:Clips TransFlag=\"false\" /><ofd:AbbreviatedData>M 0.1323 0.1323 L 94.1323 0.1323</ofd:AbbreviatedData></ofd:Color>")
        .swap("<ofd:PathObject ID=\"17\" Boundary=\"5 38 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Value=\"127 0 0\" Alpha=\"255\" /><ofd:Clips TransFlag=\"false\" /><ofd:AbbreviatedData>M 0.1323 0.1323 L 94.1323 0.1323</ofd:AbbreviatedData></ofd:PathObject>",
            "<CodePosition ID=\"17\" Boundary=\"5 38 94.2646 0.2646\" Rule=\"Even-Odd\" Fill=\"false\" Stroke=\"true\" LineWidth=\"0.26460000872612\" Cap=\"Butt\" Join=\"Miter\" MiterLimit=\"3.5278000831604004\"><ofd:StrokeColor Y=\"127 0 0\" Alpha=\"255\" /><ofd:Clips TransFlag=\"false\" /><X>M 0.1323 0.1323 L 94.1323 0.1323</X></CodePosition>")
        // An ImageObject named Glyphs.
        .swap("<ofd:ImageObject ID=\"39\"", "<ofd:Glyphs ID=\"39\"")

    /** The MultiMedia named Glyphs, as the resources of the real file have it. */
    private val brokenRes = res.replace("ofd:MultiMedia ", "ofd:Glyphs ").replace("</ofd:MultiMedia>", "</ofd:Glyphs>")

    /** What an object draws, without the bytes of its font or image. */
    private fun shown(o: OfdObject): String = when (o) {
        is OfdObject.Text -> "text ${o.id} ${o.matrix} a${o.alpha} font ${o.font?.id} ${o.size} ${o.fill} ${o.stroke} ${o.codes} ${o.cg}"
        is OfdObject.Path -> "path ${o.id} ${o.matrix} a${o.alpha} ${o.commands} ${o.fill} ${o.stroke} ${o.lineWidth} ${o.evenOdd} ${o.cap} ${o.join} ${o.miterLimit}"
        is OfdObject.Image -> "image ${o.id} ${o.matrix} a${o.alpha} ${o.media?.id} ${o.media?.format}"
    }

    private fun read(content: String, resources: String) = assertNotNull(OfdPackage.read(DocumentSigning.unzip(ofd(content, resources)))).pages.single()

    @Test
    fun rebuildsWrongNamesFromValuesAndStructure() {
        val good = read(clean, res)
        assertFalse(good.repaired, "a well written page is read as it is")
        assertEquals(24, good.objects.size)
        assertTrue(good.objects.filterIsInstance<OfdObject.Text>().all { it.font?.file != null && it.cg.isNotEmpty() })
        assertEquals("PNG", good.objects.filterIsInstance<OfdObject.Image>().single().media?.format)

        val bad = read(broken, brokenRes)
        assertTrue(bad.repaired)
        val expected = good.objects.map { shown(it) }
        val actual = bad.objects.map { shown(it) }
        for (i in expected.indices) assertEquals(expected[i], actual.getOrNull(i), "object $i")
        assertEquals(expected.size, actual.size)
        assertEquals(good.texts, bad.texts)
        val pkg = assertNotNull(OfdPackage.read(DocumentSigning.unzip(ofd(broken, brokenRes))))
        assertEquals(OfdText.extract(assertNotNull(OfdPackage.read(DocumentSigning.unzip(ofd(clean, res))))), OfdText.extract(pkg))
    }

    @Test
    fun leavesProducerExtensionsAlone() {
        // Attributes and elements that are not of the format (a producer's own) do not make a page a broken one.
        val own = clean
            .swap("<ofd:TextObject ID=\"21\"", "<ofd:TextObject xmlns:v=\"urn:vendor\" v:Tag=\"12\" Lang=\"zh\" ID=\"21\"")
            .swap("<ofd:TextCode X=\"0\" Y=\"2.7285\">Z</ofd:TextCode>", "<ofd:TextCode X=\"0\" Y=\"2.7285\">Z</ofd:TextCode><v:Note xmlns:v=\"urn:vendor\">n</v:Note>")
        val page = read(own, res)
        assertFalse(page.repaired)
        assertEquals(read(clean, res).objects.map { shown(it) }, page.objects.map { shown(it) })
        // Text that reads like numbers or path data stays text.
        val odd = read(clean.swap(">12.50<", ">M 1 2<").swap(">AB中<", ">123<"), res)
        assertFalse(odd.repaired)
        assertEquals(listOf("M 1 2", "123"), listOf(odd.texts["24"], odd.texts["23"]))
    }

    @Test
    fun keepsAttributesInWrittenOrder() {
        val xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ELEMENT r ANY>]><!-- <x b=\"1\"/> --><p:r xmlns:p=\"urn:p\" Zeta=\"1\" alpha=\"2\" p:Mid='3'>" +
            "<![CDATA[<y c=\"1\"/>]]><p:c  Y = \"a>b\" X=\"2\"/><?pi <z d=\"1\"?><d B=\"\" A=\"x\"></d></p:r>"
        val root = assertNotNull(XmlTree.parse(xml.encodeToByteArray())).root
        assertEquals(listOf("Zeta", "alpha", "Mid"), root.attributes.keys.toList())
        assertEquals(listOf("Y", "X"), root.children[0].attributes.keys.toList())
        assertEquals("a>b", root.children[0].attributes["Y"])
        assertEquals(listOf("B", "A"), root.children[1].attributes.keys.toList())
        // A document the scan of the source cannot follow is still read.
        val utf16 = "<r b=\"1\" a=\"2\"><c/></r>".toByteArray(Charsets.UTF_16)
        assertEquals(setOf("a", "b"), assertNotNull(XmlTree.parse(utf16)).root.attributes.keys)
    }
}

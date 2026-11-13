package diw.wallet.core.document.ofd

import diw.wallet.core.document.XmlElement
import diw.wallet.core.document.XmlTree
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.acos
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.math.tan

/**
 * Reads the content of an OFD package (GB/T 33190-2016) from its files: documents, pages with their templates,
 * layers and annotations, resources (fonts, colour spaces, drawing parameters, images, composite units),
 * attachments, custom tags and metadata. Pure Kotlin on [XmlTree]; signatures are checked elsewhere.
 * Paths are resolved the way the standard says (absolute from the package root, else relative to the file that
 * names them) with fallbacks for producers that write them relative to the document or the package root.
 */
class OfdPackage private constructor(val files: Map<String, ByteArray>, val documents: List<OfdDocument>) {

    val pageCount: Int get() = documents.sumOf { it.pages.size }

    /** Every page of every document, in order. */
    val pages: List<OfdPage> get() = documents.flatMap { it.pages }

    companion object {
        /** Pages read at most per document, so a huge file cannot exhaust memory. */
        const val MAX_PAGES = 500

        fun isOfd(files: Map<String, ByteArray>) = "OFD.xml" in files

        /** The package in [files] (the entries of the ZIP), or null when it is not OFD. */
        fun read(files: Map<String, ByteArray>, maxPages: Int = MAX_PAGES): OfdPackage? {
            val normalized = files.mapKeys { normalize(it.key) }
            val ofd = normalized["OFD.xml"]?.let { XmlTree.parse(it)?.root } ?: return null
            val docs = ofd.all("DocBody").mapNotNull { body ->
                val root = body.child("DocRoot")?.text?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null
                runCatching { DocumentReader(normalized, normalize(root), body, maxPages).read() }.getOrNull()
            }
            return OfdPackage(normalized, docs)
        }

        internal fun normalize(p: String): String {
            val out = ArrayList<String>()
            for (part in p.replace('\\', '/').split('/')) when (part) {
                "", "." -> {}
                ".." -> if (out.isNotEmpty()) out.removeAt(out.size - 1)
                else -> out.add(part)
            }
            return out.joinToString("/")
        }

        internal fun dir(path: String) = normalize(path).substringBeforeLast('/', "")

        /** The image format of [bytes] by its signature, else [declared]. */
        fun mediaFormat(bytes: ByteArray, declared: String?): String {
            fun at(i: Int) = if (i < bytes.size) bytes[i].toInt() and 0xFF else -1
            return when {
                at(0) == 0x89 && at(1) == 0x50 && at(2) == 0x4E && at(3) == 0x47 -> "PNG"
                at(0) == 0xFF && at(1) == 0xD8 -> "JPEG"
                at(0) == 0x42 && at(1) == 0x4D -> "BMP"
                at(0) == 0x47 && at(1) == 0x49 && at(2) == 0x46 -> "GIF"
                (at(0) == 0x49 && at(1) == 0x49 && at(2) == 0x2A) || (at(0) == 0x4D && at(1) == 0x4D && at(3) == 0x2A) -> "TIFF"
                at(0) == 0x97 && at(1) == 0x4A && at(2) == 0x42 && at(3) == 0x32 -> "JB2"
                at(0) == 0x50 && at(1) == 0x4B -> "OFD"
                else -> declared?.uppercase()?.let { if (it == "JPG") "JPEG" else it } ?: "UNKNOWN"
            }
        }
    }

    private class DrawParam(val parent: String?, val lineWidth: Double?, val fill: OfdColor?, val stroke: OfdColor?, val cap: String?, val join: String?, val dash: List<Double>?)
    private class ColorSpace(val type: String, val bits: Int, val palette: List<String>)
    private class Unit(val element: XmlElement, val width: Double, val height: Double)

    /** The resources and parsing of one document. */
    private class DocumentReader(val files: Map<String, ByteArray>, val root: String, val body: XmlElement, val maxPages: Int) {
        val docDir = dir(root)
        val fonts = HashMap<String, OfdFont>()
        val colorSpaces = HashMap<String, ColorSpace>()
        val drawParams = HashMap<String, DrawParam>()
        val medias = HashMap<String, OfdMedia>()
        val units = HashMap<String, Unit>()
        var defaultCs: String? = null

        /** [path] named in the file at [from]: absolute, relative to that file, to the document or to the package. */
        fun resolve(path: String, from: String): String? {
            val p = path.trim().ifEmpty { return null }
            val candidates = if (p.startsWith("/")) listOf(normalize(p))
            else listOf(normalize(if (from.isEmpty()) p else "$from/$p"), normalize("$docDir/$p"), normalize(p))
            return candidates.firstOrNull { it in files }
        }

        fun xml(path: String?): XmlElement? = path?.let { files[it] }?.let { XmlTree.parse(it)?.root }

        fun read(): OfdDocument {
            val doc = xml(root) ?: error("Document.xml missing")
            val common = doc.child("CommonData")
            defaultCs = common?.child("DefaultCS")?.text
            for (res in common?.all("PublicRes").orEmpty() + common?.all("DocumentRes").orEmpty()) {
                resolve(res.text, docDir)?.let { loadRes(it) }
            }
            val pageArea = common?.child("PageArea")?.let { area(it) }
            val templates = common?.all("TemplatePage").orEmpty().associate { t ->
                t.attributes["ID"].orEmpty() to (t.attributes["BaseLoc"].orEmpty() to (t.attributes["ZOrder"] ?: "Background"))
            }
            val pageRefs = doc.child("Pages")?.all("Page").orEmpty()
            val annotations = annotations(doc)
            val pages = ArrayList<OfdPage>()
            for ((index, ref) in pageRefs.withIndex()) {
                if (index >= maxPages) break
                val id = ref.attributes["ID"].orEmpty()
                val path = resolve(ref.attributes["BaseLoc"].orEmpty(), docDir) ?: continue
                val page = runCatching { page(id, index, path, pageArea, templates, annotations[id].orEmpty()) }.getOrNull() ?: continue
                pages.add(page)
            }
            val texts = pages.flatMap { it.texts.entries }.associate { it.key to it.value }
            return OfdDocument(
                root = root,
                info = info(body),
                pages = pages,
                attachments = attachments(doc),
                tags = tags(doc, texts),
                signatures = body.child("Signatures")?.text?.let { s -> normalize(s).takeIf { it in files } ?: resolve(s, "") },
            )
        }

        // ------------------------------------------------------------ resources

        fun loadRes(path: String) {
            val res = xml(path) ?: return
            val base = res.attributes["BaseLoc"]?.let { b -> if (b.startsWith("/")) normalize(b) else normalize(dir(path) + "/" + b) } ?: dir(path)
            fun file(name: String?): String? {
                val n = name?.trim()?.ifEmpty { null } ?: return null
                if (n.startsWith("/")) return normalize(n).takeIf { it in files }
                return listOf(normalize("$base/$n"), normalize(dir(path) + "/" + n), normalize("$docDir/$n"), normalize(n))
                    .firstOrNull { it in files } ?: files.keys.firstOrNull { it.endsWith("/" + n.substringAfterLast('/')) }
            }
            for (cs in res.all("ColorSpaces").flatMap { it.all("ColorSpace") }) {
                val id = cs.attributes["ID"] ?: continue
                colorSpaces[id] = ColorSpace(
                    cs.attributes["Type"] ?: "RGB",
                    cs.attributes["BitsPerComponent"]?.toIntOrNull() ?: 8,
                    cs.child("Palette")?.all("CV")?.map { it.text }.orEmpty(),
                )
            }
            for (dp in res.all("DrawParams").flatMap { it.all("DrawParam") }) {
                val id = dp.attributes["ID"] ?: continue
                drawParams[id] = DrawParam(
                    dp.attributes["Relative"],
                    dp.attributes["LineWidth"]?.toDoubleOrNull(),
                    dp.child("FillColor")?.let { color(it) },
                    dp.child("StrokeColor")?.let { color(it) },
                    dp.attributes["Cap"], dp.attributes["Join"],
                    dp.attributes["DashPattern"]?.let { OfdNumbers.list(it) },
                )
            }
            for (f in res.all("Fonts").flatMap { it.all("Font") }) {
                val id = f.attributes["ID"] ?: continue
                val a = f.attributes
                fonts[id] = OfdFont(
                    id, a["FontName"].orEmpty(), a["FamilyName"],
                    a["Bold"] == "true", a["Italic"] == "true", a["Serif"] == "true", a["FixedWidth"] == "true",
                    file(f.child("FontFile")?.text)?.let { files[it] },
                )
            }
            for (m in res.all("MultiMedias").flatMap { it.all("MultiMedia") }) {
                val id = m.attributes["ID"] ?: continue
                val p = file(m.child("MediaFile")?.text) ?: continue
                val bytes = files[p] ?: continue
                medias[id] = OfdMedia(id, mediaFormat(bytes, m.attributes["Format"]), bytes, p)
            }
            for (u in res.all("CompositeGraphicUnits").flatMap { it.all("CompositeGraphicUnit") }) {
                val id = u.attributes["ID"] ?: continue
                units[id] = Unit(u, u.attributes["Width"]?.toDoubleOrNull() ?: 0.0, u.attributes["Height"]?.toDoubleOrNull() ?: 0.0)
            }
        }

        /** A colour element (FillColor, StrokeColor): Value in its colour space, an Index into a palette, or the first colour of a shading. */
        fun color(e: XmlElement): OfdColor {
            val alpha = e.attributes["Alpha"]?.toIntOrNull()?.coerceIn(0, 255) ?: 255
            val cs = e.attributes["ColorSpace"]?.let { colorSpaces[it] } ?: defaultCs?.let { colorSpaces[it] }
            val type = cs?.type?.uppercase() ?: "RGB"
            val bits = cs?.bits ?: 8
            val value = e.attributes["Value"]
                ?: e.attributes["Index"]?.toIntOrNull()?.let { cs?.palette?.getOrNull(it) }
                ?: e.descendants("Segment").firstOrNull()?.child("Color")?.attributes?.get("Value")
                ?: return OfdColor.BLACK.withAlpha(alpha)
            val max = ((1 shl bits.coerceIn(1, 16)) - 1).toDouble()
            val n = value.trim().split(Regex("\\s+")).mapNotNull { t ->
                if (t.startsWith("#")) t.drop(1).toIntOrNull(16)?.toDouble() else t.toDoubleOrNull()
            }.map { (it / max).coerceIn(0.0, 1.0) }
            fun c(v: Double) = (v * 255 + 0.5).toInt().coerceIn(0, 255)
            return when {
                type == "GRAY" && n.isNotEmpty() -> OfdColor(c(n[0]), c(n[0]), c(n[0]), alpha)
                type == "CMYK" && n.size >= 4 -> OfdColor(c((1 - n[0]) * (1 - n[3])), c((1 - n[1]) * (1 - n[3])), c((1 - n[2]) * (1 - n[3])), alpha)
                n.size >= 3 -> OfdColor(c(n[0]), c(n[1]), c(n[2]), alpha)
                n.size == 1 -> OfdColor(c(n[0]), c(n[0]), c(n[0]), alpha)
                else -> OfdColor.BLACK.withAlpha(alpha)
            }
        }

        /** The drawing parameter [id] with what it inherits from its Relative chain. */
        fun param(id: String?): DrawParam? {
            var cur = id?.let { drawParams[it] } ?: return null
            var lw = cur.lineWidth; var fill = cur.fill; var stroke = cur.stroke; var cap = cur.cap; var join = cur.join; var dash = cur.dash
            var depth = 0
            while (depth++ < 8) {
                cur = cur.parent?.let { drawParams[it] } ?: break
                lw = lw ?: cur.lineWidth; fill = fill ?: cur.fill; stroke = stroke ?: cur.stroke
                cap = cap ?: cur.cap; join = join ?: cur.join; dash = dash ?: cur.dash
            }
            return DrawParam(null, lw, fill, stroke, cap, join, dash)
        }

        // ------------------------------------------------------------ pages

        fun area(e: XmlElement): OfdBox? = OfdBox.parse(e.child("PhysicalBox")?.text) ?: OfdBox.parse(e.child("ApplicationBox")?.text)

        fun page(
            id: String, index: Int, path: String, pageArea: OfdBox?,
            templates: Map<String, Pair<String, String>>, annots: List<XmlElement>,
        ): OfdPage {
            val page = xml(path) ?: error("page missing")
            for (res in page.all("PageRes")) resolve(res.text, dir(path))?.let { loadRes(it) }
            val box = page.child("Area")?.let { area(it) } ?: pageArea ?: OfdBox.A4
            val origin = OfdMatrix.translate(-box.x, -box.y)
            val back = ArrayList<OfdObject>()
            val front = ArrayList<OfdObject>()
            for (t in page.all("Template")) {
                val (loc, defaultOrder) = templates[t.attributes["TemplateID"]] ?: continue
                val tplPath = resolve(loc, docDir) ?: continue
                val tpl = xml(tplPath) ?: continue
                for (res in tpl.all("PageRes")) resolve(res.text, dir(tplPath))?.let { loadRes(it) }
                val objects = content(tpl, origin)
                if ((t.attributes["ZOrder"] ?: defaultOrder).equals("Foreground", true)) front.addAll(objects) else back.addAll(objects)
            }
            val objects = back + content(page, origin) + front + annots.flatMap { annot(it, origin) }
            val texts = LinkedHashMap<String, String>()
            objects.filterIsInstance<OfdObject.Text>().forEach { t -> t.id?.let { texts[it] = (texts[it].orEmpty() + t.codes.joinToString("") { c -> c.text }) } }
            return OfdPage(id, index, box, objects, texts)
        }

        /** The layers of a page or template, background first, then body, then foreground. */
        fun content(page: XmlElement, base: OfdMatrix): List<OfdObject> {
            val layers = page.child("Content")?.all("Layer").orEmpty()
            fun rank(l: XmlElement) = when (l.attributes["Type"]?.lowercase()) { "background" -> 0; "foreground" -> 2; else -> 1 }
            return layers.sortedBy { rank(it) }.flatMap { l -> objects(l.children, base, param(l.attributes["DrawParam"]), 0) }
        }

        fun annot(a: XmlElement, base: OfdMatrix): List<OfdObject> {
            if (a.attributes["Visible"] == "false") return emptyList()
            return a.all("Appearance").flatMap { ap ->
                val b = OfdBox.parse(ap.attributes["Boundary"])
                val m = if (b != null) OfdMatrix.translate(b.x, b.y).then(base) else base
                objects(ap.children, m, null, 0)
            }
        }

        fun objects(elements: List<XmlElement>, base: OfdMatrix, inherited: DrawParam?, depth: Int): List<OfdObject> {
            if (depth > 16) return emptyList()
            val out = ArrayList<OfdObject>()
            for (e in elements) {
                if (e.attributes["Visible"] == "false") continue
                when (e.name) {
                    "PageBlock" -> out.addAll(objects(e.children, base, inherited, depth + 1))
                    "TextObject", "PathObject", "ImageObject", "CompositeObject" -> {
                        val b = OfdBox.parse(e.attributes["Boundary"]) ?: OfdBox(0.0, 0.0, 1.0, 1.0)
                        val m = OfdMatrix.parse(e.attributes["CTM"]).then(OfdMatrix.translate(b.x, b.y)).then(base)
                        val p = param(e.attributes["DrawParam"]) ?: inherited
                        val alpha = e.attributes["Alpha"]?.toIntOrNull()?.coerceIn(0, 255) ?: 255
                        val id = e.attributes["ID"]
                        val clips = clips(e, b, base, depth)
                        when (e.name) {
                            "TextObject" -> out.add(text(e, id, m, alpha, p, depth, clips))
                            "PathObject" -> out.add(path(e, id, m, alpha, p, depth, clips))
                            "ImageObject" -> out.add(OfdObject.Image(id, m, alpha, e.attributes["ResourceID"]?.let { medias[it] }, clips))
                            else -> e.attributes["ResourceID"]?.let { units[it] }?.let { u ->
                                val inner = objects(u.element.child("Content")?.children.orEmpty(), m, p, depth + 1)
                                out.addAll(if (clips.isEmpty()) inner else inner.map { withClips(it, clips) })
                            }
                        }
                    }
                }
            }
            return out
        }

        fun text(e: XmlElement, id: String?, m: OfdMatrix, alpha: Int, p: DrawParam?, depth: Int, clips: List<OfdClip>): OfdObject.Text {
            val a = e.attributes
            val fill = if (a["Fill"] == "false") null else e.child("FillColor")?.let { color(it) } ?: p?.fill ?: OfdColor.BLACK
            val stroke = if (a["Stroke"] != "true") null else e.child("StrokeColor")?.let { color(it) } ?: p?.stroke ?: OfdColor.BLACK
            fun clean(c: XmlElement) = c.rawText.replace("\r", "").replace("\n", "")
            val codes = e.all("TextCode").map { c ->
                OfdTextCode(
                    c.attributes["X"]?.toDoubleOrNull(), c.attributes["Y"]?.toDoubleOrNull(),
                    OfdNumbers.deltas(c.attributes["DeltaX"]), OfdNumbers.deltas(c.attributes["DeltaY"]),
                    clean(c),
                )
            }
            // CGTransform counts characters of the TextCode that follows it (positions run on across TextCodes).
            val cg = ArrayList<OfdCgTransform>()
            val pending = ArrayList<XmlElement>()
            var offset = 0
            fun flush() {
                for (t in pending) {
                    val glyphs = t.child("Glyphs")?.text?.trim()?.split(Regex("\\s+"))?.mapNotNull { it.toIntOrNull() }.orEmpty()
                    if (glyphs.isEmpty()) continue
                    cg.add(OfdCgTransform(offset + (t.attributes["CodePosition"]?.toIntOrNull() ?: 0), t.attributes["CodeCount"]?.toIntOrNull() ?: 1, glyphs))
                }
                pending.clear()
            }
            for (c in e.children) when (c.name) {
                "CGTransform" -> pending.add(c)
                "TextCode" -> { flush(); offset += OfdNumbers.codePoints(clean(c)).size }
            }
            offset = 0
            flush()
            return OfdObject.Text(
                id, m, alpha, a["Font"]?.let { fonts[it] }, a["Size"]?.toDoubleOrNull() ?: 3.5, fill, stroke,
                a["HScale"]?.toDoubleOrNull() ?: 1.0, a["Weight"]?.toIntOrNull() ?: 400, a["Italic"] == "true",
                a["ReadDirection"]?.toIntOrNull() ?: 0, a["CharDirection"]?.toIntOrNull() ?: 0, codes, cg,
                e.child("FillColor")?.let { shade(it, depth) }, clips,
            )
        }

        fun path(e: XmlElement, id: String?, m: OfdMatrix, alpha: Int, p: DrawParam?, depth: Int, clips: List<OfdClip>): OfdObject.Path {
            val a = e.attributes
            val fill = if (a["Fill"] != "true") null else e.child("FillColor")?.let { color(it) } ?: p?.fill ?: OfdColor.BLACK
            val stroke = if (a["Stroke"] == "false") null else e.child("StrokeColor")?.let { color(it) } ?: p?.stroke ?: OfdColor.BLACK
            return OfdObject.Path(
                id, m, alpha, abbreviated(e.child("AbbreviatedData")?.text.orEmpty()), fill, stroke,
                a["LineWidth"]?.toDoubleOrNull() ?: p?.lineWidth ?: 0.353,
                a["Rule"].equals("Even-Odd", true), a["Cap"] ?: p?.cap ?: "Butt", a["Join"] ?: p?.join ?: "Miter",
                a["DashPattern"]?.let { OfdNumbers.list(it) } ?: p?.dash.orEmpty(),
                if (fill != null) e.child("FillColor")?.let { shade(it, depth) } else null,
                if (stroke != null) e.child("StrokeColor")?.let { shade(it, depth) } else null,
                a["MiterLimit"]?.toDoubleOrNull() ?: 4.234,
                clips,
            )
        }

        fun withClips(o: OfdObject, c: List<OfdClip>): OfdObject = when (o) {
            is OfdObject.Text -> o.copy(clips = o.clips + c)
            is OfdObject.Path -> o.copy(clips = o.clips + c)
            is OfdObject.Image -> o.copy(clips = o.clips + c)
        }

        // ------------------------------------------------------------ clips and shadings

        /** The points of [cmds] through [m]. */
        fun bounds(cmds: List<OfdPathCommand>, m: OfdMatrix): DoubleArray? {
            var minX = Double.MAX_VALUE; var minY = Double.MAX_VALUE; var maxX = -Double.MAX_VALUE; var maxY = -Double.MAX_VALUE
            fun add(x: Double, y: Double) {
                val px = m.x(x, y); val py = m.y(x, y)
                minX = minOf(minX, px); minY = minOf(minY, py); maxX = maxOf(maxX, px); maxY = maxOf(maxY, py)
            }
            for (c in cmds) when (c) {
                is OfdPathCommand.Move -> add(c.x, c.y)
                is OfdPathCommand.Line -> add(c.x, c.y)
                is OfdPathCommand.Quad -> { add(c.x1, c.y1); add(c.x, c.y) }
                is OfdPathCommand.Cubic -> { add(c.x1, c.y1); add(c.x2, c.y2); add(c.x, c.y) }
                OfdPathCommand.Close -> {}
            }
            return if (minX == Double.MAX_VALUE) null else doubleArrayOf(minX, minY, maxX, maxY)
        }

        fun overlaps(a: DoubleArray?, b: DoubleArray?) = a != null && b != null && a[0] <= b[2] && b[0] <= a[2] && a[1] <= b[3] && b[1] <= a[3]

        /**
         * The clips of an object (GB/T 33190 8.4): areas in the object's coordinate space (its Boundary), each with its
         * own CTM. Some producers give the clip path in page space instead; a path that only meets the object that way
         * is read so.
         */
        fun clips(e: XmlElement, b: OfdBox, base: OfdMatrix, depth: Int): List<OfdClip> {
            val list = e.child("Clips")?.all("Clip").orEmpty()
            if (list.isEmpty()) return emptyList()
            val objectSpace = OfdMatrix.translate(b.x, b.y).then(base)
            val objectBox = bounds(listOf(OfdPathCommand.Move(0.0, 0.0), OfdPathCommand.Line(b.w, b.h), OfdPathCommand.Line(0.0, b.h), OfdPathCommand.Line(b.w, 0.0)), objectSpace)
            return list.mapNotNull { c ->
                val areas = c.all("Area").mapNotNull { a ->
                    val actm = OfdMatrix.parse(a.attributes["CTM"])
                    val p = param(a.attributes["DrawParam"])
                    val pe = a.child("Path")
                    val te = a.child("Text")
                    fun origin(x: XmlElement): OfdMatrix {
                        val n = OfdNumbers.list(x.attributes["Boundary"])
                        return OfdMatrix.parse(x.attributes["CTM"]).then(OfdMatrix.translate(n.getOrElse(0) { 0.0 }, n.getOrElse(1) { 0.0 }))
                    }
                    when {
                        pe != null -> {
                            val cmds = abbreviated(pe.child("AbbreviatedData")?.text.orEmpty())
                            val inner = origin(pe).then(actm)
                            val primary = inner.then(objectSpace)
                            val alternative = inner.then(base)
                            val m = if (!overlaps(bounds(cmds, primary), objectBox) && overlaps(bounds(cmds, alternative), objectBox)) alternative else primary
                            OfdClipArea(m, cmds, pe.attributes["Rule"].equals("Even-Odd", true), null)
                        }
                        te != null -> {
                            val m = origin(te).then(actm).then(objectSpace)
                            OfdClipArea(m, emptyList(), false, text(te, null, m, 255, p, depth + 1, emptyList()))
                        }
                        else -> null
                    }
                }
                if (areas.isEmpty()) null else OfdClip(areas)
            }
        }

        fun point(s: String?): Pair<Double, Double>? = OfdNumbers.list(s).takeIf { it.size >= 2 }?.let { it[0] to it[1] }

        fun stops(e: XmlElement): List<OfdColorStop> {
            val segs = e.all("Segment")
            return segs.mapIndexedNotNull { i, sg ->
                val c = sg.child("Color") ?: return@mapIndexedNotNull null
                val pos = sg.attributes["Position"]?.toDoubleOrNull() ?: if (segs.size > 1) i.toDouble() / (segs.size - 1) else 0.0
                OfdColorStop(pos.coerceIn(0.0, 1.0), color(c))
            }.sortedBy { it.position }
        }

        /** The shading or pattern of a FillColor or StrokeColor, or null for a plain colour. */
        fun shade(c: XmlElement, depth: Int): OfdShade? {
            c.child("AxialShd")?.let { a ->
                val (x0, y0) = point(a.attributes["StartPoint"]) ?: return null
                val (x1, y1) = point(a.attributes["EndPoint"]) ?: return null
                val ext = a.attributes["Extend"]?.toIntOrNull() ?: 0
                val st = stops(a).ifEmpty { return null }
                return OfdShade.Axial(x0, y0, x1, y1, st, ext == 1 || ext == 3, ext == 2 || ext == 3, a.attributes["MapType"] ?: "Direct", a.attributes["MapUnit"]?.toDoubleOrNull() ?: 0.0)
            }
            c.child("RadialShd")?.let { a ->
                val (x0, y0) = point(a.attributes["StartPoint"]) ?: return null
                val (x1, y1) = point(a.attributes["EndPoint"]) ?: return null
                val ext = a.attributes["Extend"]?.toIntOrNull() ?: 0
                val st = stops(a).ifEmpty { return null }
                return OfdShade.Radial(
                    x0, y0, a.attributes["StartRadius"]?.toDoubleOrNull() ?: 0.0, x1, y1, a.attributes["EndRadius"]?.toDoubleOrNull() ?: return null,
                    (a.attributes["Eccentricity"]?.toDoubleOrNull() ?: 0.0).coerceIn(0.0, 0.999), a.attributes["Angle"]?.toDoubleOrNull() ?: 0.0,
                    st, ext == 1 || ext == 3, ext == 2 || ext == 3, a.attributes["MapType"] ?: "Direct", a.attributes["MapUnit"]?.toDoubleOrNull() ?: 0.0,
                )
            }
            fun shadePoint(pe: XmlElement): OfdShadePoint? {
                val x = pe.attributes["X"]?.toDoubleOrNull() ?: return null
                val y = pe.attributes["Y"]?.toDoubleOrNull() ?: return null
                return OfdShadePoint(x, y, pe.child("Color")?.let { color(it) } ?: OfdColor.BLACK)
            }
            c.child("GouraudShd")?.let { g ->
                // Triangles as in a free-form mesh: EdgeFlag 0 starts one, 1 and 2 add one from the previous triangle's points.
                val tris = ArrayList<List<OfdShadePoint>>()
                var cur = ArrayList<OfdShadePoint>()
                for (pe in g.all("Point")) {
                    val pt = shadePoint(pe) ?: continue
                    val flag = pe.attributes["EdgeFlag"]?.toIntOrNull() ?: 0
                    val last = tris.lastOrNull()
                    when {
                        cur.size < 3 && (flag == 0 || last == null) -> { cur.add(pt); if (cur.size == 3) { tris.add(cur); cur = ArrayList() } }
                        flag == 1 && last != null -> tris.add(listOf(last[1], last[2], pt))
                        flag == 2 && last != null -> tris.add(listOf(last[0], last[2], pt))
                        else -> { cur = arrayListOf(pt) }
                    }
                }
                if (tris.isEmpty()) return null
                return OfdShade.Gouraud(tris, g.attributes["Extend"] == "1", g.child("BackColor")?.let { color(it) })
            }
            c.child("LaGouraudShd")?.let { g ->
                val perRow = g.attributes["VerticesPerRow"]?.toIntOrNull()?.takeIf { it >= 2 } ?: return null
                val pts = g.all("Point").mapNotNull { shadePoint(it) }
                val rows = pts.size / perRow
                val tris = ArrayList<List<OfdShadePoint>>()
                for (r in 0 until rows - 1) for (k in 0 until perRow - 1) {
                    val a0 = pts[r * perRow + k]; val a1 = pts[r * perRow + k + 1]
                    val b0 = pts[(r + 1) * perRow + k]; val b1 = pts[(r + 1) * perRow + k + 1]
                    tris.add(listOf(a0, a1, b0)); tris.add(listOf(a1, b1, b0))
                }
                if (tris.isEmpty()) return null
                return OfdShade.Gouraud(tris, g.attributes["Extend"] == "1", g.child("BackColor")?.let { color(it) })
            }
            c.child("Pattern")?.let { pt ->
                if (depth > 8) return null
                val w = pt.attributes["Width"]?.toDoubleOrNull()?.takeIf { it > 0 } ?: return null
                val h = pt.attributes["Height"]?.toDoubleOrNull()?.takeIf { it > 0 } ?: return null
                val cell = pt.child("CellContent") ?: return null
                return OfdShade.Pattern(
                    w, h, pt.attributes["XStep"]?.toDoubleOrNull()?.takeIf { it > 0 } ?: w, pt.attributes["YStep"]?.toDoubleOrNull()?.takeIf { it > 0 } ?: h,
                    OfdMatrix.parse(pt.attributes["CTM"]), pt.attributes["ReflectMethod"] ?: "Normal",
                    pt.attributes["RelativeTo"].equals("Page", true), objects(cell.children, OfdMatrix.IDENTITY, null, depth + 1),
                )
            }
            return null
        }

        // ------------------------------------------------------------ annotations, attachments, tags, info

        fun annotations(doc: XmlElement): Map<String, List<XmlElement>> {
            val out = HashMap<String, MutableList<XmlElement>>()
            for (loc in doc.all("Annotations")) {
                val path = resolve(loc.text, docDir) ?: continue
                val list = xml(path) ?: continue
                for (p in list.all("Page")) {
                    val pageId = p.attributes["PageID"] ?: continue
                    val file = resolve(p.child("FileLoc")?.text.orEmpty(), dir(path)) ?: continue
                    xml(file)?.all("Annot")?.let { out.getOrPut(pageId) { ArrayList() }.addAll(it) }
                }
            }
            return out
        }

        fun attachments(doc: XmlElement): List<OfdAttachment> = doc.all("Attachments").flatMap { loc ->
            val path = resolve(loc.text, docDir) ?: return@flatMap emptyList()
            val list = xml(path) ?: return@flatMap emptyList()
            list.all("Attachment").mapNotNull { a ->
                val fileLoc = a.child("FileLoc")?.text ?: return@mapNotNull null
                val p = resolve(fileLoc, dir(path)) ?: normalize(dir(path) + "/" + fileLoc)
                OfdAttachment(
                    a.attributes["ID"], a.attributes["Name"]?.ifEmpty { null } ?: fileLoc.substringAfterLast('/'),
                    a.attributes["Format"], a.attributes["CreationDate"], p, files[p],
                )
            }
        }

        fun tags(doc: XmlElement, texts: Map<String, String>): List<OfdCustomTag> = doc.all("CustomTags").flatMap { loc ->
            val path = resolve(loc.text, docDir) ?: return@flatMap emptyList()
            val list = xml(path) ?: return@flatMap emptyList()
            list.all("CustomTag").mapNotNull { t ->
                val p = resolve(t.child("FileLoc")?.text.orEmpty(), dir(path)) ?: return@mapNotNull null
                val bytes = files[p] ?: return@mapNotNull null
                OfdCustomTag(t.attributes["NameSpace"], p, OfdTags.values(bytes, texts))
            }
        }

        fun info(body: XmlElement): OfdDocInfo {
            val i = body.child("DocInfo")
            fun v(n: String) = i?.child(n)?.text?.ifEmpty { null }
            return OfdDocInfo(
                v("DocID"), v("Title"), v("Author"), v("Subject"), v("Creator"), v("CreationDate"),
                i?.child("CustomDatas")?.all("CustomData")?.mapNotNull { c -> c.attributes["Name"]?.let { it to c.text } }.orEmpty(),
            )
        }

        // ------------------------------------------------------------ abbreviated path data

        /** GB/T 33190 9.3.6: S/M move, L line, Q quadratic, B cubic, A arc, C close; arcs become cubic curves. */
        fun abbreviated(data: String): List<OfdPathCommand> {
            val t = data.trim().split(Regex("[\\s,]+")).filter { it.isNotEmpty() }
            val out = ArrayList<OfdPathCommand>()
            var i = 0
            var cx = 0.0; var cy = 0.0
            var sx = 0.0; var sy = 0.0
            fun num(): Double? = t.getOrNull(i)?.toDoubleOrNull()?.also { i++ }
            while (i < t.size) {
                val op = t[i++]
                when (op) {
                    "S", "M" -> { val x = num() ?: break; val y = num() ?: break; out.add(OfdPathCommand.Move(x, y)); cx = x; cy = y; sx = x; sy = y }
                    "L" -> { val x = num() ?: break; val y = num() ?: break; out.add(OfdPathCommand.Line(x, y)); cx = x; cy = y }
                    "Q" -> {
                        val n = List(4) { num() ?: return out }
                        out.add(OfdPathCommand.Quad(n[0], n[1], n[2], n[3])); cx = n[2]; cy = n[3]
                    }
                    "B" -> {
                        val n = List(6) { num() ?: return out }
                        out.add(OfdPathCommand.Cubic(n[0], n[1], n[2], n[3], n[4], n[5])); cx = n[4]; cy = n[5]
                    }
                    "A" -> {
                        val n = List(7) { num() ?: return out }
                        out.addAll(arc(cx, cy, n[0], n[1], n[2], n[3] != 0.0, n[4] != 0.0, n[5], n[6])); cx = n[5]; cy = n[6]
                    }
                    "C" -> { out.add(OfdPathCommand.Close); cx = sx; cy = sy }
                    else -> {}
                }
            }
            return out
        }

        /** An elliptical arc in endpoint form (as SVG), as cubic curves of at most 90 degrees. */
        fun arc(x1: Double, y1: Double, rx0: Double, ry0: Double, angleDeg: Double, large: Boolean, sweep: Boolean, x2: Double, y2: Double): List<OfdPathCommand> {
            if (x1 == x2 && y1 == y2) return emptyList()
            var rx = abs(rx0); var ry = abs(ry0)
            if (rx == 0.0 || ry == 0.0) return listOf(OfdPathCommand.Line(x2, y2))
            val phi = angleDeg * PI / 180
            val cosP = cos(phi); val sinP = sin(phi)
            val dx = (x1 - x2) / 2; val dy = (y1 - y2) / 2
            val x1p = cosP * dx + sinP * dy
            val y1p = -sinP * dx + cosP * dy
            val lambda = (x1p * x1p) / (rx * rx) + (y1p * y1p) / (ry * ry)
            if (lambda > 1) { val s = sqrt(lambda); rx *= s; ry *= s }
            val num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
            val den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
            var coef = if (den == 0.0) 0.0 else sqrt(max(0.0, num / den))
            if (large == sweep) coef = -coef
            val cxp = coef * rx * y1p / ry
            val cyp = -coef * ry * x1p / rx
            val cx = cosP * cxp - sinP * cyp + (x1 + x2) / 2
            val cy = sinP * cxp + cosP * cyp + (y1 + y2) / 2
            fun angle(ux: Double, uy: Double, vx: Double, vy: Double): Double {
                val dot = ux * vx + uy * vy
                val len = sqrt(ux * ux + uy * uy) * sqrt(vx * vx + vy * vy)
                val a = acos((dot / len).coerceIn(-1.0, 1.0))
                return if (ux * vy - uy * vx < 0) -a else a
            }
            val theta1 = angle(1.0, 0.0, (x1p - cxp) / rx, (y1p - cyp) / ry)
            var delta = angle((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry)
            if (!sweep && delta > 0) delta -= 2 * PI
            if (sweep && delta < 0) delta += 2 * PI
            val segments = ceil(abs(delta) / (PI / 2)).toInt().coerceIn(1, 8)
            val step = delta / segments
            val k = 4.0 / 3.0 * tan(step / 4)
            val out = ArrayList<OfdPathCommand>()
            var t = theta1
            fun px(a: Double, b: Double) = cx + rx * cosP * a - ry * sinP * b
            fun py(a: Double, b: Double) = cy + rx * sinP * a + ry * cosP * b
            repeat(segments) { s ->
                val t2 = t + step
                val c1 = cos(t); val s1 = sin(t); val c2 = cos(t2); val s2 = sin(t2)
                val ex = if (s == segments - 1) x2 else px(c2, s2)
                val ey = if (s == segments - 1) y2 else py(c2, s2)
                out.add(OfdPathCommand.Cubic(px(c1 - k * s1, s1 + k * c1), py(c1 - k * s1, s1 + k * c1), px(c2 + k * s2, s2 - k * c2), py(c2 + k * s2, s2 - k * c2), ex, ey))
                t = t2
            }
            return out
        }
    }
}

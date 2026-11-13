package diw.wallet.core.document.ofd

import diw.wallet.core.document.XmlElement

/**
 * Recovery of page content and resources whose producer wrote wrong element or attribute names while keeping the
 * values and the nesting. Seen in the wild: a Boundary written as CodeCount, a Font as CodePosition, a TextCode as Y,
 * an ImageObject and a MultiMedia as Glyphs, and a renamed attribute that met an existing one of that name
 * replacing it. What reads as the schema of GB/T 33190-2016 (annex A) says is returned as it is. A broken page is
 * rebuilt from what the schema allows: each object and child element is known by what it holds (path data, glyph
 * lists, text, colours), and each attribute by the shape of its value and by its place in the attribute order the
 * well written elements of the page use. Nothing here knows what kind of document the page is.
 */
internal object OfdRepair {
    private val OBJECTS = setOf("TextObject", "PathObject", "ImageObject", "CompositeObject", "PageBlock")
    private val SPACE = Regex("\\s+")
    private val INT = Regex("\\d+")
    private val PATH = Regex("^[SM]\\s+[-+.\\d]")

    private val COMMON = listOf(
        "ID", "Boundary", "Name", "Visible", "CTM", "DrawParam", "LineWidth", "Cap", "Join", "MiterLimit", "DashOffset", "DashPattern", "Alpha",
    )

    /** The attributes the standard gives each element. */
    private val VALID = mapOf(
        "TextObject" to (COMMON + listOf("Font", "Size", "Stroke", "Fill", "HScale", "ReadDirection", "CharDirection", "Weight", "Italic")).toSet(),
        "PathObject" to (COMMON + listOf("Stroke", "Fill", "Rule")).toSet(),
        "ImageObject" to (COMMON + listOf("ResourceID", "Substitution", "ImageMask")).toSet(),
        "TextCode" to setOf("X", "Y", "DeltaX", "DeltaY"),
        "CGTransform" to setOf("CodePosition", "CodeCount", "GlyphCount"),
        "FillColor" to setOf("Value", "Index", "ColorSpace", "Alpha"),
        "StrokeColor" to setOf("Value", "Index", "ColorSpace", "Alpha"),
    )

    /** The child elements the standard gives each object. */
    private val CHILDREN = mapOf(
        "TextObject" to setOf("FillColor", "StrokeColor", "CGTransform", "TextCode", "Clips", "Actions"),
        "PathObject" to setOf("FillColor", "StrokeColor", "AbbreviatedData", "Clips", "Actions"),
        "ImageObject" to setOf("Border", "Clips", "Actions"),
    )

    /** Names of the format: one of these where the standard does not put it is a wrong name, not a producer's own. */
    private val VOCABULARY: Set<String> = VALID.values.flatten().toSet() + VALID.keys + OBJECTS + setOf(
        "Glyphs", "AbbreviatedData", "Clips", "Clip", "Area", "Path", "Text", "Layer", "Content", "Page", "Color", "Border", "Actions",
        "TransFlag", "FontName", "FamilyName", "FontFile", "Type", "Format", "MediaFile", "BaseLoc", "PhysicalBox", "Template",
    )

    /** Attributes an object cannot be drawn without. */
    private val CORE = mapOf(
        "TextObject" to listOf("Boundary", "Font", "Size"),
        "PathObject" to listOf("Boundary"),
        "ImageObject" to listOf("Boundary", "ResourceID"),
    )

    private class Ids(val fonts: Set<String>, val medias: Set<String>)

    private fun tokens(v: String) = v.trim().split(SPACE).filter { it.isNotEmpty() }

    private fun numbers(v: String): List<Double>? {
        val t = tokens(v)
        if (t.isEmpty()) return null
        return t.map { it.toDoubleOrNull() ?: return null }
    }

    private fun word(v: String, vararg options: String) = options.any { it.equals(v.trim(), true) }

    /**
     * True when [value] has the shape of attribute [name]. With [strict] (a value looking for its name) a Font or a
     * ResourceID must also be one the document defines.
     */
    private fun fits(name: String, value: String, ids: Ids, strict: Boolean): Boolean {
        val v = value.trim()
        val n = numbers(v)
        val int = INT.matches(v)
        return when (name) {
            "ID", "DrawParam", "ColorSpace", "Index", "Substitution", "ImageMask" -> int
            "Boundary" -> n?.size == 4
            "CTM" -> n?.size == 6
            "Font" -> int && (!strict || ids.fonts.isEmpty() || v in ids.fonts)
            "ResourceID" -> int && (!strict || ids.medias.isEmpty() || v in ids.medias)
            "Size", "LineWidth", "MiterLimit", "HScale", "DashOffset", "X", "Y" -> n?.size == 1
            "Alpha" -> n?.size == 1 && n[0] in 0.0..255.0 && (!strict || int)
            "Weight", "ReadDirection", "CharDirection" -> int
            "Fill", "Stroke", "Visible", "Italic" -> word(v, "true", "false")
            "Rule" -> word(v, "NonZero", "Even-Odd")
            "Cap" -> word(v, "Butt", "Round", "Square")
            "Join" -> word(v, "Miter", "Round", "Bevel")
            "DashPattern" -> n != null
            "DeltaX", "DeltaY" -> v.isNotEmpty() && tokens(v).all { it == "g" || it.toDoubleOrNull() != null }
            "CodePosition" -> int
            "CodeCount", "GlyphCount" -> int && (v.toIntOrNull() ?: 0) >= 1
            "Value" -> tokens(v).let { t -> t.size in 1..4 && t.all { it.toDoubleOrNull() != null || it.startsWith("#") } } &&
                (!strict || (tokens(v).size >= 3 && tokens(v).all { INT.matches(it) }))
            "Name" -> !strict
            else -> false
        }
    }

    // ------------------------------------------------------------ structure

    private fun isGlyphList(e: XmlElement) = e.children.isEmpty() && e.text.isNotEmpty() && tokens(e.text).all { INT.matches(it) }
    private fun isCg(e: XmlElement) = e.text.isEmpty() && e.children.isNotEmpty() && e.children.all { isGlyphList(it) }
    private fun isTextLike(e: XmlElement) = e.children.isEmpty() && e.rawText.isNotBlank()
    private fun isPathData(e: XmlElement) = isTextLike(e) && PATH.containsMatchIn(e.text)
    private fun isColorLike(e: XmlElement) = e.children.isEmpty() && e.rawText.isBlank() &&
        e.attributes.values.any { v -> tokens(v).let { t -> t.size in 3..4 && t.all { INT.matches(it) } } }

    /** The kind of a page object from what it holds, for an element whose name is not one. */
    private fun objectKind(e: XmlElement, ids: Ids): String? = when {
        e.name in OBJECTS -> e.name
        e.children.any { isCg(it) } -> "TextObject"
        e.children.any { isPathData(it) } -> "PathObject"
        e.children.any { isTextLike(it) } -> "TextObject"
        e.children.none { isTextLike(it) } && e.attributes.values.any { fits("Boundary", it, ids, true) } &&
            e.attributes.values.any { ids.medias.isNotEmpty() && fits("ResourceID", it, ids, true) } -> "ImageObject"
        else -> null
    }

    /** The name a child of a [kind] object should have, from what it holds; its own name when that cannot be told. */
    private fun childName(kind: String, c: XmlElement, flags: Map<String, String>, hasStroke: Boolean): String {
        val known = CHILDREN[kind].orEmpty()
        return when {
            kind == "TextObject" && isCg(c) -> "CGTransform"
            kind == "TextObject" && c.name != "TextCode" && isTextLike(c) -> "TextCode"
            kind == "PathObject" && c.name != "AbbreviatedData" && isPathData(c) -> "AbbreviatedData"
            c.name !in known && c.children.any { it.name == "Clip" } -> "Clips"
            c.name in known && c.name != "CGTransform" -> when {
                // A stroked, unfilled path with one colour: the colour is the stroke's whatever it is called.
                kind == "PathObject" && c.name == "FillColor" && c.children.isEmpty() && !hasStroke &&
                    word(flags["Fill"] ?: "false", "false") && !word(flags["Stroke"] ?: "true", "false") && "Fill" in flags -> "StrokeColor"
                else -> c.name
            }
            kind != "ImageObject" && isColorLike(c) -> if (kind == "PathObject" && !hasStroke && !word(flags["Stroke"] ?: "true", "false")) "StrokeColor" else "FillColor"
            else -> c.name
        }
    }

    // ------------------------------------------------------------ detection

    /** True when [a] on a [kind] element cannot be as the producer meant: a name of the format out of place, or a value of another shape. */
    private fun wrong(kind: String, a: Map<String, String>, ids: Ids): Boolean {
        val valid = VALID[kind] ?: return false
        return a.any { (k, v) -> if (k in valid) !fits(k, v, ids, false) else k in VOCABULARY }
    }

    private fun broken(elements: List<XmlElement>, ids: Ids): Boolean = elements.any { o ->
        val kind = o.name
        when {
            kind == "PageBlock" -> broken(o.children, ids)
            kind !in OBJECTS -> objectKind(o, ids) != null
            kind == "CompositeObject" -> false
            wrong(kind, o.attributes, ids) || "Boundary" !in o.attributes -> true
            else -> o.children.any { c ->
                when {
                    c.name == "TextCode" && kind == "TextObject" -> c.children.isNotEmpty() || wrong("TextCode", c.attributes, ids)
                    c.name == "CGTransform" && kind == "TextObject" -> c.children.any { it.name != "Glyphs" } || wrong("CGTransform", c.attributes, ids)
                    (c.name == "FillColor" || c.name == "StrokeColor") && kind != "ImageObject" ->
                        if (c.children.isEmpty()) c.rawText.isNotBlank() || wrong(c.name, c.attributes, ids) else isCg(c)
                    c.name == "AbbreviatedData" && kind == "PathObject" -> false
                    c.name in CHILDREN[kind].orEmpty() -> false
                    else -> c.name in VOCABULARY
                }
            }
        }
    }

    // ------------------------------------------------------------ attributes

    /** The most common attribute order of the well written [kind] elements among [samples]. */
    private fun order(kind: String, samples: List<Map<String, String>>, ids: Ids): List<String> {
        val valid = VALID[kind] ?: return emptyList()
        return samples.filter { a -> a.isNotEmpty() && a.all { (k, v) -> k in valid && fits(k, v, ids, false) } }
            .groupingBy { it.keys.toList() }.eachCount().maxByOrNull { it.value }?.key.orEmpty()
    }

    /**
     * The attributes of a [kind] element under their right names. Those whose name is in the usual [order], in place
     * and of the right shape, are kept as anchors; a value between two anchors under a wrong name takes the name
     * the order has there when its shape fits; what is left takes the first free name of its shape, or is dropped.
     */
    private fun attrs(kind: String, a: Map<String, String>, order: List<String>, ids: Ids): Map<String, String> {
        val valid = VALID[kind] ?: return a
        if (!wrong(kind, a, ids) && (CORE[kind].orEmpty() + order).all { it in a }) return a
        val entries = a.entries.toList()
        val anchor = IntArray(entries.size) { -1 }
        var last = -1
        for ((i, e) in entries.withIndex()) {
            val at = order.indexOf(e.key)
            if (at > last && fits(e.key, e.value, ids, false)) { anchor[i] = at; last = at }
        }
        val out = LinkedHashMap<String, String>()
        for ((i, e) in entries.withIndex()) if (anchor[i] >= 0) out[e.key] = e.value
        val loose = ArrayList<Map.Entry<String, String>>()
        for ((i, e) in entries.withIndex()) {
            if (anchor[i] >= 0) continue
            val before = (i - 1 downTo 0).firstOrNull { anchor[it] >= 0 }?.let { anchor[it] } ?: -1
            val after = (i + 1 until entries.size).firstOrNull { anchor[it] >= 0 }?.let { anchor[it] } ?: order.size
            // A value under a name that could be its own only moves to a name the object cannot do without.
            val own = e.key in valid && fits(e.key, e.value, ids, false)
            val slot = (before + 1 until after).map { order[it] }
                .firstOrNull { it !in out && (!own || it == "ID" || it in CORE[kind].orEmpty()) && fits(it, e.value, ids, true) }
            if (slot != null) out[slot] = e.value else loose.add(e)
        }
        for (e in loose) {
            val own = e.key in valid && e.key !in out && fits(e.key, e.value, ids, false)
            val name = if (own) e.key else (CORE[kind].orEmpty() + order + valid).firstOrNull { it !in out && it != "Name" && fits(it, e.value, ids, true) }
            if (name != null) out[name] = e.value else if (e.key !in VOCABULARY && e.key !in out) out[e.key] = e.value
        }
        return out
    }

    // ------------------------------------------------------------ resources

    /** The groups of a resource file with the one kind of entry the standard gives each. */
    private val GROUPS = mapOf(
        "ColorSpaces" to "ColorSpace", "DrawParams" to "DrawParam", "Fonts" to "Font",
        "MultiMedias" to "MultiMedia", "CompositeGraphicUnits" to "CompositeGraphicUnit",
    )
    private val FONT_ATTRS = setOf("ID", "FontName", "FamilyName", "Charset", "Italic", "Bold", "Serif", "FixedWidth")
    private val MEDIA_ATTRS = setOf("ID", "Type", "Format")
    private val FONT_FILES = setOf("ttf", "otf", "ttc", "cff", "pfb", "woff")

    private fun fileChild(e: XmlElement) = e.children.firstOrNull { it.children.isEmpty() && it.text.isNotEmpty() }

    /** An entry's attributes with its ID back under that name, when a whole number sits under one the entry does not have. */
    private fun withId(a: Map<String, String>, valid: Set<String>): Map<String, String> {
        if (a["ID"]?.let { INT.matches(it.trim()) } == true) return a
        val stray = a.entries.firstOrNull { it.key !in valid && INT.matches(it.value.trim()) } ?: return a
        return mapOf("ID" to stray.value) + (a - stray.key - "ID")
    }

    /**
     * A resource file (PublicRes, DocumentRes, PageRes) as it should have been written, and whether anything was
     * changed: each group holds one kind of entry whatever the entry is called, a group under a wrong name is known
     * by its entries (fonts by their font files or names, media by their files), and the file of a font or a
     * medium is its one child with text.
     */
    fun res(res: XmlElement): Pair<XmlElement, Boolean> {
        val groups = res.children.map { group ->
            val files = group.children.mapNotNull { fileChild(it)?.text }
            val kind = when {
                group.name in GROUPS -> group.name
                group.children.isEmpty() -> return@map group
                group.children.any { "FontName" in it.attributes } ||
                    (files.isNotEmpty() && files.all { it.substringAfterLast('.', "").lowercase() in FONT_FILES }) -> "Fonts"
                files.size == group.children.size -> "MultiMedias"
                else -> return@map group
            }
            val entry = GROUPS.getValue(kind)
            fun withFile(e: XmlElement, name: String, valid: Set<String>): XmlElement {
                val file = e.child(name) ?: fileChild(e)
                return e.copy(name = entry, attributes = withId(e.attributes, valid), children = e.children.map { if (it === file) it.copy(name = name) else it })
            }
            group.copy(
                name = kind,
                children = group.children.map { e ->
                    when (kind) {
                        "Fonts" -> withFile(e, "FontFile", FONT_ATTRS)
                        "MultiMedias" -> withFile(e, "MediaFile", MEDIA_ATTRS)
                        else -> if (e.name == entry) e else e.copy(name = entry)
                    }
                },
            )
        }
        val out = res.copy(children = groups)
        return if (out == res) res to false else out to true
    }

    // ------------------------------------------------------------ rebuild

    private class Draft(val kind: String, val element: XmlElement, val children: List<Pair<String, XmlElement>>, val block: List<Draft>?)

    private fun <T> usual(values: List<T>): T? = values.groupingBy { it }.eachCount().maxByOrNull { it.value }?.key

    /**
     * [content] (the root of a page or template) as it should have been written, and whether anything was changed.
     * [fonts] and [medias] are the resource IDs the document defines.
     */
    fun page(content: XmlElement, fonts: Set<String>, medias: Set<String>): Pair<XmlElement, Boolean> {
        val ids = Ids(fonts, medias)
        val body = content.child("Content") ?: return content to false
        val layers = body.all("Layer")
        if (layers.none { broken(it.children, ids) }) return content to false

        // Every object and child is named first, so the usual attribute order of each kind comes from the whole page.
        fun drafts(elements: List<XmlElement>): List<Draft> = elements.map { o ->
            val kind = objectKind(o, ids)
            when {
                kind == "PageBlock" -> Draft(kind, o, emptyList(), drafts(o.children))
                kind == null || kind == "CompositeObject" -> Draft("", o, emptyList(), null)
                else -> {
                    var hasStroke = false
                    Draft(kind, o, o.children.map { c -> childName(kind, c, o.attributes, hasStroke).also { if (it == "StrokeColor") hasStroke = true } to c }, null)
                }
            }
        }
        val all = layers.map { drafts(it.children) }
        val samples = HashMap<String, MutableList<Map<String, String>>>()
        fun collect(list: List<Draft>) {
            for (d in list) {
                if (d.block != null) { collect(d.block); continue }
                if (d.kind.isEmpty()) continue
                samples.getOrPut(d.kind) { ArrayList() }.add(d.element.attributes)
                for ((n, c) in d.children) if (n in VALID) samples.getOrPut(n) { ArrayList() }.add(c.attributes)
            }
        }
        all.forEach { collect(it) }
        val orders = samples.mapValues { (k, v) -> order(k, v, ids) }
        fun fixed(kind: String, a: Map<String, String>) = attrs(kind, a, orders[kind].orEmpty(), ids)

        // What a lost value falls back on: the colour most used by that kind of element, the size most used at that height.
        val colors = listOf("FillColor", "StrokeColor").associateWith { k -> usual(samples[k].orEmpty().mapNotNull { fixed(k, it)["Value"] }) }
        val sizes = samples["TextObject"].orEmpty().map { fixed("TextObject", it) }
            .mapNotNull { a -> val h = OfdBox.parse(a["Boundary"])?.h; val s = a["Size"]; if (h != null && s != null) h to s else null }
            .groupBy({ it.first }, { it.second }).mapValues { usual(it.value) }

        fun child(name: String, c: XmlElement): XmlElement = when (name) {
            "CGTransform" -> {
                val a = LinkedHashMap(fixed(name, c.attributes))
                val glyphs = c.children.firstOrNull { isGlyphList(it) }
                val count = glyphs?.let { tokens(it.text).size } ?: 1
                // Text set by glyph index pairs characters and glyphs unless it says otherwise; a lost count is the other one.
                if ("GlyphCount" !in a) a["GlyphCount"] = count.toString()
                if ("CodeCount" !in a) a["CodeCount"] = a["GlyphCount"] ?: count.toString()
                c.copy(name = name, attributes = a, children = listOfNotNull(glyphs?.copy(name = "Glyphs", attributes = emptyMap())))
            }
            "AbbreviatedData" -> c.copy(name = name)
            "FillColor", "StrokeColor" -> if (c.children.isNotEmpty()) c.copy(name = name) else {
                val a = LinkedHashMap(fixed(name, c.attributes))
                if ("Value" !in a && "Index" !in a && "Value" in orders[name].orEmpty()) colors[name]?.let { a["Value"] = it }
                c.copy(name = name, attributes = a)
            }
            "TextCode" -> c.copy(name = name, attributes = fixed(name, c.attributes))
            else -> c.copy(name = name)
        }

        fun rebuild(list: List<Draft>): List<XmlElement> {
            val built = list.map { d ->
                when {
                    d.block != null -> d.element.copy(children = rebuild(d.block))
                    d.kind.isEmpty() -> d.element
                    else -> {
                        val a = LinkedHashMap(fixed(d.kind, d.element.attributes))
                        if (d.kind == "TextObject" && "Size" !in a) OfdBox.parse(a["Boundary"])?.h?.let { h -> a["Size"] = sizes[h] ?: h.toString() }
                        d.element.copy(name = d.kind, attributes = a, children = d.children.map { (n, c) -> child(n, c) })
                    }
                }
            }
            // An object that lost its ID takes the one its neighbours leave free.
            return built.mapIndexed { i, e ->
                if (e.name !in CORE || "ID" in e.attributes) return@mapIndexed e
                val prev = built.getOrNull(i - 1)?.attributes?.get("ID")?.toIntOrNull()
                val next = built.getOrNull(i + 1)?.attributes?.get("ID")?.toIntOrNull()
                if (prev != null && next != null && next - prev == 2) e.copy(attributes = mapOf("ID" to (prev + 1).toString()) + e.attributes) else e
            }
        }
        val fixedLayers = all.mapIndexed { i, list -> layers[i].copy(children = rebuild(list)) }
        var li = 0
        val newBody = body.copy(children = body.children.map { if (it.name == "Layer") fixedLayers[li++] else it })
        if (newBody == body) return content to false
        return content.copy(children = content.children.map { if (it === body) newBody else it }) to true
    }
}

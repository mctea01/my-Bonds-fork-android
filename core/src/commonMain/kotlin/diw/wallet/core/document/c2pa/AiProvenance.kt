package diw.wallet.core.document.c2pa

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/** One declared IPTC digital source type: where it was written and whether it names generative AI or other algorithms. */
@Serializable
data class AiSourceDeclaration(
    /** The IPTC code (trainedAlgorithmicMedia, digitalCapture...). */
    val code: String,
    /** "c2pa" for an action of a C2PA manifest, "xmp" for the IPTC metadata of the file. */
    val source: String,
    /** The manifest's title or label, for C2PA. */
    val manifest: String? = null,
    /** The manifest's claim signature verified (null for XMP, which is not signed). */
    val signed: Boolean? = null,
    val active: Boolean = false,
    val ai: Boolean,
    val synthetic: Boolean,
    val tool: String? = null,
)

/** A c2pa.soft-binding assertion: a watermark or fingerprint the manifest says the content carries. */
@Serializable
data class C2paSoftBinding(
    val manifest: String,
    val alg: String,
    /** watermark or fingerprint, from the C2PA soft binding algorithm list. */
    val type: String? = null,
    val description: String? = null,
    val registered: Boolean,
    val synthId: Boolean,
)

/**
 * What a file declares, read offline, about being made or changed with AI: IPTC digital source types in C2PA actions
 * and XMP, soft binding (watermark) assertions, and mentions of Google SynthID. Nothing here detects a watermark in
 * the pixels: SynthID has no public detector, so the app offers Google's own checking site instead.
 */
@Serializable
data class AiProvenance(
    val declarations: List<AiSourceDeclaration> = emptyList(),
    val softBindings: List<C2paSoftBinding> = emptyList(),
    /** Where the file names SynthID (a soft binding algorithm, an assertion label, the XMP metadata). */
    val synthIdHints: List<String> = emptyList(),
    /** The file declares AI generation by a Google tool (Gemini, Imagen, Veo, "Made with Google AI"). */
    val googleAi: Boolean = false,
    /** Tools named for the AI actions and in the metadata. */
    val aiTools: List<String> = emptyList(),
) {
    val aiDeclared: Boolean get() = declarations.any { it.ai }
    val syntheticDeclared: Boolean get() = declarations.any { it.synthetic }
    val synthIdDeclared: Boolean get() = synthIdHints.isNotEmpty()

    /** SynthID may be in the content: named by the file, or the file says a Google generative model made it. */
    val synthIdPossible: Boolean get() = synthIdDeclared || googleAi
}

/** Reads [AiProvenance] from a file's C2PA manifest store and XMP packet. */
object AiProvenanceReader {
    private val GOOGLE_AI = Regex("(?i)\\b(google\\s*ai|gemini|imagen|veo|nano\\s*banana|google\\s*deepmind|vertex\\s*ai)\\b")
    private val SYNTHID = Regex("(?i)synth[\\s_-]?id")

    /**
     * The declarations of [bytes] (the whole file) and its manifest [store]; [signedManifests] lists the labels whose
     * claim signature verified. Null when the file declares nothing about AI or algorithms and names no soft binding.
     */
    fun read(bytes: ByteArray?, store: C2paStore?, signedManifests: Set<String> = emptySet()): AiProvenance? {
        val declarations = ArrayList<AiSourceDeclaration>()
        val bindings = ArrayList<C2paSoftBinding>()
        val hints = LinkedHashSet<String>()
        val tools = LinkedHashSet<String>()
        var google = false
        val active = store?.active

        for (m in store?.manifests.orEmpty()) {
            val title = m.claim.str("dc:title") ?: m.label
            val generator = C2paManifests.generator(m)
            for (a in C2paManifests.actions(m)) {
                val code = a.digitalSourceType?.let(DigitalSourceTypes::code) ?: continue
                val ai = code in DigitalSourceTypes.AI_GENERATED
                val synthetic = code in DigitalSourceTypes.SYNTHETIC
                declarations += AiSourceDeclaration(code, "c2pa", title, m.label in signedManifests, m === active, ai, synthetic, a.softwareAgent)
                if (ai || synthetic) {
                    a.softwareAgent?.let { tools += it }
                    if (listOfNotNull(a.softwareAgent, generator, a.description).any { GOOGLE_AI.containsMatchIn(it) } && ai) google = true
                }
            }
            for ((label, value) in C2paManifests.assertion(m, "c2pa.soft-binding")) {
                val o = value as? JsonObject ?: continue
                val alg = o.str("alg") ?: continue
                val known = SoftBindingAlgorithms.find(alg)
                val synth = SYNTHID.containsMatchIn(alg)
                bindings += C2paSoftBinding(title, alg, known?.type, known?.description, known != null, synth)
                if (synth) hints += "$label: $alg"
            }
            C2paManifests.labels(m).filter { SYNTHID.containsMatchIn(it) }.forEach { hints += it }
        }

        val xmp = bytes?.let(::xmpPacket)
        if (xmp != null) {
            for (code in xmpSourceTypes(xmp)) {
                val c = DigitalSourceTypes.code(code)
                declarations += AiSourceDeclaration(c, "xmp", ai = c in DigitalSourceTypes.AI_GENERATED, synthetic = c in DigitalSourceTypes.SYNTHETIC)
            }
            val credit = xmpValue(xmp, "Credit")
            val creatorTool = xmpValue(xmp, "CreatorTool")
            val xmpAi = declarations.any { it.source == "xmp" && it.ai }
            if (xmpAi) listOfNotNull(creatorTool, credit).forEach { tools += it }
            if (xmpAi && listOfNotNull(credit, creatorTool).any { GOOGLE_AI.containsMatchIn(it) }) google = true
            if (SYNTHID.containsMatchIn(xmp)) hints += "XMP"
        }

        if (declarations.isEmpty() && bindings.isEmpty() && hints.isEmpty()) return null
        return AiProvenance(declarations.distinct(), bindings.distinct(), hints.toList(), google, tools.toList())
    }

    /** The XMP packet (x:xmpmeta) of a JPEG APP1, PNG iTXt (uncompressed), WebP XMP chunk or any file that embeds one. */
    fun xmpPacket(bytes: ByteArray): String? {
        val start = indexOf(bytes, "<x:xmpmeta".encodeToByteArray())
        if (start < 0) return null
        val endTag = "</x:xmpmeta>".encodeToByteArray()
        val end = indexOf(bytes, endTag, start)
        if (end < 0) return null
        return bytes.copyOfRange(start, end + endTag.size).decodeToString()
    }

    /** Iptc4xmpExt:DigitalSourceType values: attribute, element text or rdf:resource, with any namespace prefix. */
    fun xmpSourceTypes(xmp: String): List<String> {
        val out = LinkedHashSet<String>()
        Regex("[\\w-]+:DigitalSourceType\\s*=\\s*\"([^\"]+)\"").findAll(xmp).forEach { out += it.groupValues[1] }
        Regex("<[\\w-]+:DigitalSourceType\\s*>\\s*([^<\\s]+)\\s*</").findAll(xmp).forEach { out += it.groupValues[1] }
        Regex("<[\\w-]+:DigitalSourceType\\s+rdf:resource\\s*=\\s*\"([^\"]+)\"").findAll(xmp).forEach { out += it.groupValues[1] }
        return out.map { unescape(it) }.filter { it.isNotBlank() }
    }

    /** The text of a simple XMP property [name] (attribute, element, or the first rdf:li of an alternative). */
    private fun xmpValue(xmp: String, name: String): String? {
        Regex("[\\w-]+:$name\\s*=\\s*\"([^\"]*)\"").find(xmp)?.let { return unescape(it.groupValues[1]).ifBlank { null } }
        val element = Regex("<[\\w-]+:$name(?:\\s[^>]*)?>(.*?)</[\\w-]+:$name>", RegexOption.DOT_MATCHES_ALL).find(xmp)?.groupValues?.get(1) ?: return null
        val li = Regex("<rdf:li(?:\\s[^>]*)?>(.*?)</rdf:li>", RegexOption.DOT_MATCHES_ALL).find(element)?.groupValues?.get(1)
        return unescape((li ?: element).trim()).ifBlank { null }
    }

    private fun unescape(s: String) = s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")

    private fun indexOf(b: ByteArray, p: ByteArray, from: Int = 0): Int {
        if (p.isEmpty()) return from
        outer@ for (i in from..b.size - p.size) {
            for (j in p.indices) if (b[i + j] != p[j]) continue@outer
            return i
        }
        return -1
    }
}

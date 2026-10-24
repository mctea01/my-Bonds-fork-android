package diw.wallet.core.zktls

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * A verification page (p4-circuits.md section 4.2): which HTTPS request to make, which inputs the holder types, and
 * which parts of the response may be revealed. A reveal rule is a regular expression over the response text whose
 * whole match is revealed; its first group is the value the verifier reads back with the same expression. A rule must
 * end on a delimiter after the value (a closing tag, a line end), since the holder decides where a revealed segment
 * ends. The profile never holds a real query result.
 */
@Serializable
data class ZkTlsProfile(
    val id: String,
    val title: String,
    val host: String,
    val port: Int = 443,
    /** The site belongs to a government; shown to the user, it never raises the trust tier. */
    val official: Boolean = false,
    val prepare: Prepare = Prepare(),
    val request: Request,
    val limits: Limits = Limits(),
    val status: Status,
    val fields: List<Field>,
) {
    /**
     * What the holder fetches before the query, outside zkTLS (ZkTlsPrepare). With "captcha" the wallet opens [page]
     * for a session, shows the picture at [image] in that session, and the user types it into the input [input]; the
     * named [cookies] of that session go in the query's Cookie header, which stays hidden like the inputs. [values]
     * are read from [page] (a form's CSRF token, the picture's key) and fill {name} placeholders of [image] and of
     * the query, hidden too.
     */
    @Serializable
    data class Prepare(
        /** none, or captcha. */
        val type: String = "none",
        val page: String? = null,
        val image: String? = null,
        val input: String? = null,
        val cookies: List<String> = emptyList(),
        val values: List<PageValue> = emptyList(),
    )

    /** A value of the prepared page: the first group of [pattern] over the page, a token of [VALUE_RE]. */
    @Serializable
    data class PageValue(val name: String, val pattern: String)

    @Serializable
    data class Request(
        val method: String = "GET",
        val path: String,
        /** Query template with {input} placeholders; the whole query stays hidden from the verifier. */
        val query: String? = null,
        /** Form body template ("name=value&...") with {input} placeholders; hidden too. */
        val body: String? = null,
        val headers: Map<String, String> = emptyMap(),
        val inputs: List<Input> = emptyList(),
        /** How the body is sent: "form" (application/x-www-form-urlencoded) or "multipart" (multipart/form-data). */
        val encoding: String = "form",
        /** File fields of a multipart form sent empty, as a browser sends a file input left unused. */
        val files: List<String> = emptyList(),
    )

    @Serializable
    data class Input(
        val name: String,
        val label: String,
        val pattern: String,
        @SerialName("private") val isPrivate: Boolean = true,
        /**
         * Where a stored document prints this value: the first group over the document's text (a transcript's check
         * number), so the wallet can fill it in. Matched on the text as it is, then with all white space taken out.
         */
        val document: String? = null,
    ) {
        /** This input's value as [text] prints it, when it has a [document] rule and the value fits [pattern]. */
        fun fromDocument(text: String): String? {
            val rule = Regex(document ?: return null)
            val fits = Regex(pattern)
            return sequenceOf(text, text.filterNot { it.isWhitespace() })
                .flatMap { t -> rule.findAll(t).mapNotNull { it.groupValues.getOrNull(1) } }
                .firstOrNull { fits.matches(it) }
        }
    }

    @Serializable
    data class Limits(val maxSent: Int = 4096, val maxRecv: Int = 262_144)

    @Serializable
    data class Status(
        /** Finds the status segment that is always revealed. */
        val reveal: String,
        /** The revealed status segment must match this for the query to count as found. */
        val success: String,
    )

    @Serializable
    data class Field(val name: String, val label: String, val reveal: String)

    fun field(name: String): Field? = fields.firstOrNull { it.name == name }

    /** Checks what a profile must hold before it is used: limits within the engine's bounds and compilable rules. */
    fun validated(): ZkTlsProfile {
        fun bad(why: String): Nothing = throw ProtocolException("invalid_profile", "Verification page $id: $why")
        if (!ID_RE.matches(id)) bad("malformed id")
        if (!HOST_RE.matches(host)) bad("malformed host")
        if (port !in 1..65535) bad("port out of range")
        if (request.method !in setOf("GET", "POST")) bad("unsupported method")
        if (!request.path.startsWith("/") || '?' in request.path || request.path.any { it <= ' ' }) bad("malformed path")
        if (request.method == "GET" && request.body != null) bad("a GET request has no body")
        if (limits.maxSent !in 256..MAX_SENT || limits.maxRecv !in 1024..MAX_RECV) bad("limits out of range")
        if (fields.isEmpty() || fields.map { it.name }.toSet().size != fields.size) bad("fields missing or repeated")
        val names = request.inputs.map { it.name }
        if (names.toSet().size != names.size || names.any { !NAME_RE.matches(it) }) bad("malformed inputs")
        val values = prepare.values.map { it.name }
        if (values.toSet().size != values.size || values.any { !NAME_RE.matches(it) || it in names }) bad("malformed page values")
        prepare.values.forEach { v ->
            if (runCatching { capturingGroups(v.pattern) }.getOrDefault(0) < 1 || runCatching { Regex(v.pattern) }.isFailure) bad("page value ${v.name} has no value group")
        }
        val placeholders = PLACEHOLDER.findAll((request.query ?: "") + (request.body ?: "")).map { it.groupValues[1] }.toSet()
        if (!(names + values).toSet().containsAll(placeholders)) bad("a placeholder names no input")
        when (request.encoding) {
            "form" -> if (request.files.isNotEmpty()) bad("file fields need a multipart body")
            "multipart" -> {
                if (request.method != "POST" || request.body == null) bad("a multipart request is a POST with a body")
                val parts = request.body.split('&').map { it.substringBefore('=') } + request.files
                if (parts.any { !FIELD_RE.matches(it) } || request.body.split('&').any { '=' !in it }) bad("malformed multipart fields")
            }
            else -> bad("unsupported body encoding")
        }
        request.headers.forEach { (k, v) ->
            if (!TOKEN_RE.matches(k) || v.any { it < ' ' } || k.lowercase() in RESERVED_HEADERS) bad("header $k is not allowed")
        }
        when (prepare.type) {
            "none" -> if (prepare.page != null || prepare.image != null || prepare.input != null || prepare.cookies.isNotEmpty() || prepare.values.isNotEmpty()) {
                bad("prepare has no steps")
            }
            "captcha" -> {
                listOfNotNull(prepare.page, prepare.image ?: bad("captcha without image")).forEach { path ->
                    if (!path.startsWith("/") || path.any { it <= ' ' || it == '#' }) bad("malformed prepare path")
                }
                if (prepare.input == null || prepare.input !in names) bad("captcha input is not one of the inputs")
                if (prepare.cookies.isEmpty() || prepare.cookies.any { !COOKIE_RE.matches(it) }) bad("captcha needs session cookie names")
                if (prepare.values.isNotEmpty() && prepare.page == null) bad("page values need the page")
                if (!values.toSet().containsAll(PLACEHOLDER.findAll(prepare.image!!).map { it.groupValues[1] }.toList())) bad("an image placeholder names no page value")
                if (request.headers.keys.any { it.equals("Cookie", ignoreCase = true) }) bad("the session supplies the Cookie header")
            }
            else -> bad("unsupported prepare type")
        }
        request.inputs.forEach { i -> i.document?.let { if (runCatching { capturingGroups(it) }.getOrDefault(0) < 1) bad("document rule of ${i.name} has no value group") } }
        (request.inputs.map { it.pattern } + request.inputs.mapNotNull { it.document } + status.reveal + status.success + fields.map { it.reveal }).forEach {
            runCatching { Regex(it) }.getOrElse { bad("rule does not compile") }
        }
        fields.forEach { if (capturingGroups(it.reveal) < 1) bad("rule of ${it.name} has no value group") }
        return this
    }

    companion object {
        /** The engine's bounds (native/zktls limits). */
        const val MAX_SENT = 4096
        const val MAX_RECV = 262_144
        val PLACEHOLDER = Regex("\\{([A-Za-z][A-Za-z0-9_]{0,31})\\}")
        private val ID_RE = Regex("^[a-z0-9.-]{3,64}/[0-9]{1,4}$")
        private val HOST_RE = Regex("^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
        private val NAME_RE = Regex("^[A-Za-z][A-Za-z0-9_]{0,31}$")
        private val TOKEN_RE = Regex("^[A-Za-z0-9-]{1,64}$")
        private val FIELD_RE = Regex("^[A-Za-z0-9_.-]{1,64}$")
        internal val COOKIE_RE = Regex("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$")
        /** What a page value may hold: a token, so it can go in a URL, a form or a multipart field as it is. */
        val VALUE_RE = Regex("^[A-Za-z0-9._~-]{1,256}$")
        /** Set by the planner itself: the request line, the target, the body framing and the compression rule. */
        private val RESERVED_HEADERS = setOf("host", "content-length", "transfer-encoding", "accept-encoding", "connection")

        fun parse(json: JsonObject): ZkTlsProfile = runCatching { DiwJson.decodeFromJsonElement(serializer(), json) }
            .getOrElse { throw ProtocolException("invalid_profile", "Unreadable verification page", it) }
            .validated()
    }
}

/** Capturing groups of [pattern]: each unescaped ( outside a character class that is not followed by ?. */
internal fun capturingGroups(pattern: String): Int {
    var count = 0
    var i = 0
    var inClass = false
    while (i < pattern.length) {
        val c = pattern[i]
        when {
            c == '\\' -> i++
            inClass -> if (c == ']') inClass = false
            c == '[' -> inClass = true
            c == '(' && (i + 1 >= pattern.length || pattern[i + 1] != '?') -> count++
        }
        i++
    }
    return count
}

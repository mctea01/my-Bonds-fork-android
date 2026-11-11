package diw.wallet.core.zkpassport

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.io.encoding.Base64

/** Data a zkPassport request can ask the holder to disclose (the SDK's query keys). */
enum class ZkPassportField(val key: String) {
    DOCUMENT_TYPE("document_type"),
    ISSUING_COUNTRY("issuing_country"),
    FULLNAME("fullname"),
    NATIONALITY("nationality"),
    BIRTHDATE("birthdate"),
    EXPIRY_DATE("expiry_date"),
    DOCUMENT_NUMBER("document_number"),
    GENDER("gender"),
}

/**
 * What this wallet asks a zkPassport holder for. The document type and issuing country are always disclosed: they
 * fix the zone layout the other fields are read with and decide the trust shown. [domain] is the service the proofs
 * are scoped to; the holder's app shows it but nothing proves it, so the result is labelled with it as entered.
 */
data class ZkPassportRequest(
    val domain: String,
    val name: String,
    val purpose: String,
    val logo: String = "",
    val scope: String? = null,
    val disclose: Set<ZkPassportField> = emptySet(),
    val minAge: Int? = null,
    val nationalityIn: List<String> = emptyList(),
    val nationalityOut: List<String> = emptyList(),
    val issuingCountryIn: List<String> = emptyList(),
    val issuingCountryOut: List<String> = emptyList(),
    val customData: String? = null,
    /** Accepts mock documents (zkPassport's test passports) and uses the Sepolia registry. */
    val devMode: Boolean = false,
    val validitySeconds: Long = ZkPassport.DEFAULT_VALIDITY,
)

/**
 * A zkPassport request this wallet answers as the holder (Z3, docs/design/zkpassport.md 5.3), read from the
 * `https://zkpassport.id/r` link. [domain] is what the link claims; only the bridge's report of the creator's origin
 * says where it came from, and the service name, logo and purpose are the requester's own words.
 */
data class ZkPassportIncoming(
    val domain: String,
    /** The requester's compressed secp256k1 key in hex: the bridge id and the ECDH key. */
    val verifierPublicKey: String,
    val query: JsonObject,
    val service: JsonObject,
    /** `fast` (proofs made here) or a `compressed` mode that needs zkPassport's cloud prover. */
    val mode: String,
    val sdkVersion: String?,
    val devMode: Boolean,
    val link: String,
) {
    private fun text(key: String) = (service[key] as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
    val name: String? get() = text("name")
    val purpose: String? get() = text("purpose")
    val logo: String? get() = text("logo")
    val scope: String? get() = text("scope")
    /** The https origin the bridge must report for the creator: the link's domain. */
    val expectedOrigin: String get() = "https://$domain"
    val fastMode: Boolean get() = mode == "fast"

    /**
     * Whether a reported [origin] that is not [expectedOrigin] is still an https page of the same site (the same
     * registrable domain, e.g. verify.zkpassport.id for demo.zkpassport.id): the request did not come from someone
     * else, it was sent by another page of the site it names.
     */
    fun sameSite(origin: String?): Boolean {
        val host = origin?.takeIf { it.startsWith("https://") }?.removePrefix("https://")?.substringBefore('/')?.substringBefore(':')?.lowercase()
            ?: return false
        val site = registrable(host) ?: return false
        return site == registrable(domain.lowercase().substringBefore(':'))
    }

    private fun registrable(host: String): String? {
        val labels = host.trimEnd('.').split('.')
        if (labels.size < 2 || labels.any { it.isEmpty() }) return null
        // Two-letter country codes with a second level such as com.tw or co.uk keep three labels.
        val secondLevel = labels.size >= 3 && labels.last().length == 2 &&
            labels[labels.size - 2] in setOf("com", "net", "org", "gov", "edu", "co", "ac", "go", "or", "ne", "idv", "mil")
        val n = if (secondLevel) 3 else 2
        return labels.takeLast(n).joinToString(".")
    }
}

/** The chip files an answer is proved from: SOD and DG1 always, DG2 for the face photo hash. */
class ZkPassportChip(val sod: ByteArray, val dg1: ByteArray, val dg2: ByteArray?)

/** Where an answer stands, for the screen. */
sealed interface ZkPassportAnswerProgress {
    data object Registry : ZkPassportAnswerProgress
    data class Circuits(val count: Int) : ZkPassportAnswerProgress
    data class Proving(val index: Int, val total: Int, val name: String) : ZkPassportAnswerProgress
    data object Sending : ZkPassportAnswerProgress
}

/** Why an answer stopped; [code] names the step (bridge_origin, connection, native_unavailable, crs_missing, inputs, ...). */
class ZkPassportAnswerFailure(val code: String) : Exception(code)

/** This wallet answering one zkPassport request (Z3): the bridge is open and the requester's origin known. */
interface ZkPassportAnswer {
    /** The requester's origin as zkPassport's bridge reports it. */
    val origin: String
    /** Whether [origin] is the https origin of the link's domain; otherwise the link may be relayed (5.3). */
    val originMatches: Boolean
    suspend fun reject()
    /** Accepts, proves [chip] against the request on this device and sends the proofs; throws [ZkPassportAnswerFailure]. */
    suspend fun answer(chip: ZkPassportChip, progress: (ZkPassportAnswerProgress) -> Unit)
    fun close()
}

/** Answers zkPassport requests with proofs made on this device. */
interface ZkPassportHolder {
    /** Opens the bridge for [incoming]; [rpc] is the Ethereum node for the registries, null for the built-in one. */
    suspend fun connect(incoming: ZkPassportIncoming, rpc: String?): ZkPassportAnswer
}

/** Where the registries are read; null RPC addresses use the built-in public nodes. */
data class ZkPassportConfig(
    val mainnetRpc: String? = null,
    val sepoliaRpc: String? = null,
    /** Lets zkPassport's verifier service decide when this device cannot verify the proofs itself. Off by default. */
    val verifierApi: Boolean = false,
    /** DER of this wallet's CSCA anchors, against which the registry's keys of the issuing country are checked. */
    val cscaAnchors: List<ByteArray> = emptyList(),
    /**
     * The `oprf_pk_hash` (0x hex) of the project OPRF key the user's server publishes (5.5); salted identifiers
     * under any other key, zkPassport's included, are refused. Null accepts none.
     */
    val oprfKeyHash: String? = null,
)

/**
 * The registry's CSCA keys for the issuing country the proofs disclose (or limit to), checked against this wallet's
 * CSCA anchors (docs/design/zkpassport.md 4.3). The circuits bind the CSCA's country to the document's issuing
 * state, so when every such key is an anchor the signer chains to one of them.
 */
data class ZkPassportCscaCheck(
    val countries: List<String>,
    /** Keys of [countries] in the certificate package the proofs' registry root was built from. */
    val inPackage: Int,
    /** Of those, the keys that are also this wallet's anchors. */
    val anchored: Int,
    /** Why the package could not be checked (`certificates_unavailable`, `certificates_root`), or null. */
    val error: String? = null,
) {
    val allAnchored: Boolean get() = error == null && inPackage > 0 && anchored == inPackage
}

/** The holder's document as the proofs disclose it; every value is committed to by a verified proof. */
data class ZkPassportDisclosed(
    val documentCode: String?,
    val issuingCountry: String?,
    val nationality: String?,
    val lastName: String?,
    val givenNames: String?,
    val documentNumber: String?,
    /** YYMMDD as in the zone. */
    val birthdate: String?,
    val expiryDate: String?,
    val gender: String?,
    /** "td3" (passport), "td1" (card) or "unknown". */
    val layout: String,
)

data class ZkPassportResult(
    val verified: Boolean,
    /** Codes from the native checker or this client, such as `scope:compare_age` or `registry_unreachable`. */
    val errors: List<String>,
    val version: String?,
    /** The date the proofs were made for, Unix seconds. */
    val proofDate: Long?,
    val uniqueIdentifier: String?,
    val identifierType: String?,
    val disclosed: ZkPassportDisclosed?,
    val minAge: Int?,
    val maxAge: Int?,
    val nationalityIn: List<String>,
    val nationalityOut: List<String>,
    val issuingCountryIn: List<String>,
    val issuingCountryOut: List<String>,
    val boundData: String?,
    val devMode: Boolean,
    /** Decided by zkPassport's verifier service instead of on this device. */
    val viaVerifierApi: Boolean = false,
    /** The issuing country's CSCA keys against this wallet's anchors; null without an issuing country or a pass. */
    val csca: ZkPassportCscaCheck? = null,
)

sealed interface ZkPassportState {
    data object Connecting : ZkPassportState
    /** Show [url] as a QR code or open it on this phone. */
    data class Waiting(val url: String) : ZkPassportState
    data class Scanned(val url: String) : ZkPassportState
    data object Generating : ZkPassportState
    data class Receiving(val received: Int, val total: Int) : ZkPassportState
    data object Verifying : ZkPassportState
    data class Done(val result: ZkPassportResult) : ZkPassportState
    data object Rejected : ZkPassportState
    /** [code]: `unsupported_document`, `proof_failed`, `holder_error`, `connection`, `native_unavailable`. */
    data class Failed(val code: String, val detail: String? = null) : ZkPassportState
}

interface ZkPassportSession {
    val state: StateFlow<ZkPassportState>
    fun close()
}

/** Asks a zkPassport holder over zkPassport's bridge and verifies the proofs on this device. */
interface ZkPassportVerifier {
    fun open(request: ZkPassportRequest, config: ZkPassportConfig, scope: CoroutineScope): ZkPassportSession
}

object ZkPassport {
    const val DEFAULT_VALIDITY: Long = 7 * 24 * 60 * 60
    /** The SDK version the request URL claims; the holder's app reads its parameters by it. */
    const val SDK_VERSION = "0.19.3"
    const val MAINNET = 1L
    const val SEPOLIA = 11155111L
    /** Built-in public Ethereum nodes the registries are read from when the user has not set their own. */
    /**
     * The first circuit version keyed by the Barretenberg this app ships (bb v6). Earlier versions were keyed by
     * bb 5 and their proofs do not verify under bb v6 keys, so the app does not prove them.
     */
    const val CIRCUIT_VERSION = "0.22.0"

    const val MAINNET_RPC = "https://ethereum-rpc.publicnode.com"
    const val SEPOLIA_RPC = "https://ethereum-sepolia-rpc.publicnode.com"

    fun chain(devMode: Boolean): Long = if (devMode) SEPOLIA else MAINNET

    /** The SDK's domain form: lower case without scheme, port, path, query or fragment. */
    fun normalizeDomain(input: String): String =
        input.trim().lowercase().substringAfter("://").substringBefore('/').substringBefore('?')
            .substringBefore('#').substringAfterLast('@').substringBefore(':')

    /** The SDK query object for [request]. */
    fun query(request: ZkPassportRequest): JsonObject = buildJsonObject {
        val disclose = request.disclose + ZkPassportField.DOCUMENT_TYPE + ZkPassportField.ISSUING_COUNTRY
        for (field in ZkPassportField.entries) {
            val inList = when (field) {
                ZkPassportField.NATIONALITY -> request.nationalityIn
                ZkPassportField.ISSUING_COUNTRY -> request.issuingCountryIn
                else -> emptyList()
            }
            val outList = when (field) {
                ZkPassportField.NATIONALITY -> request.nationalityOut
                ZkPassportField.ISSUING_COUNTRY -> request.issuingCountryOut
                else -> emptyList()
            }
            if (field !in disclose && inList.isEmpty() && outList.isEmpty()) continue
            putJsonObject(field.key) {
                if (field in disclose) put("disclose", true)
                if (inList.isNotEmpty()) putJsonArray("in") { inList.forEach { add(JsonPrimitive(it)) } }
                if (outList.isNotEmpty()) putJsonArray("out") { outList.forEach { add(JsonPrimitive(it)) } }
            }
        }
        request.minAge?.let { age -> putJsonObject("age") { put("gte", age) } }
        request.customData?.takeIf { it.isNotEmpty() }?.let { data -> putJsonObject("bind") { put("custom_data", data) } }
    }

    /** The service object of the request URL. */
    fun service(request: ZkPassportRequest): JsonObject = buildJsonObject {
        put("name", request.name)
        put("logo", request.logo)
        put("purpose", request.purpose)
        request.scope?.takeIf { it.isNotEmpty() }?.let { put("scope", it) }
    }

    /** The `https://zkpassport.id/r` link the holder's app opens; [bridgeId] is the bridge's public key in hex. */
    fun url(request: ZkPassportRequest, bridgeId: String, nowSeconds: Long): String {
        val config = Base64.encode(Json.encodeToString(JsonObject.serializer(), query(request)).encodeToByteArray())
        val service = Base64.encode(Json.encodeToString(JsonObject.serializer(), service(request)).encodeToByteArray())
        return "https://zkpassport.id/r?d=${normalizeDomain(request.domain)}&t=$bridgeId&c=${encode(config)}&s=${encode(service)}" +
            "&p=$bridgeId&m=fast&v=$SDK_VERSION&dt=${nowSeconds - request.validitySeconds}&dev=${if (request.devMode) 1 else 0}"
    }

    /**
     * Reads a request link (`https://zkpassport.id/r?...`, or `/c` of the App Clip); null for anything else or when
     * the domain, the requester's key or the query is missing or malformed.
     */
    fun parseLink(link: String): ZkPassportIncoming? {
        val url = runCatching { io.ktor.http.Url(link.trim()) }.getOrNull() ?: return null
        if (url.protocol.name != "https" || url.host != "zkpassport.id" || url.encodedPath !in setOf("/r", "/c")) return null
        val p = url.parameters
        val domain = p["d"]?.let(::normalizeDomain)?.takeIf { DOMAIN.matches(it) } ?: return null
        val key = p["p"]?.lowercase()?.takeIf { KEY.matches(it) } ?: return null
        fun json(name: String): JsonObject? = p[name]?.let { v ->
            runCatching { Json.parseToJsonElement(Base64.decode(v.replace(' ', '+')).decodeToString()) as? JsonObject }.getOrNull()
        }
        val query = json("c") ?: return null
        return ZkPassportIncoming(
            domain = domain, verifierPublicKey = key, query = query, service = json("s") ?: JsonObject(emptyMap()),
            mode = p["m"]?.takeIf { it.isNotBlank() } ?: "fast", sdkVersion = p["v"], devMode = p["dev"] == "1", link = link.trim(),
        )
    }

    private val DOMAIN = Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
    private val KEY = Regex("^0[23][0-9a-f]{64}$")

    /** encodeURIComponent for the base64 alphabet. */
    private fun encode(s: String): String = s.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")

    private fun JsonElement?.text(): String? = (this as? JsonPrimitive)?.contentOrNull
    private fun JsonElement?.countries(): List<String> =
        (this as? JsonObject)?.get("countries")?.let { it as? JsonArray }?.mapNotNull { it.text() }.orEmpty()

    /** Reads the native checker's JSON result. */
    fun result(json: String, viaVerifierApi: Boolean = false): ZkPassportResult {
        val o = Json.parseToJsonElement(json).jsonObject
        val conditions = o["conditions"] as? JsonObject ?: JsonObject(emptyMap())
        val age = conditions["compare_age"] as? JsonObject
        val disclosed = (o["disclosed"] as? JsonObject)?.let { d ->
            ZkPassportDisclosed(
                documentCode = d["documentCode"].text(), issuingCountry = d["issuingCountry"].text(),
                nationality = d["nationality"].text(), lastName = d["lastName"].text(), givenNames = d["givenNames"].text(),
                documentNumber = d["documentNumber"].text(), birthdate = d["birthdate"].text(),
                expiryDate = d["expiryDate"].text(), gender = d["gender"].text(), layout = d["layout"].text() ?: "unknown",
            )
        }
        return ZkPassportResult(
            verified = o["verified"]?.jsonPrimitive?.booleanOrNull == true,
            errors = (o["errors"] as? JsonArray)?.mapNotNull { it.text() }.orEmpty(),
            version = o["version"].text(),
            proofDate = (o["date"] as? JsonPrimitive)?.longOrNull,
            uniqueIdentifier = o["uniqueIdentifier"].text(),
            identifierType = o["uniqueIdentifierType"].text(),
            disclosed = disclosed,
            minAge = (age?.get("minAge") as? JsonPrimitive)?.longOrNull?.toInt(),
            maxAge = (age?.get("maxAge") as? JsonPrimitive)?.longOrNull?.toInt(),
            nationalityIn = conditions["inclusion_check_nationality"].countries(),
            nationalityOut = conditions["exclusion_check_nationality"].countries(),
            issuingCountryIn = conditions["inclusion_check_issuing_country"].countries(),
            issuingCountryOut = conditions["exclusion_check_issuing_country"].countries(),
            boundData = (conditions["bind"] as? JsonObject)?.get("data")?.let { it as? JsonObject }?.get("custom_data").text(),
            devMode = o["devMode"]?.jsonPrimitive?.booleanOrNull == true,
            viaVerifierApi = viaVerifierApi,
        )
    }

    /** A result for a bundle that could not be checked at all. */
    fun failure(error: String, devMode: Boolean): ZkPassportResult = ZkPassportResult(
        false, listOf(error), null, null, null, null, null, null, null,
        emptyList(), emptyList(), emptyList(), emptyList(), null, devMode,
    )

    internal fun JsonObject.array(key: String) = this[key]?.jsonArray
}

package diw.wallet.core.zkpassport

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
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
import io.ktor.http.encodeURLParameter
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
    /** Asks the holder to prove a face comparison with the document's photo; null asks for none. */
    val faceMatch: ZkPassportFaceMatchRequest? = null,
)

/**
 * The kinds of FaceMatch proof (docs/design/zkpassport.md 5.6). They state the same thing and differ in who vouches
 * for it: zkPassport's own circuits (its attested app), this project's key attestation circuits (a hardware key of a
 * named Android app, without Play Integrity) and this project's self-declared circuit (nothing but the wallet's word).
 */
object ZkPassportFaceMatchKind {
    const val OFFICIAL = "official"
    const val KEY_ATTESTATION = "keyattest"
    const val SELF = "self"
}

/** An app trusted to have made the comparison: its package name and the SHA-256 (hex) of its signing certificates. */
data class ZkPassportFaceMatchApp(val appId: String, val signers: List<String>)

/**
 * FaceMatch as a verifier asks for it. zkPassport's own proofs are always accepted; this project's kinds only when
 * listed, and a key attested proof only from one of [apps].
 */
data class ZkPassportFaceMatchRequest(
    /** zkPassport's strict mode (a stricter liveness check in its app; this wallet's holder adds a head turn challenge). */
    val strict: Boolean = false,
    val keyAttestation: Boolean = false,
    val selfDeclared: Boolean = false,
    val apps: List<ZkPassportFaceMatchApp> = emptyList(),
    /** Accepts a locked device whose system is signed with its owner's key. */
    val allowSelfSigned: Boolean = false,
    /** Attestation roots (registry leaves) accepted besides Google's, for test devices. */
    val extraRoots: List<String> = emptyList(),
) {
    val mode: String get() = if (strict) "strict" else "regular"
    /** This project's kinds the request lists, for the query's `diw` extension. */
    val projectKinds: List<String>
        get() = buildList {
            if (keyAttestation) add(ZkPassportFaceMatchKind.KEY_ATTESTATION)
            if (selfDeclared) add(ZkPassportFaceMatchKind.SELF)
        }
}

/** The FaceMatch proof of a verified answer, as the native checker reports it. */
data class ZkPassportFaceMatch(
    /** One of [ZkPassportFaceMatchKind]. */
    val kind: String,
    val strict: Boolean,
    /** `production`, `self_signed` (key attestation only) or `development`. */
    val environment: String,
    val appId: String?,
    val signerDigest: String?,
    /** `ios` or `android` for zkPassport's own proofs. */
    val platform: String?,
)

/**
 * DIW extension of a zkPassport request link (docs/design/zkpassport.md 5.7): a room on the relay of a
 * diw-wallet-server (`/zktls/relay/{room}`, binary frames between two connections) where the requester, this
 * wallet, listens besides zkPassport's bridge. Another copy of this wallet answering the link exchanges the same
 * bridge messages there; the relay forwards end-to-end encrypted bytes only. The link's standard parameters do not
 * change, so zkPassport's app reads it as before and answers over the bridge.
 */
data class ZkPassportDiwRelay(
    /** The relay's ws or wss address, ending in /zktls/relay. */
    val url: String,
    /** 16 random bytes, unpadded base64url. */
    val room: String,
) {
    /** The address to connect to. */
    val address: String get() = "${url.trimEnd('/')}/$room"

    /**
     * The relay's web origin (https for wss), what the holder shows in place of the origin zkPassport's bridge reports:
     * the request reached it through that server.
     */
    val origin: String get() {
        val u = io.ktor.http.Url(url)
        val scheme = if (u.protocol.name == "wss") "https" else "http"
        return "$scheme://${u.host.lowercase()}"
    }

    companion object {
        const val URL_PARAM = "diw_relay"
        const val ROOM_PARAM = "diw_room"

        /** A new room for the relay at [url]. */
        fun open(url: String, random: ByteArray): ZkPassportDiwRelay =
            ZkPassportDiwRelay(url.trimEnd('/'), Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(random))

        /**
         * The extension read from a link, or null when either part is missing or malformed: only wss addresses of a
         * relay path (ws on the loopback for tests) and well-formed rooms. A malformed one is ignored, not refused, as
         * the request itself is still zkPassport's.
         */
        fun parse(url: String?, room: String?): ZkPassportDiwRelay? {
            if (url == null || room == null) return null
            val u = runCatching { io.ktor.http.Url(url) }.getOrNull() ?: return null
            val loopback = u.host == "127.0.0.1" || u.host == "localhost" || u.host == "[::1]"
            val schemeOk = u.protocol.name == "wss" || (u.protocol.name == "ws" && loopback)
            if (!schemeOk || u.host.isEmpty() || !u.encodedPath.trimEnd('/').endsWith("/zktls/relay")) return null
            if (u.encodedQuery.isNotEmpty() || u.encodedFragment.isNotEmpty() || u.user != null) return null
            val bytes = runCatching { Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).decode(room) }.getOrNull()
            if (room.length != 22 || bytes?.size != 16) return null
            return ZkPassportDiwRelay(url.trimEnd('/'), room)
        }
    }
}

/**
 * DIW extension of a zkPassport request link (docs/design/zkpassport.md 5.8): ways a requester of this wallet nearby
 * takes the whole answer in one exchange, without the Internet: plain http addresses on its local networks ([lan],
 * the BondsLanPresentation rules) and the one-time service of the Bonds BLE link ([ble]). The answer is the bridge
 * frames the holder would have sent, end-to-end encrypted to the requester's bridge key, so the network and the
 * radio carry ciphertext only. zkPassport's app ignores these parameters.
 */
data class ZkPassportDiwNearby(val lan: List<String> = emptyList(), val ble: String? = null) {
    val isEmpty: Boolean get() = lan.isEmpty() && ble == null

    companion object {
        const val LAN_PARAM = "diw_lan"
        const val BLE_PARAM = "diw_ble"
        /** The most addresses a link names: as many as a Bonds local network request. */
        const val MAX_LAN = diw.wallet.core.profile.bonds.MAX_LAN_URLS
        /** The largest answer either way takes: the Bonds BLE link's own limit. */
        const val MAX_PAYLOAD = 1024 * 1024
        private val UUID_RE = Regex("^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

        /** A fresh one-time BLE service id, as a Bonds request makes one. */
        fun newServiceId(): String = diw.wallet.core.profile.bonds.BondsPresentationRequest.randomUuid().lowercase()

        /** A fresh unguessable path for a local network listener. */
        fun newPath(): String = "/zkpassport/" + diw.wallet.core.profile.bonds.BondsPresentationRequest.randomUuid().lowercase()

        /**
         * The extension read from a link, or null when it names neither way. Addresses that are not plain http to a
         * private address, and a malformed service id, are left out rather than refused: the request is still zkPassport's.
         */
        fun parse(lan: String?, ble: String?): ZkPassportDiwNearby? {
            val urls = lan?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
                .filter { diw.wallet.core.profile.bonds.BondsLanPresentation.acceptableUrl(it) }.distinct().take(MAX_LAN)
            val service = ble?.trim()?.takeIf { UUID_RE.matches(it) }?.lowercase()
            return ZkPassportDiwNearby(urls, service).takeUnless { it.isEmpty }
        }
    }
}

/**
 * The one message of a nearby answer (DIW extension, [ZkPassportDiwNearby]): the holder's bridge frames in sending
 * order, starting with its handshake, and the requester's reply once it has read them.
 */
object ZkPassportNearbyPayload {
    const val TYPE = "diw-zkpassport-nearby"
    const val VERSION = 1

    fun encode(frames: List<String>): ByteArray = buildJsonObject {
        put("t", TYPE)
        put("v", VERSION)
        putJsonArray("frames") { frames.forEach { add(JsonPrimitive(it)) } }
    }.toString().encodeToByteArray()

    /** The frames of a payload; null for anything else (another device on the network). */
    fun decode(bytes: ByteArray): List<String>? {
        if (bytes.size > ZkPassportDiwNearby.MAX_PAYLOAD) return null
        val o = runCatching { Json.parseToJsonElement(bytes.decodeToString()) as? JsonObject }.getOrNull() ?: return null
        if ((o["t"] as? JsonPrimitive)?.contentOrNull != TYPE || (o["v"] as? JsonPrimitive)?.contentOrNull != VERSION.toString()) return null
        val frames = (o["frames"] as? JsonArray)?.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: return null } ?: return null
        return frames.takeIf { it.isNotEmpty() && it.size <= MAX_FRAMES }
    }

    /** The requester's reply: received, or the reason it was not. */
    fun reply(error: String? = null): ByteArray = buildJsonObject {
        put("t", TYPE)
        put("v", VERSION)
        if (error == null) put("received", true) else put("error", error)
    }.toString().encodeToByteArray()

    /** Null when the reply says the answer was received, otherwise its reason. */
    fun replyError(bytes: ByteArray): String? {
        val o = runCatching { Json.parseToJsonElement(bytes.decodeToString()) as? JsonObject }.getOrNull() ?: return "reply"
        if ((o["t"] as? JsonPrimitive)?.contentOrNull != TYPE) return "reply"
        if ((o["received"] as? JsonPrimitive)?.booleanOrNull == true) return null
        return (o["error"] as? JsonPrimitive)?.contentOrNull?.filter { it in 'a'..'z' || it == '_' }?.take(40)?.ifEmpty { null } ?: "reply"
    }

    private const val MAX_FRAMES = 512
}

/**
 * A nearby requester of this wallet as the holder's app reaches it (DIW extension, [ZkPassportDiwNearby]): its local
 * network addresses or its BLE link.
 */
interface ZkPassportNearbyLink {
    /** The way the answer would go now (`lan` or `ble`), or null when neither reaches the requester. */
    suspend fun probe(): String?

    /** Delivers [payload] and returns the requester's reply; throws when it cannot be delivered. */
    suspend fun deliver(payload: ByteArray, onProgress: (String) -> Unit = {}): ByteArray
}

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
    /**
     * A room on a diw-wallet-server relay the requester also listens in, when the requester is this wallet (DIW
     * extension, [ZkPassportDiwRelay]); zkPassport's app ignores it and uses the bridge as before.
     */
    val diwRelay: ZkPassportDiwRelay? = null,
    /** The requester's nearby ways (DIW extension, [ZkPassportDiwNearby]); zkPassport's app ignores them. */
    val diwNearby: ZkPassportDiwNearby? = null,
) {
    private fun text(key: String) = (service[key] as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
    val name: String? get() = text("name")
    val purpose: String? get() = text("purpose")
    val logo: String? get() = text("logo")
    val scope: String? get() = text("scope")
    /** The https origin the bridge must report for the creator: the link's domain. */
    val expectedOrigin: String get() = "https://$domain"
    val fastMode: Boolean get() = mode == "fast"

    private val faceMatch: JsonObject? get() = query["facematch"] as? JsonObject
    /** The FaceMatch mode the request asks for (`regular` or `strict`), or null. An unknown mode reads as strict. */
    val faceMatchMode: String?
        get() = faceMatch?.let { if ((it["mode"] as? JsonPrimitive)?.contentOrNull == "regular") "regular" else "strict" }
    /**
     * This project's FaceMatch kinds the requester says it takes (the query's `diw` extension). zkPassport's SDK
     * sends none and accepts only its own app's proofs.
     */
    val faceMatchKinds: List<String>
        get() = (faceMatch?.get("diw") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            ?.filter { it == ZkPassportFaceMatchKind.KEY_ATTESTATION || it == ZkPassportFaceMatchKind.SELF }.orEmpty()

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

/** The statement of a face comparison (zkPassport's `ZKPassportAppAttest`) and the 32 bytes a keystore key signs. */
class ZkPassportFaceMatchStatement(val clientData: ByteArray, val toSign: ByteArray)

/**
 * A hardware key's signature over a [ZkPassportFaceMatchStatement]: the key's attestation [chain] (DER, the key's
 * certificate first and the root last) and the DER ECDSA [signature] (SHA256withECDSA over the statement's `toSign`).
 */
class ZkPassportFaceMatchAttestation(val clientData: ByteArray, val chain: List<ByteArray>, val signature: ByteArray, val signerDigest: String)

/**
 * A face comparison this wallet made for an answer: the holder's live face against the document's photo passed. With
 * [attestation] the proof is the key attestation kind, without it the self-declared kind. [appId] is this app's
 * package name.
 */
class ZkPassportFaceMatchEvidence(val strict: Boolean, val appId: String, val attestation: ZkPassportFaceMatchAttestation?) {
    val kind: String get() = if (attestation == null) ZkPassportFaceMatchKind.SELF else ZkPassportFaceMatchKind.KEY_ATTESTATION
}

/** Where an answer stands, for the screen. */
sealed interface ZkPassportAnswerProgress {
    data object Registry : ZkPassportAnswerProgress
    data class Circuits(val count: Int) : ZkPassportAnswerProgress
    data class Proving(val index: Int, val total: Int, val name: String) : ZkPassportAnswerProgress
    data object Sending : ZkPassportAnswerProgress
}

/** Why an answer stopped; [code] names the step (bridge_origin, connection, native_unavailable, crs_missing, inputs, ...). */
class ZkPassportAnswerFailure(val code: String) : Exception(code)

/** How an answer reaches the requester: zkPassport's bridge, or between two copies of this wallet a DIW relay or nearby. */
enum class ZkPassportChannel { BRIDGE, DIW_RELAY, DIW_LAN, DIW_BLE }

/** This wallet answering one zkPassport request (Z3): the bridge is open and the requester's origin known. */
interface ZkPassportAnswer {
    /** The requester's origin as zkPassport's bridge reports it (the relay's origin over a DIW relay; empty nearby). */
    val origin: String
    /** Whether [origin] is the https origin of the link's domain; otherwise the link may be relayed (5.3). */
    val originMatches: Boolean
    /** Which way the answer goes. */
    val channel: ZkPassportChannel get() = ZkPassportChannel.BRIDGE
    suspend fun reject()
    /**
     * Accepts, proves [chip] against the request where [target] says and sends the proofs from this device; throws
     * [ZkPassportAnswerFailure]. [faceMatch] adds the FaceMatch proof a request asks for.
     */
    suspend fun answer(
        chip: ZkPassportChip,
        target: ZkPassportProverTarget,
        faceMatch: ZkPassportFaceMatchEvidence? = null,
        progress: (ZkPassportAnswerProgress) -> Unit,
    )
    fun close()
}

/**
 * Where an answer is proved. Off this device the prover sees the SOD and DG1 (never DG2) and the request; the
 * proofs still go to the requester from this device (diw-wallet-server DESIGN 3.9 and 3.10).
 */
sealed interface ZkPassportProverTarget {
    data object Device : ZkPassportProverTarget
    /** The owner's self-hosted prover with its access token. */
    data class Host(val url: String, val token: String) : ZkPassportProverTarget
    /** A temporary prover paired by its one-time QR code. */
    data class Paired(val prover: ZkPassportPairedProver) : ZkPassportProverTarget
}

/** A session with a temporary prover (diw-server prover), kept in memory only. */
interface ZkPassportPairedProver {
    /** The prover's address, for the consent screen. */
    val url: String
    /** Ends the session on the prover; failures are ignored. */
    suspend fun end()
}

/** Answers zkPassport requests with proofs made on this device or on the owner's prover. */
interface ZkPassportHolder {
    /**
     * Opens the bridge for [incoming]; [rpc] is the Ethereum node for the registries, null for the built-in one. When
     * the link is this wallet's, its DIW relay is tried first and then [nearby], the app's way to the requester's
     * local network addresses or BLE link; zkPassport's bridge last.
     */
    suspend fun connect(incoming: ZkPassportIncoming, rpc: String?, nearby: ZkPassportNearbyLink? = null): ZkPassportAnswer
    /**
     * Downloads, checks and keeps the registry files and circuits answering this wallet's requests with [chip] takes,
     * so a nearby request can be answered offline; returns the number of circuits. Throws [ZkPassportAnswerFailure].
     */
    suspend fun prepareOffline(chip: ZkPassportChip, devMode: Boolean, rpc: String?, progress: (ZkPassportAnswerProgress) -> Unit = {}): Int =
        throw ZkPassportAnswerFailure("offline_unsupported")

    /** Pairs with a temporary prover from its one-time code (`diw-prover://v1?...`); throws [ZkPassportAnswerFailure]. */
    suspend fun pair(link: String): ZkPassportPairedProver = throw ZkPassportAnswerFailure("pairing_unsupported")

    /**
     * The statement of a face comparison with [chip]'s photo for a hardware key to sign: the app's version, the mode,
     * the photo's hash, the hash of the reference [embedding] and the [cosine] score with its [threshold] (both times
     * 10^8, as zkPassport's app writes them). Throws [ZkPassportAnswerFailure].
     */
    suspend fun faceMatchStatement(
        chip: ZkPassportChip,
        appVersion: String,
        strict: Boolean,
        embedding: FloatArray,
        cosine: Long,
        threshold: Long,
    ): ZkPassportFaceMatchStatement = throw ZkPassportAnswerFailure("facematch_unsupported")
}

/** The one-time pairing code of a temporary prover. */
object ZkPassportPairingLink {
    const val PREFIX = "diw-prover://v1?"
    fun looksLike(text: String): Boolean = text.trim().startsWith(PREFIX)
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
    /** The current [verifierApi] setting, read when the proofs arrive, so a change during a request still applies. */
    val verifierApiNow: (() -> Boolean)? = null,
    /**
     * The ws or wss relay address of the user's diw-wallet-server (ZkTlsTransport.relayAddress): the request link
     * also names a room there, so another copy of this wallet can answer through it ([ZkPassportDiwRelay]). Null
     * listens on zkPassport's bridge only.
     */
    val diwRelay: String? = null,
    /**
     * Nearby ways the requester also takes an answer of this wallet (DIW extension, [ZkPassportDiwNearby]): the local
     * network addresses it listens on and its BLE service id. The app listens; [ZkPassportSession.nearby] reads what arrives.
     */
    val diwNearby: ZkPassportDiwNearby? = null,
) {
    fun verifierApiAllowed(): Boolean = verifierApiNow?.invoke() ?: verifierApi
}

/**
 * The registry's CSCA keys for the issuing country the proofs disclose (or limit to), checked against this wallet's
 * CSCA anchors (docs/design/zkpassport.md 4.3). The circuits bind the CSCA's country to the document's issuing
 * state, so when every such key is an anchor the signer chains to one of them. Keys whose CSCA certificate has
 * expired are left out, as this wallet's anchors are: a CSCA stays valid as long as the documents it signed for, so
 * only an expired document can chain to an expired CSCA.
 */
data class ZkPassportCscaCheck(
    val countries: List<String>,
    /** Keys of [countries] in the certificate package the proofs' registry root was built from, still valid. */
    val inPackage: Int,
    /** Of those, the keys that are also this wallet's anchors. */
    val anchored: Int,
    /** Why the package could not be checked (`certificates_unavailable`, `certificates_root`), or null. */
    val error: String? = null,
    /** Keys of [countries] in the package whose CSCA certificate has expired, not counted in [inPackage]. */
    val expired: Int = 0,
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
    /** The FaceMatch proof of the answer; null when it has none. */
    val faceMatch: ZkPassportFaceMatch? = null,
    /**
     * When the registry could not be reached and a root was taken from this device's record of an earlier check:
     * the time (Unix seconds) of the oldest such check, "registry state as of". Null when every root was checked now.
     */
    val registryAsOf: Long? = null,
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

    /**
     * An answer that arrived nearby (DIW extension, [ZkPassportNearbyPayload]); returns the reply for the holder. The
     * proofs are then verified as if they had come over the bridge.
     */
    suspend fun nearby(payload: ByteArray): ByteArray = ZkPassportNearbyPayload.reply("unsupported")

    fun close()
}

/**
 * What this device keeps for zkPassport without the Internet (docs/design/zkpassport.md 5.8): the latest certificate
 * root it read and when, whether that root's certificate package is here, the manifest versions kept and the
 * registry files (certificate packages, manifests, packaged circuits) with their size.
 */
data class ZkPassportOfflineState(
    val certificateRoot: String?,
    val certificateRootAt: Long?,
    val certificates: Boolean,
    val versions: List<String>,
    val files: Int,
    val bytes: Long,
)

/** Asks a zkPassport holder over zkPassport's bridge and verifies the proofs on this device. */
interface ZkPassportVerifier {
    fun open(request: ZkPassportRequest, config: ZkPassportConfig, scope: CoroutineScope): ZkPassportSession

    /**
     * Reads and keeps what verifying offline takes: the manifest of the current circuit version and the validity of
     * its root, the latest certificate root, its validity and its package. Throws [ZkPassportAnswerFailure].
     */
    suspend fun prepareOffline(devMode: Boolean, config: ZkPassportConfig): ZkPassportOfflineState =
        throw ZkPassportAnswerFailure("offline_unsupported")

    /** What is kept now; null when nothing is. */
    fun offlineState(devMode: Boolean): ZkPassportOfflineState? = null

    /** Deletes every registry file and record kept on this device. */
    fun clearOffline() {}
}

object ZkPassport {
    const val DEFAULT_VALIDITY: Long = 7 * 24 * 60 * 60
    /** The SDK version the request URL claims; the holder's app reads its parameters by it. */
    const val SDK_VERSION = "0.19.3"
    const val MAINNET = 1L
    const val SEPOLIA = 11155111L
    /** Built-in public Ethereum nodes the registries are read from when the user has not set their own. */
    /**
     * The first circuit version keyed by the Barretenberg this app proves with (bb v6). Earlier versions were keyed by
     * bb 5 and their proofs do not verify under bb v6 keys, so the app does not prove them; it verifies them with
     * the optional Barretenberg 5 component.
     */
    const val CIRCUIT_VERSION = "0.22.0"

    /**
     * Whether proofs of circuit [version] need Barretenberg 5 (the optional ZkEnvironment.zkPassportLegacy component):
     * versions before [CIRCUIT_VERSION], as zkPassport's SDK decides (a malformed version counts as current).
     */
    fun legacyBackend(version: String): Boolean {
        val parts = version.split('.').map { it.toIntOrNull() ?: return false }
        if (parts.size != 3) return false
        val current = CIRCUIT_VERSION.split('.').map { it.toInt() }
        for (i in 0 until 3) if (parts[i] != current[i]) return parts[i] < current[i]
        return false
    }

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
        request.faceMatch?.let { face ->
            putJsonObject("facematch") {
                put("mode", face.mode)
                // An extension zkPassport's app ignores: the kinds of this project's proofs the requester takes.
                if (face.projectKinds.isNotEmpty()) putJsonArray("diw") { face.projectKinds.forEach { add(JsonPrimitive(it)) } }
            }
        }
    }

    /** The native checker's FaceMatch policy for [face]: the accepted kinds and, for key attestation, the apps. */
    fun faceMatchPolicy(face: ZkPassportFaceMatchRequest): JsonObject = buildJsonObject {
        putJsonArray("accept") { (listOf(ZkPassportFaceMatchKind.OFFICIAL) + face.projectKinds).forEach { add(JsonPrimitive(it)) } }
        putJsonArray("apps") {
            for (app in face.apps) add(buildJsonObject {
                put("appId", app.appId)
                putJsonArray("signers") { app.signers.forEach { add(JsonPrimitive(it.lowercase())) } }
            })
        }
        put("allowSelfSigned", face.allowSelfSigned)
        putJsonArray("roots") { face.extraRoots.forEach { add(JsonPrimitive(it)) } }
    }

    /** The service object of the request URL. */
    fun service(request: ZkPassportRequest): JsonObject = buildJsonObject {
        put("name", request.name)
        put("logo", request.logo)
        put("purpose", request.purpose)
        request.scope?.takeIf { it.isNotEmpty() }?.let { put("scope", it) }
    }

    /**
     * The `https://zkpassport.id/r` link the holder's app opens; [bridgeId] is the bridge's public key in hex. With
     * [relay] the DIW extension is appended after the SDK's parameters, which stay as they are.
     */
    fun url(
        request: ZkPassportRequest,
        bridgeId: String,
        nowSeconds: Long,
        relay: ZkPassportDiwRelay? = null,
        nearby: ZkPassportDiwNearby? = null,
    ): String {
        val config = Base64.encode(Json.encodeToString(JsonObject.serializer(), query(request)).encodeToByteArray())
        val service = Base64.encode(Json.encodeToString(JsonObject.serializer(), service(request)).encodeToByteArray())
        return "https://zkpassport.id/r?d=${normalizeDomain(request.domain)}&t=$bridgeId&c=${encode(config)}&s=${encode(service)}" +
            "&p=$bridgeId&m=fast&v=$SDK_VERSION&dt=${nowSeconds - request.validitySeconds}&dev=${if (request.devMode) 1 else 0}" +
            (relay?.let { "&${ZkPassportDiwRelay.URL_PARAM}=${uriComponent(it.url)}&${ZkPassportDiwRelay.ROOM_PARAM}=${it.room}" } ?: "") +
            (nearby?.lan?.takeIf { it.isNotEmpty() }?.let { "&${ZkPassportDiwNearby.LAN_PARAM}=${uriComponent(it.joinToString(","))}" } ?: "") +
            (nearby?.ble?.let { "&${ZkPassportDiwNearby.BLE_PARAM}=$it" } ?: "")
    }

    /**
     * Reads a request link (`https://zkpassport.id/r?...`, `/c` of the App Clip, or `zkpassport:///r?...` that request
     * pages open on a phone); null for anything else or when the domain, the requester's key or the query is missing
     * or malformed.
     */
    /**
     * The values the disclosures of [query] would send from the zone [mrz] (DG1's text, 88 characters for a passport
     * or 90 for a card), read as zkPassport's circuits and SDK read them (zkpassport-core disclosure.rs). Its
     * "firstname" is the given names' first component only: a given name written TAI<MING is sent as TAI. Fields asked
     * with disclose true, in query order; empty for another zone layout.
     */
    fun disclosedPreview(mrz: String, query: JsonObject): List<Pair<String, String>> {
        val card = mrz.length == 90
        if (mrz.length != 88 && !card) return emptyList()
        fun part(a: Int, b: Int) = mrz.substring(a, b)
        fun name(text: String) = text.replace('<', ' ').split(' ').filter { it.isNotEmpty() }.joinToString(" ")
        val (last, given) = names(mrz)
        val code = part(0, 2).replace("<", "")
        val values = mapOf(
            "firstname" to name(given.substringBefore('<')),
            "lastname" to name(last),
            "fullname" to name("$given $last"),
            "nationality" to if (card) part(45, 48) else part(54, 57),
            "issuing_country" to part(2, 5),
            "document_number" to (if (card) part(5, 14) else part(44, 53)).trim('<').replace('<', ' '),
            "document_type" to when {
                code.startsWith("P") -> "passport"
                code == "IR" || code == "AR" -> "residence_permit"
                code.startsWith("I") -> "id_card"
                else -> "other"
            },
            "gender" to if (card) part(37, 38) else part(64, 65),
            "birthdate" to if (card) part(30, 36) else part(57, 63),
            "expiry_date" to if (card) part(38, 44) else part(65, 71),
        )
        return query.mapNotNull { (key, value) ->
            val disclose = ((value as? JsonObject)?.get("disclose") as? JsonPrimitive)?.contentOrNull == "true"
            values[key]?.takeIf { disclose }?.let { key to it }
        }
    }

    /** Whether [mrz]'s given names have more than one component, which zkPassport's "firstname" leaves out. */
    fun firstNameDropsParts(mrz: String): Boolean =
        (mrz.length == 88 || mrz.length == 90) && names(mrz).second.trim('<').contains('<')

    /** Surname and given names of the zone's name field, fillers kept. */
    private fun names(mrz: String): Pair<String, String> {
        val raw = if (mrz.length == 90) mrz.substring(60, 90) else mrz.substring(5, 44)
        val split = raw.indexOf("<<")
        return if (split < 0) "" to "" else raw.substring(0, split) to raw.substring(split + 2)
    }

    fun parseLink(link: String): ZkPassportIncoming? {
        val trimmed = link.trim()
        val app = Regex("^zkpassport://(/[rc])(\\?.*)$", RegexOption.IGNORE_CASE).find(trimmed)
        val https = app?.let { "https://zkpassport.id" + it.groupValues[1].lowercase() + it.groupValues[2] } ?: trimmed
        val url = runCatching { io.ktor.http.Url(https) }.getOrNull() ?: return null
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
            mode = p["m"]?.takeIf { it.isNotBlank() } ?: "fast", sdkVersion = p["v"], devMode = p["dev"] == "1", link = https,
            diwRelay = ZkPassportDiwRelay.parse(p[ZkPassportDiwRelay.URL_PARAM], p[ZkPassportDiwRelay.ROOM_PARAM]),
            diwNearby = ZkPassportDiwNearby.parse(p[ZkPassportDiwNearby.LAN_PARAM], p[ZkPassportDiwNearby.BLE_PARAM]),
        )
    }

    private val DOMAIN = Regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
    private val KEY = Regex("^0[23][0-9a-f]{64}$")

    /** encodeURIComponent for the base64 alphabet. */
    private fun encode(s: String): String = s.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")

    /** encodeURIComponent for an address. */
    private fun uriComponent(s: String): String = s.encodeURLParameter()

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
            faceMatch = (o["facematch"] as? JsonObject)?.let { f ->
                ZkPassportFaceMatch(
                    kind = f["kind"].text() ?: return@let null, strict = f["mode"].text() == "strict",
                    environment = f["environment"].text() ?: "development", appId = f["appId"].text(),
                    signerDigest = f["signerDigest"].text(), platform = f["platform"].text(),
                )
            },
        )
    }

    /** A result for a bundle that could not be checked at all. */
    fun failure(error: String, devMode: Boolean): ZkPassportResult = ZkPassportResult(
        false, listOf(error), null, null, null, null, null, null, null,
        emptyList(), emptyList(), emptyList(), emptyList(), null, devMode,
    )

    internal fun JsonObject.array(key: String) = this[key]?.jsonArray
}

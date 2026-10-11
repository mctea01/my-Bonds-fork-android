package diw.wallet.core.w3c

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.str
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonObject
import org.multipaz.cbor.CborBuilder
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.MapBuilder
import org.multipaz.cbor.buildCborArray
import org.multipaz.claim.Claim
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.util.fromBase64Url
import kotlin.time.Instant

/**
 * How the issuer-provided bytes of a W3C credential are encoded.
 * [SD_JWT] covers issuers that announce a W3C format but return a W3C credential inside an SD-JWT (TWDIW).
 */
enum class W3cEncoding(val wire: String) {
    JWT("jwt"),
    JSON_LD("json-ld"),
    SD_JWT("sd-jwt");

    companion object {
        fun fromWire(w: String?): W3cEncoding = entries.firstOrNull { it.wire == w } ?: JWT
    }
}

/** Fields shared by the key-bound and keyless W3C credential implementations. */
interface W3cVcCredential {
    /** OpenID4VCI format the credential was requested in, e.g. jwt_vc_json, ldp_vc. */
    val format: String
    /** W3C type list, most specific last. */
    val types: List<String>
    val encoding: W3cEncoding

    val raw: String get() = (this as Credential).issuerProvidedData.decodeToString()

    /** The credential as a W3C data model object (vc claim of a JWT, the JSON-LD document, or the SD-JWT payload's vc). */
    fun credentialJson(): JsonObject = W3cVc.credentialObject(raw, encoding)
}

internal suspend fun w3cValidity(raw: String, encoding: W3cEncoding): Pair<Instant, Instant> {
    val (from, until) = W3cVc.validity(W3cVc.credentialObject(raw, encoding), W3cVc.jwtPayloadOrNull(raw, encoding))
    return (from ?: Instant.fromEpochSeconds(0)) to (until ?: Instant.fromEpochSeconds(253402300799))
}

/** A W3C Verifiable Credential bound to a holder key in a [SecureArea]. */
class KeyBoundW3cVcCredential : SecureAreaBoundCredential, W3cVcCredential {
    override lateinit var format: String
        private set
    override lateinit var types: List<String>
        private set
    override var encoding: W3cEncoding = W3cEncoding.JWT
        private set

    private constructor(
        document: Document,
        asReplacementForIdentifier: String?,
        domain: String,
        secureArea: SecureArea,
        format: String,
        types: List<String>,
        encoding: W3cEncoding,
    ) : super(document, asReplacementForIdentifier, domain, secureArea) {
        this.format = format
        this.types = types
        this.encoding = encoding
    }

    constructor(document: Document) : super(document)

    override val credentialType: String get() = CREDENTIAL_TYPE

    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        format = dataItem["format"].asTstr
        types = dataItem["types"].asArray.map { it.asTstr }
        encoding = W3cEncoding.fromWire(dataItem.getOrNull("encoding")?.asTstr)
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("format", format)
        builder.put("types", buildCborArray { types.forEach { add(it) } })
        builder.put("encoding", encoding.wire)
    }

    /** Re-labels the encoding once the issued bytes are known (an SD-JWT where a JWT was announced). */
    fun setEncodingBeforeCertify(e: W3cEncoding) {
        encoding = e
    }

    override suspend fun getClaims(documentTypeRepository: DocumentTypeRepository?): List<Claim> = emptyList()

    override suspend fun extractValidityFromIssuerData(): Pair<Instant, Instant> = w3cValidity(raw, encoding)

    companion object {
        const val CREDENTIAL_TYPE = "DiwKeyBoundW3cVcCredential"

        suspend fun create(
            document: Document,
            domain: String,
            secureArea: SecureArea,
            format: String,
            types: List<String>,
            createKeySettings: CreateKeySettings,
        ): KeyBoundW3cVcCredential = KeyBoundW3cVcCredential(document, null, domain, secureArea, format, types, W3cEncoding.JWT)
            .apply { generateKey(createKeySettings) }
    }
}

/** A W3C Verifiable Credential without holder binding (bearer credential). */
class KeylessW3cVcCredential : Credential, W3cVcCredential {
    override lateinit var format: String
        private set
    override lateinit var types: List<String>
        private set
    override var encoding: W3cEncoding = W3cEncoding.JWT
        private set

    private constructor(
        document: Document,
        domain: String,
        format: String,
        types: List<String>,
    ) : super(document, null, domain) {
        this.format = format
        this.types = types
    }

    constructor(document: Document) : super(document)

    override val credentialType: String get() = CREDENTIAL_TYPE

    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        format = dataItem["format"].asTstr
        types = dataItem["types"].asArray.map { it.asTstr }
        encoding = W3cEncoding.fromWire(dataItem.getOrNull("encoding")?.asTstr)
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("format", format)
        builder.put("types", buildCborArray { types.forEach { add(it) } })
        builder.put("encoding", encoding.wire)
    }

    fun setEncodingBeforeCertify(e: W3cEncoding) {
        encoding = e
    }

    override suspend fun getClaims(documentTypeRepository: DocumentTypeRepository?): List<Claim> = emptyList()

    override suspend fun extractValidityFromIssuerData(): Pair<Instant, Instant> = w3cValidity(raw, encoding)

    companion object {
        const val CREDENTIAL_TYPE = "DiwKeylessW3cVcCredential"

        suspend fun create(document: Document, domain: String, format: String, types: List<String>): KeylessW3cVcCredential =
            KeylessW3cVcCredential(document, domain, format, types).apply { addToDocument() }
    }
}

/** Registers this wallet's own credential implementations with a Multipaz document store. */
fun DocumentStore.Builder.addDiwCredentialImplementations(): DocumentStore.Builder = apply {
    addCredentialImplementation(KeyBoundW3cVcCredential.CREDENTIAL_TYPE) { doc -> KeyBoundW3cVcCredential(doc) }
    addCredentialImplementation(KeylessW3cVcCredential.CREDENTIAL_TYPE) { doc -> KeylessW3cVcCredential(doc) }
}

internal fun base64UrlJson(part: String): JsonObject = DiwJson.parseToJsonElement(part.fromBase64Url().decodeToString()) as JsonObject

internal fun JsonObject.idOf(name: String): String? = str(name) ?: (this[name] as? JsonObject)?.str("id")

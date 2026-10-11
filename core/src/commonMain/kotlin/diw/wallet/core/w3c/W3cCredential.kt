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
import org.multipaz.crypto.EcPublicKey
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
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

        /** Encoding of issued bytes: JSON-LD object, SD-JWT (a '~' after the JWS), or plain JWT. */
        fun detect(raw: String): W3cEncoding {
            val t = raw.trim()
            return when {
                t.startsWith("{") -> JSON_LD
                '~' in t -> SD_JWT
                else -> JWT
            }
        }
    }
}

/**
 * A W3C Verifiable Credential (VCDM 1.1 or 2.0) in JWT, SD-JWT or JSON-LD form.
 *
 * Unlike Multipaz's own credential types, the holder key is optional and may be shared: profiles that need one
 * holder identifier for all their credentials (TWDIW, Microsoft Verified ID) bind every credential to the same
 * key, and deleting one credential must not delete that key. Keys owned by a single credential are deleted with it.
 */
class W3cVcCredential : Credential {
    /** OpenID4VCI format the credential was requested in, e.g. jwt_vc_json, ldp_vc. */
    lateinit var format: String
        private set
    /** W3C type list, most specific last. */
    lateinit var types: List<String>
        private set
    var encoding: W3cEncoding = W3cEncoding.JWT
        private set
    /** Secure area holding the holder key; null for a bearer credential. */
    var secureArea: SecureArea? = null
        private set
    var alias: String? = null
        private set
    /** True when [alias] belongs to a holder identity shared by several credentials. */
    var sharedKey: Boolean = false
        private set
    /** Holder identifier the issuer bound the credential to (DID), when there is one. */
    var holderDid: String? = null
        private set

    private constructor(
        document: Document,
        domain: String,
        format: String,
        types: List<String>,
        secureArea: SecureArea?,
        alias: String?,
        sharedKey: Boolean,
        holderDid: String?,
    ) : super(document, null, domain) {
        this.format = format
        this.types = types
        this.secureArea = secureArea
        this.alias = alias
        this.sharedKey = sharedKey
        this.holderDid = holderDid
    }

    /** Deserializing constructor; [secureAreas] resolves the stored secure area identifier. */
    constructor(document: Document, secureAreas: SecureAreaRepository) : super(document) {
        this.secureAreas = secureAreas
    }

    private var secureAreas: SecureAreaRepository? = null

    override val credentialType: String get() = CREDENTIAL_TYPE

    val keyBound: Boolean get() = alias != null

    val raw: String get() = issuerProvidedData.decodeToString()

    /** The credential as a W3C data model object (vc claim of a JWT, the JSON-LD document, or the SD-JWT payload's vc). */
    fun credentialJson(): JsonObject = W3cVc.credentialObject(raw, encoding)

    suspend fun holderPublicKey(): EcPublicKey? {
        val a = alias ?: return null
        return secureArea?.getKeyInfo(a)?.publicKey
    }

    override suspend fun deserialize(dataItem: DataItem) {
        super.deserialize(dataItem)
        format = dataItem["format"].asTstr
        types = dataItem["types"].asArray.map { it.asTstr }
        encoding = W3cEncoding.fromWire(dataItem.getOrNull("encoding")?.asTstr)
        alias = dataItem.getOrNull("alias")?.asTstr
        sharedKey = dataItem.getOrNull("sharedKey")?.asBoolean ?: false
        holderDid = dataItem.getOrNull("holderDid")?.asTstr
        secureArea = dataItem.getOrNull("secureAreaIdentifier")?.asTstr?.let { secureAreas?.getImplementation(it) }
    }

    override fun addSerializedData(builder: MapBuilder<CborBuilder>) {
        super.addSerializedData(builder)
        builder.put("format", format)
        builder.put("types", buildCborArray { types.forEach { add(it) } })
        builder.put("encoding", encoding.wire)
        alias?.let { builder.put("alias", it) }
        secureArea?.let { builder.put("secureAreaIdentifier", it.identifier) }
        builder.put("sharedKey", sharedKey)
        holderDid?.let { builder.put("holderDid", it) }
    }

    /** Records what the issued bytes turned out to be before [certify] (an SD-JWT where a JWT was announced). */
    fun setIssuedFormBeforeCertify(e: W3cEncoding, types: List<String>?, holderDid: String?) {
        encoding = e
        if (!types.isNullOrEmpty()) this.types = types
        if (holderDid != null) this.holderDid = holderDid
    }

    override suspend fun isInvalidated(): Boolean {
        val a = alias ?: return false
        return secureArea?.getKeyInvalidated(a) ?: false
    }

    override suspend fun clear() {
        val a = alias
        if (a != null && !sharedKey) runCatching { secureArea?.deleteKey(a) }
        super.clear()
    }

    override suspend fun getClaims(documentTypeRepository: DocumentTypeRepository?): List<Claim> = emptyList()

    override suspend fun extractValidityFromIssuerData(): Pair<Instant, Instant> {
        val (from, until) = W3cVc.validity(W3cVc.credentialObject(raw, encoding), W3cVc.jwtPayloadOrNull(raw, encoding))
        return (from ?: Instant.fromEpochSeconds(0)) to (until ?: Instant.fromEpochSeconds(253402300799))
    }

    companion object {
        const val CREDENTIAL_TYPE = "DiwW3cVcCredential"

        /** A credential bound to [alias] in [secureArea]; [sharedKey] keeps the key when the credential is deleted. */
        suspend fun createKeyBound(
            document: Document,
            domain: String,
            format: String,
            types: List<String>,
            secureArea: SecureArea,
            alias: String,
            sharedKey: Boolean,
            holderDid: String?,
        ): W3cVcCredential {
            secureArea.getKeyInfo(alias)
            return W3cVcCredential(document, domain, format, types, secureArea, alias, sharedKey, holderDid).apply { addToDocument() }
        }

        suspend fun createKeyless(document: Document, domain: String, format: String, types: List<String>): W3cVcCredential =
            W3cVcCredential(document, domain, format, types, null, null, false, null).apply { addToDocument() }
    }
}

/** Registers this wallet's own credential implementations with a Multipaz document store. */
fun DocumentStore.Builder.addDiwCredentialImplementations(secureAreas: SecureAreaRepository): DocumentStore.Builder = apply {
    addCredentialImplementation(W3cVcCredential.CREDENTIAL_TYPE) { doc -> W3cVcCredential(doc, secureAreas) }
}

internal fun base64UrlJson(part: String): JsonObject = DiwJson.parseToJsonElement(part.fromBase64Url().decodeToString()) as JsonObject

internal fun JsonObject.idOf(name: String): String? = str(name) ?: (this[name] as? JsonObject)?.str("id")

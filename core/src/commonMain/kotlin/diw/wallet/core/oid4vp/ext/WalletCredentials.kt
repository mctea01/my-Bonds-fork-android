package diw.wallet.core.oid4vp.ext

import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.util.DiwJson
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.w3c.SdJwtParts
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.W3cVcCredential
import diw.wallet.core.w3c.base64UrlJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** How a stored credential is secured, which decides how it can be presented. */
enum class CredentialFamily {
    MDOC,
    SD_JWT_VC,
    /** W3C VC as a JWT (jwt_vc_json, jwt_vc_json-ld, vc+jwt). */
    W3C_JWT,
    /** W3C VC inside an SD-JWT (TWDIW). */
    W3C_SD_JWT,
    /** W3C VC as JSON-LD with a Data Integrity proof. */
    W3C_LDP,
}

/**
 * A stored credential as the extended presentation engine (Presentation Exchange, DCQL for W3C formats, legacy
 * and profile requests) sees it: the JSON its paths are evaluated against, and what it can be presented as.
 */
class WalletCredential(
    val document: Document,
    val credential: Credential,
    val family: CredentialFamily,
    /** Fully disclosed JSON: SD-JWT payload with disclosures applied, JWT payload, JSON-LD document, or mdoc namespaces. */
    val json: JsonObject,
    /** The W3C credential object when [json] wraps it (vc claim of a JWT); paths are tried against it as well. */
    val w3c: JsonObject?,
    val types: List<String>,
    val vct: String?,
    val docType: String?,
    val issuer: String?,
    /** SD-JWT parts for choosing disclosures. */
    val sdJwt: SdJwtParts?,
    /** Undisclosed SD-JWT payload (with _sd digests) for choosing disclosures. */
    val sdPayload: JsonObject?,
) {
    /** Format identifiers (DCQL and Presentation Exchange) this credential can be presented as. */
    val formats: Set<String> get() = when (family) {
        CredentialFamily.MDOC -> setOf("mso_mdoc")
        CredentialFamily.SD_JWT_VC -> setOf("dc+sd-jwt", "vc+sd-jwt")
        CredentialFamily.W3C_JWT -> setOf("jwt_vc_json", "jwt_vc", "jwt_vc_json-ld", "jwt_vp", "jwt_vp_json", "jwt_vp_json-ld", "vc+jwt")
        CredentialFamily.W3C_SD_JWT -> setOf("vc+sd-jwt", "jwt_vc", "jwt_vc_json", "jwt_vp", "jwt_vp_json", "dc+sd-jwt")
        CredentialFamily.W3C_LDP -> setOf("ldp_vc", "ldp_vp", "ldp", "di_vc", "di_vp")
    }

    val keyBound: Boolean get() = credential is SecureAreaBoundCredential || (credential as? W3cVcCredential)?.keyBound == true

    val raw: String get() = credential.issuerProvidedData.decodeToString()

    val displayName: String get() = document.displayName ?: W3cVc.displayType(types) ?: vct ?: docType ?: "Credential"

    /** TWDIW cards: W3C SD-JWT credentials bound to the TWDIW wallet holder. */
    val isTwdiw: Boolean get() = document.issuanceRecord?.profile == "twdiw" || (family == CredentialFamily.W3C_SD_JWT && document.issuanceRecord?.specs?.contains("TWDIW") == true)

    companion object {
        /** Allowance for an issuer clock ahead of the wallet's when a credential has just been issued. */
        private val CLOCK_SKEW = 5.minutes

        /**
         * All certified credentials in [store] the extended engine can present (one per document per kind). Credentials
         * outside their validity period (expired, or not yet valid beyond [CLOCK_SKEW]) are left out.
         */
        suspend fun load(store: DocumentStore, now: Instant = Clock.System.now()): List<WalletCredential> {
            val out = mutableListOf<WalletCredential>()
            for (id in store.listDocumentIds()) {
                val doc = store.lookupDocument(id) ?: continue
                val creds = doc.getCertifiedCredentials().filter { it.validFrom <= now + CLOCK_SKEW && now < it.validUntil }
                // Prefer the least used credential of each kind so batch issued credentials rotate.
                creds.groupBy { it::class }.values.mapNotNull { list -> list.minByOrNull { it.usageCount } }.forEach { c ->
                    runCatching { from(doc, c) }.getOrNull()?.let { out += it }
                }
            }
            return out
        }

        suspend fun from(doc: Document, c: Credential): WalletCredential? = when (c) {
            is W3cVcCredential -> fromW3c(doc, c)
            is MdocCredential -> fromMdoc(doc, c)
            is SdJwtVcCredential -> fromSdJwtVc(doc, c, (c as Credential).issuerProvidedData.decodeToString())
            else -> null
        }

        private fun fromW3c(doc: Document, c: W3cVcCredential): WalletCredential {
            val raw = c.raw
            return when (c.encoding) {
                W3cEncoding.JSON_LD -> {
                    val vc = W3cVc.credentialObject(raw, W3cEncoding.JSON_LD)
                    WalletCredential(doc, c, CredentialFamily.W3C_LDP, vc, vc, W3cVc.types(vc), null, null, W3cVc.issuer(vc, null), null, null)
                }
                W3cEncoding.JWT -> {
                    val payload = base64UrlJson(raw.trim().split('.')[1])
                    val vc = payload["vc"] as? JsonObject ?: payload
                    WalletCredential(doc, c, CredentialFamily.W3C_JWT, payload, vc, W3cVc.types(vc), null, null, W3cVc.issuer(vc, payload), null, null)
                }
                W3cEncoding.SD_JWT -> {
                    val parts = SdJwtDisclosures.parse(raw)
                    val payload = base64UrlJson(parts.issuerJwt.split('.')[1])
                    val resolved = SdJwtDisclosures.resolve(payload, parts.disclosures)
                    val vc = resolved["vc"] as? JsonObject ?: resolved
                    WalletCredential(doc, c, CredentialFamily.W3C_SD_JWT, resolved, vc, W3cVc.types(vc), null, null, W3cVc.issuer(vc, resolved), parts, payload)
                }
            }
        }

        private fun fromSdJwtVc(doc: Document, c: Credential, raw: String): WalletCredential {
            val parts = SdJwtDisclosures.parse(raw)
            val payload = base64UrlJson(parts.issuerJwt.split('.')[1])
            val resolved = SdJwtDisclosures.resolve(payload, parts.disclosures)
            return WalletCredential(
                doc, c, CredentialFamily.SD_JWT_VC, resolved, null, emptyList(),
                (c as SdJwtVcCredential).vct, null, resolved["iss"]?.let { (it as? JsonPrimitive)?.content }, parts, payload,
            )
        }

        private fun fromMdoc(doc: Document, c: MdocCredential): WalletCredential {
            val issuerSigned = Cbor.decode(c.issuerProvidedData.toByteArray())
            val ns = IssuerNamespaces.fromDataItem(issuerSigned["nameSpaces"])
            val json = buildJsonObject {
                for ((name, items) in ns.data) {
                    put(name, buildJsonObject { for ((elem, item) in items) put(elem, cborToJson(item.dataElementValue)) })
                }
            }
            return WalletCredential(doc, c, CredentialFamily.MDOC, json, null, emptyList(), null, c.docType, null, null, null)
        }

        /** CBOR data element value as JSON for path evaluation and display (byte strings as base64url, full-date tags as text). */
        fun cborToJson(d: DataItem): JsonElement = when (d) {
            is Tstr -> JsonPrimitive(d.value)
            is Bstr -> JsonPrimitive(d.value.toBase64Url())
            is CborArray -> JsonArray(d.items.map { cborToJson(it) })
            is CborMap -> buildJsonObject { for ((k, v) in d.items) put((k as? Tstr)?.value ?: k.toString(), cborToJson(v)) }
            is Tagged -> cborToJson(d.taggedItem)
            is Simple -> when (d) {
                Simple.TRUE -> JsonPrimitive(true)
                Simple.FALSE -> JsonPrimitive(false)
                else -> JsonNull
            }
            else -> runCatching { JsonPrimitive(d.asNumber) }.getOrElse {
                runCatching { JsonPrimitive(d.asDouble) }.getOrElse { DiwJson.parseToJsonElement("\"" + d.toString().replace("\"", "'") + "\"") }
            }
        }
    }
}

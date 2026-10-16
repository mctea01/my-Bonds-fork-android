package diw.wallet.core.oid4vci

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import org.multipaz.document.Document

/** Storage domains shared by issuance and presentment. */
object CredentialDomains {
    const val MDOC = "mdoc"
    const val SD_JWT = "sdjwt"
    const val SD_JWT_KEYLESS = "sdjwt-keyless"
    /** W3C Verifiable Credentials (JWT, SD-JWT wrapped, JSON-LD), key bound or bearer. */
    const val W3C = "w3c"
}

/**
 * Per-document issuance facts, kept in [Document.appData] as JSON. The UI uses it for the trust tier,
 * the TEST environment watermark and issuer display; notification uses [notificationId].
 */
@Serializable
data class IssuanceRecord(
    val credentialIssuer: String,
    val configurationId: String,
    val format: String,
    val docType: String? = null,
    val vct: String? = null,
    val tier: String,
    val environment: String? = null,
    val official: Boolean = false,
    val anchorName: String? = null,
    val labels: List<String> = emptyList(),
    val notificationId: String? = null,
    val issuedAt: Long,
    val keyStorage: String? = null,
    val pendingTransactionId: String? = null,
    /** Specifications used besides OpenID4VCI 1.0 and the credential format, e.g. OpenID4VCI draft 13 or TWDIW. */
    val specs: List<String> = emptyList(),
    /** Why the issuer got its trust tier, for the details view. */
    val reasons: List<String> = emptyList(),
    /** Claim names the issuer gave for the user's language, keyed by claim path joined with '.'. */
    val claimNames: Map<String, String> = emptyMap(),
    /** W3C credential types from the issuer configuration. */
    val w3cTypes: List<String> = emptyList(),
    /** Profile the issuer follows (twdiw, draft11, msvid), or null for OpenID4VCI 1.0. */
    val profile: String? = null,
    /** Holder DID the credential is bound to, when bound to a DID. */
    val holderDid: String? = null,
    /** Card art from the credential's display metadata (logo URI, background and text colours as written by the issuer). */
    val logoUri: String? = null,
    val backgroundColor: String? = null,
    val textColor: String? = null,
    /** Card face image URI from the credential display (background_image), shown as the card when it decodes. */
    val backgroundImageUri: String? = null,
    /** When the display metadata was last read for a credential stored before card faces were kept (epoch seconds). */
    val displayCheckedAt: Long? = null,
) {
    val trustTier: TrustTier get() = TrustTier.valueOf(tier)
    val trustEnvironment: TrustEnvironment? get() = TrustEnvironment.fromId(environment)
    val isTestEnvironment: Boolean get() = trustEnvironment == TrustEnvironment.TEST

    fun encode(): ByteString = DiwJson.encodeToString(serializer(), this).encodeToByteString()

    fun withTrust(t: TrustDecision): IssuanceRecord = copy(
        tier = t.tier.name,
        environment = t.environment?.id,
        official = t.official,
        anchorName = t.anchorName,
        labels = t.labels.map(TrustLabel::name),
        reasons = t.reasons,
    )

    companion object {
        fun decode(bytes: ByteString?): IssuanceRecord? = bytes?.let {
            runCatching { DiwJson.decodeFromString(serializer(), it.decodeToString()) }.getOrNull()
        }
    }
}

val Document.issuanceRecord: IssuanceRecord? get() = IssuanceRecord.decode(appData)

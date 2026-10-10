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
    )

    companion object {
        fun decode(bytes: ByteString?): IssuanceRecord? = bytes?.let {
            runCatching { DiwJson.decodeFromString(serializer(), it.decodeToString()) }.getOrNull()
        }
    }
}

val Document.issuanceRecord: IssuanceRecord? get() = IssuanceRecord.decode(appData)

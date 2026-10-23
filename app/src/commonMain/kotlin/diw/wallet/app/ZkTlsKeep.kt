package diw.wallet.app

import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.holder.HolderIdentities
import diw.wallet.core.holder.HolderKey
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vci.CredentialDomains
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustLabel
import diw.wallet.core.trust.TrustTier
import diw.wallet.core.zktls.WebProofCredentials
import diw.wallet.core.zktls.ZkTlsProved
import diw.wallet.core.zktls.ZkTlsSessionRequest
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.json.JsonObject
import org.multipaz.document.Document
import org.multipaz.sdjwt.credential.KeyBoundSdJwtVcCredential
import kotlin.time.Clock

/**
 * Keeps a zkTLS result in the documents list (WebProofCredentials). Before proving, a credential key is made in a
 * pending document; its public key goes to the verifier as the receipt binding. After a passed proof the pending
 * document is certified with the verifier's receipt (a web-proof), or, when the verifier gave none or it did not
 * check out, with this wallet's own statement of what it read (a web-record, not a zero-knowledge proof). On any
 * other end it is deleted.
 */
class ZkTlsKeep(private val model: WalletModel) {
    class Pending(val document: Document, val credential: KeyBoundSdJwtVcCredential, val jwk: JsonObject, val keyStorage: String?)

    /** What was kept, for the result screen. */
    data class Kept(val documentId: String, val receipt: Boolean, val note: String?)

    suspend fun prepare(): Pending = unlocked {
        val keys = model.keyRequest()
        val record = IssuanceRecord(
            credentialIssuer = "", configurationId = CONFIGURATION, format = "dc+sd-jwt", vct = WebProofCredentials.VCT_RECORD,
            tier = TrustTier.T3.name, issuedAt = Clock.System.now().epochSeconds, keyStorage = keys.keyStorage, profile = PROFILE,
        )
        val created = model.documentStore.createDocument(displayName = "網站查驗結果", typeDisplayName = TYPE_NAME, appData = record.encode())
        try {
            val credential = KeyBoundSdJwtVcCredential.create(
                created, null, CredentialDomains.SD_JWT, keys.secureArea, WebProofCredentials.VCT_RECORD,
                keys.createKeySettings(ByteString(PlatformCrypto.randomBytes(16))),
            )
            val jwk = credential.secureArea.getKeyInfo(credential.alias).publicKey.toJwk()
            Pending(created, credential, WebProofCredentials.publicJwk(jwk), keys.keyStorage)
        } catch (e: Exception) {
            runCatching { model.documentStore.deleteDocument(created.identifier) }
            throw e
        }
    }

    suspend fun discard(p: Pending) {
        runCatching { model.documentStore.deleteDocument(p.document.identifier) }
    }

    /**
     * Certifies [p] with what [proved] read from the page of [session]. [verifierName] and [verifierTrust] describe
     * who signed the request; a receipt from them is as trusted as they are, never T1.
     */
    suspend fun keep(
        p: Pending,
        session: ZkTlsSessionRequest.Verified,
        proved: ZkTlsProved,
        verifierName: String,
        verifierTrust: TrustDecision?,
    ): Kept = unlocked {
        val outcome = proved.outcome
        val title = outcome.profile.title
        var note: String? = null
        val receipt = proved.receipt?.let { r ->
            runCatching { WebProofCredentials.checkReceipt(r, session, model.didResolver(), p.jwk, outcome); r }
                .onFailure { note = "查驗方的回執無法驗證（${model.describe(it)}），改存為本機紀錄" }
                .getOrNull()
        }
        if (proved.receipt == null) note = "查驗方沒有簽發回執，改存為本機紀錄"
        val now = Clock.System.now()
        val record: IssuanceRecord
        val compact: String
        if (receipt != null) {
            val tier = when (verifierTrust?.tier) {
                TrustTier.T1, TrustTier.T2 -> TrustTier.T2
                else -> TrustTier.T3
            }
            compact = receipt
            record = IssuanceRecord(
                credentialIssuer = session.did ?: verifierName, configurationId = CONFIGURATION, format = "dc+sd-jwt",
                vct = WebProofCredentials.VCT_PROOF, tier = tier.name,
                environment = (verifierTrust?.environment ?: TrustEnvironment.USER).id, official = false,
                anchorName = verifierName, labels = verifierTrust?.labels.orEmpty().map { it.name },
                issuedAt = now.epochSeconds, keyStorage = p.keyStorage,
                specs = listOf("IETF SD-JWT VC", "TLSNotary"), claimNames = WebProofCredentials.claimLabels(outcome.profile),
                profile = PROFILE, displayDescription = "zkTLS 網站查驗證明：${outcome.profile.host}，由查驗方簽發",
            )
        } else {
            val issuer = issuerKey()
            compact = WebProofCredentials.issue(
                WebProofCredentials.VCT_RECORD, issuer.did!!, issuer.signingKey("ES256"), p.jwk,
                WebProofCredentials.source(outcome.profile, proved.time, proved.certChainDer, proved.cipherSuite),
                WebProofCredentials.METHOD_DEVICE, WebProofCredentials.claims(outcome),
                attestation = issuer.keyInfo.attestation.certChain?.certificates?.map { it.encoded.toByteArray() },
                now = now,
            )
            record = IssuanceRecord(
                credentialIssuer = issuer.did!!, configurationId = CONFIGURATION, format = "dc+sd-jwt",
                vct = WebProofCredentials.VCT_RECORD, tier = TrustTier.T3.name, environment = TrustEnvironment.USER.id,
                official = false, anchorName = "本錢包（網站紀錄）",
                labels = listOf(TrustLabel.SELF_ISSUED.name) + if (issuer.keyInfo.attestation.certChain == null) listOf(TrustLabel.KEY_NOT_ATTESTED.name) else emptyList(),
                issuedAt = now.epochSeconds, keyStorage = p.keyStorage,
                specs = listOf("IETF SD-JWT VC"), claimNames = WebProofCredentials.claimLabels(outcome.profile),
                profile = PROFILE, displayDescription = "裝置證明，不是零知識證明：本機讀取 ${outcome.profile.host} 的紀錄",
            )
        }
        try {
            p.credential.certify(compact.encodeToByteString())
            p.document.edit {
                displayName = title
                appData = record.encode()
                provisioned = true
            }
        } catch (e: Exception) {
            discard(p)
            throw e
        }
        model.documents.value = model.documentStore.listDocuments()
        model.platform.registerDigitalCredentials(model)
        model.record(
            HistoryKind.ISSUED, if (receipt != null) verifierName else "本錢包（網站紀錄）", if (receipt != null) verifierTrust else null,
            listOf(title), WebProofCredentials.claims(outcome).map { it.label ?: it.name },
        )
        Kept(p.document.identifier, receipt != null, note)
    }

    private suspend fun issuerKey(): HolderKey {
        val backend = model.backends.first()
        val userAuth = model.settings.requireUserAuth || !backend.protection.hardware
        return model.holderIdentities.getOrCreate(HolderIdentities.DOCUMENT_ISSUER, "did:key", backend.secureArea,
            backend.settings(ByteString(PlatformCrypto.randomBytes(16)), userAuth))
    }

    private suspend fun <T> unlocked(block: suspend () -> T): T = try {
        withContext(model.unlockProvider) { block() }
    } finally {
        model.endOperation()
    }

    companion object {
        const val PROFILE = "web-proof"
        const val CONFIGURATION = "zktls-web"
        const val TYPE_NAME = "網站查驗結果"
    }
}

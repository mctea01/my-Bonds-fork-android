package diw.wallet.app

import diw.wallet.app.ui.DocumentCategory
import diw.wallet.app.ui.categoryOf
import diw.wallet.app.ui.storedTrust
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vci.issuanceRecord
import diw.wallet.core.profile.twdiw.AnchorState
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.CredentialStatusChecker
import diw.wallet.core.status.RiskLevel
import diw.wallet.core.status.StatusAssurance
import diw.wallet.core.status.StatusDecision
import diw.wallet.core.status.StatusFinding
import diw.wallet.core.status.StatusPolicy
import diw.wallet.core.status.StatusVerdict
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.W3cVcCredential
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.sync.withPermit
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.document.Document
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.sdjwt.SdJwt
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/** The wallet's view of one document's status: the last result that means something, and the last failed attempt. */
data class DocumentStatus(
    val status: CredentialStatus,
    /** Why the latest query gave no result; [status] is then the result before it. */
    val lastError: String? = null,
    val attemptedAt: Instant = status.checkedAt,
)

@Serializable
private data class StoredStatus(
    val state: String,
    val trusted: Boolean,
    val assurance: String,
    val environment: String? = null,
    val checkedAt: Long,
    val code: Int? = null,
    val label: String? = null,
    val detail: String? = null,
    val uri: String? = null,
    val index: Int? = null,
    val referenced: Boolean = true,
    val lastError: String? = null,
    val attemptedAt: Long,
)

/**
 * Keeps every document's status current without the user asking: on start and on return to the app, documents
 * whose last result is older than their risk allows are queried in the background (three at a time), results are
 * kept in storage for offline use, and a change (revoked, suspended, valid again) is announced and recorded in the
 * history. A failed query keeps the previous meaningful result and notes the failure. The TWDIW issuers of held
 * cards are checked again against the trust list and Arbitrum, and a changed trust is written to the card.
 */
class StatusMonitor(private val model: WalletModel) {
    val statuses = MutableStateFlow<Map<String, DocumentStatus>>(emptyMap())

    /** Documents being queried now. */
    val checking = MutableStateFlow<Set<String>>(emptySet())

    /** Issuers being checked on chain now, as (done, total); null when idle. */
    val issuerCheck = MutableStateFlow<Pair<Int, Int>?>(null)

    private val lock = Mutex()
    private val gate = Semaphore(PARALLEL)
    private var runJob: Job? = null
    private var lastIssuerCheck: Instant? = null

    suspend fun load() {
        val raw = model.storage.getTable(table).get(KEY) ?: return
        val map = runCatching { DiwJson.decodeFromString(MapSerializer(String.serializer(), StoredStatus.serializer()), raw.decodeToString()) }
            .getOrNull() ?: return
        statuses.value = map.mapNotNull { (id, s) -> runCatching { id to restore(s) }.getOrNull() }.toMap()
    }

    /** The status of [doc] judged at the document's own risk. */
    fun decision(doc: Document, now: Instant = Clock.System.now()): StatusDecision =
        StatusPolicy.decide(statuses.value[doc.identifier]?.status, riskOf(doc.issuanceRecord), now)

    /**
     * Queries, in the background, every document whose status is due ([force]: all of them), then re-checks the
     * TWDIW issuers of held cards. A run already going is not started twice.
     */
    fun refreshDue(force: Boolean = false) {
        if (!force && !model.settings.autoStatus) return
        if (runJob?.isActive == true) return
        runJob = model.scope.launch {
            val now = Clock.System.now()
            val checker = checker()
            val due = model.documents.value.filter { force || isDue(it, now) }
            coroutineScope { due.forEach { doc -> launch { gate.withPermit { query(doc, checker) } } } }
            verifyIssuers(force)
        }
    }

    /** Queries [doc] now, as the Query button does. */
    fun refresh(doc: Document) = model.scope.launch { gate.withPermit { query(doc, checker()) } }

    /** Queries the documents a request is about to use when their result is too old for the request's [risk]. */
    fun refreshFor(documentIds: Collection<String>, risk: RiskLevel) {
        val now = Clock.System.now()
        model.documents.value.filter { it.identifier in documentIds }.forEach { doc ->
            val s = statuses.value[doc.identifier]
            // An unconfirmed status is asked again whenever a request needs it: the list may be reachable now.
            val unconfirmed = s != null && s.status.state == RevocationCheckState.UNKNOWN && s.status.referenced
            if (s == null || unconfirmed || now - s.status.checkedAt > risk.maxStatusAge / 2) refresh(doc)
        }
    }

    fun forget(documentId: String) = model.scope.launch {
        lock.withLock {
            statuses.value = statuses.value - documentId
            save()
        }
    }

    private fun checker() = CredentialStatusChecker(model.http, model.trust, didTrust = model.didTrust)

    private fun isDue(doc: Document, now: Instant): Boolean {
        val record = doc.issuanceRecord
        if (record?.pendingTransactionId != null) return false
        val s = statuses.value[doc.identifier] ?: return true
        val since = now - s.attemptedAt
        return when {
            s.lastError != null -> since > RETRY_AFTER_FAILURE
            !s.status.referenced -> since > NO_STATUS_RECHECK
            else -> since > StatusPolicy.refreshAfter(riskOf(record))
        }
    }

    private suspend fun query(doc: Document, checker: CredentialStatusChecker) {
        val id = doc.identifier
        val credential = doc.getCertifiedCredentials().firstOrNull() ?: return
        checking.value = checking.value + id
        try {
            val now = Clock.System.now()
            val result = runCatching { checker.check(credential) }.getOrElse {
                CredentialStatus(RevocationCheckState.UNKNOWN, false, null, now, model.describe(it))
            }
            lock.withLock {
                val previous = statuses.value[id]
                val next = merge(previous, result, now)
                statuses.value = statuses.value + (id to next)
                save()
                announce(doc, previous?.status, next.status)
            }
        } finally {
            checking.value = checking.value - id
        }
    }

    /** A result without meaning (the list could not be read) keeps the previous meaningful one and notes why. */
    private fun merge(previous: DocumentStatus?, result: CredentialStatus, now: Instant): DocumentStatus {
        val failed = result.state == RevocationCheckState.UNKNOWN && result.referenced
        return if (failed && previous != null && previous.status.state in DEFINITE) {
            DocumentStatus(previous.status, result.detail ?: "無法讀取狀態清單", now)
        } else DocumentStatus(result, null, now)
    }

    /** Announces a change of a definite state; the first result is announced only when it is not valid. */
    private fun announce(doc: Document, before: CredentialStatus?, after: CredentialStatus) {
        val from = before?.state?.takeIf { it in DEFINITE }
        val to = after.state.takeIf { it in DEFINITE } ?: return
        if (to == from || (from == null && to == RevocationCheckState.VALID)) return
        val name = doc.displayName ?: "證件"
        val note = (from?.let { CredentialDetails.stateMeaning(it) } ?: "尚未查詢") + " → " + CredentialDetails.stateMeaning(to)
        model.record(
            HistoryKind.STATUS, issuerName(doc), storedTrust(doc), listOf(name),
            note = "證件狀態：$note" + (after.label?.let { "（$it）" } ?: ""), status = to.name,
        )
        model.message.value = "「$name」狀態變更：${CredentialDetails.stateMeaning(to)}"
    }

    /**
     * Checks the TWDIW issuers of held cards again (listing, self-signed document, Arbitrum registration) at most
     * every [ISSUER_RECHECK], and writes a changed trust to each card. Offline, or with the chain unavailable, the
     * cards keep the trust they have.
     */
    private suspend fun verifyIssuers(force: Boolean) {
        val now = Clock.System.now()
        if (!force && lastIssuerCheck?.let { now - it < ISSUER_RECHECK } == true) return
        val byIssuer = model.documents.value
            .filter { it.issuanceRecord?.profile == TaiwanModel.TWDIW }
            .mapNotNull { doc -> issuerDid(doc)?.let { it to doc } }
            .groupBy({ it.first }, { it.second })
        if (byIssuer.isEmpty()) return
        lastIssuerCheck = now
        var done = 0
        issuerCheck.value = 0 to byIssuer.size
        var changed = false
        try {
            for ((did, docs) in byIssuer) {
                val trust = recheckIssuer(did)
                if (trust != null) for (doc in docs) if (applyTrust(doc, trust)) changed = true
                issuerCheck.value = ++done to byIssuer.size
            }
        } finally {
            issuerCheck.value = null
        }
        if (changed) model.refreshDocuments()
    }

    /** The issuer's trust from a fresh check, or null when the check could not be completed. */
    private suspend fun recheckIssuer(did: String): TrustDecision? {
        val snap = try {
            model.twdiwTrust.recheck(did)
        } catch (_: Exception) {
            return null
        }
        if (snap?.anchor == AnchorState.UNAVAILABLE.name) return null
        return runCatching { model.didTrust.decideOrDefault(did, TrustRole.ISSUER, "Not listed by any trust source") }.getOrNull()
    }

    private suspend fun applyTrust(doc: Document, trust: TrustDecision, why: String = "重新查驗信任清單與區塊鏈註冊"): Boolean {
        val record = doc.issuanceRecord ?: return false
        if (record.tier == trust.tier.name && record.anchorName == trust.anchorName && record.official == trust.official &&
            record.environment == trust.environment?.id) return false
        val before = WalletModel.tierTitle(record.trustTier) + (record.anchorName?.let { "（$it）" } ?: "")
        doc.edit { appData = record.withTrust(trust).encode() }
        val name = doc.displayName ?: "證件"
        model.record(
            HistoryKind.STATUS, issuerName(doc), trust, listOf(name),
            note = "發行端信任：$before → ${WalletModel.tierTitle(trust.tier)}" + (trust.anchorName?.let { "（$it）" } ?: "") + "，$why",
            status = TRUST_CHANGE,
        )
        model.message.value = "「$name」的發行端信任變更為 ${WalletModel.tierTitle(trust.tier)}"
        return true
    }

    /**
     * Judges again the issuer of every held document that [affected] selects, after a trust source changed (an anchor
     * or DID removed or added), and writes a changed trust to it with a history entry and a message. [accept] filters
     * the new decisions, so that adding a source can only bring a document under that source.
     */
    suspend fun reevaluateIssuers(why: String, affected: (IssuanceRecord) -> Boolean, accept: (TrustDecision) -> Boolean = { true }) {
        var changed = false
        for (doc in model.documents.value) {
            val record = doc.issuanceRecord ?: continue
            if (!affected(record)) continue
            val trust = runCatching { currentIssuerTrust(doc) }.getOrNull() ?: continue
            if (accept(trust) && applyTrust(doc, trust, why)) changed = true
        }
        if (changed) model.refreshDocuments()
    }

    /**
     * The issuer's trust by the sources as they are now, judged as at issuance: its certificate chain (mdoc with its
     * docType, SD-JWT VC x5c), or its DID (W3C credentials, and SD-JWT VCs whose key came from the issuer DID).
     */
    private suspend fun currentIssuerTrust(doc: Document): TrustDecision? {
        issuerDid(doc)?.let { return model.didTrust.decideOrDefault(it, TrustRole.ISSUER, "Not listed by any trust source") }
        return when (val cred = doc.getCertifiedCredentials().firstOrNull()) {
            is MdocCredential -> cred.issuerAuth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]?.asX509CertChain?.certificates
                ?.let { model.trust.decide(TrustRole.ISSUER, it, docType = cred.docType) }
            is SdJwtVcCredential -> SdJwt.fromCompactSerialization(cred.issuerProvidedData.decodeToString()).x5c?.certificates
                ?.let { model.trust.decide(TrustRole.ISSUER, it) }
            else -> null
        }
    }

    /** The issuer DID of a W3C credential, or of an SD-JWT VC that has no x5c (its key came from the DID). */
    private suspend fun issuerDid(doc: Document): String? {
        val creds = doc.getCertifiedCredentials()
        creds.filterIsInstance<SdJwtVcCredential>().firstOrNull()?.let { cred ->
            val sdJwt = runCatching { SdJwt.fromCompactSerialization(cred.issuerProvidedData.decodeToString()) }.getOrNull() ?: return null
            return sdJwt.issuer?.takeIf { sdJwt.x5c == null && it.startsWith("did:") }
        }
        val cred = creds.filterIsInstance<W3cVcCredential>().firstOrNull() ?: return null
        val vc = runCatching { cred.credentialJson() }.getOrNull() ?: return null
        return W3cVc.issuer(vc, W3cVc.jwtPayloadOrNull(cred.raw, cred.encoding))?.takeIf { it.startsWith("did:") }
    }

    private fun issuerName(doc: Document): String = doc.issuanceRecord?.anchorName ?: doc.typeDisplayName ?: doc.issuanceRecord?.credentialIssuer ?: "發行端"

    private suspend fun save() {
        val map = statuses.value.mapValues { (_, d) ->
            val s = d.status
            StoredStatus(
                state = s.state.name, trusted = s.trusted, assurance = s.assurance.name, environment = s.environment?.id,
                checkedAt = s.checkedAt.toEpochMilliseconds(), code = s.code, label = s.label, detail = s.detail, uri = s.uri,
                index = s.index, referenced = s.referenced, lastError = d.lastError, attemptedAt = d.attemptedAt.toEpochMilliseconds(),
            )
        }
        val t = model.storage.getTable(table)
        val bytes = DiwJson.encodeToString(MapSerializer(String.serializer(), StoredStatus.serializer()), map).encodeToByteString()
        runCatching { if (t.get(KEY) == null) t.insert(KEY, bytes) else t.update(KEY, bytes) }
    }

    private fun restore(s: StoredStatus): DocumentStatus {
        val status = CredentialStatus(
            state = RevocationCheckState.valueOf(s.state),
            trusted = s.trusted,
            environment = TrustEnvironment.fromId(s.environment),
            checkedAt = Instant.fromEpochMilliseconds(s.checkedAt),
            detail = s.detail,
            code = s.code,
            uri = s.uri,
            index = s.index,
            label = s.label,
            assurance = StatusAssurance.valueOf(s.assurance),
            referenced = s.referenced,
        )
        return DocumentStatus(status, s.lastError, Instant.fromEpochMilliseconds(s.attemptedAt))
    }

    companion object {
        private val table = StorageTableSpec(name = "DiwStatus", supportPartitions = false, supportExpiration = false)
        private const val KEY = "statuses"
        private const val PARALLEL = 3
        private val DEFINITE = setOf(RevocationCheckState.VALID, RevocationCheckState.INVALID, RevocationCheckState.SUSPENDED)
        private val RETRY_AFTER_FAILURE = 10.minutes
        private val NO_STATUS_RECHECK = 7.days
        private val ISSUER_RECHECK = 12.hours

        /** [HistoryEntry.status] of an issuer trust change. */
        const val TRUST_CHANGE = "TRUST"

        /**
         * Risk of a document's own use, which sets how fresh its status must be: identity documents high, government
         * wallet cards medium, membership and other cards low.
         */
        fun riskOf(record: IssuanceRecord?): RiskLevel = when (categoryOf(record)) {
            DocumentCategory.IDENTITY -> RiskLevel.HIGH
            DocumentCategory.GOVERNMENT -> RiskLevel.MEDIUM
            DocumentCategory.ORGANIZATION, DocumentCategory.OTHER -> RiskLevel.LOW
        }
    }
}

/** Words for status findings, verdicts and risk levels. */
object StatusTexts {
    fun finding(f: StatusFinding): String = when (f) {
        StatusFinding.VALID -> "有效"
        StatusFinding.VALID_TLS_ONLY -> "有效（清單僅經 HTTPS 確認）"
        StatusFinding.VALID_UNVERIFIED -> "有效（清單簽章未驗證）"
        StatusFinding.REVOKED -> "已撤銷"
        StatusFinding.SUSPENDED -> "暫停使用"
        StatusFinding.NO_STATUS -> "發行端未提供狀態"
        StatusFinding.UNKNOWN -> "無法確認狀態"
        StatusFinding.NOT_CHECKED -> "尚未查詢狀態"
    }

    fun explain(f: StatusFinding): String = when (f) {
        StatusFinding.VALID -> "狀態清單由發行端或信任錨點簽署，簽章已驗證。"
        StatusFinding.VALID_TLS_ONLY -> "狀態清單的金鑰取自 jku 網址，但該網址無法對應到發行端，來源只由 HTTPS 連線確認。"
        StatusFinding.VALID_UNVERIFIED -> "狀態清單的簽章無法驗證，內容可能遭竄改。"
        StatusFinding.REVOKED -> "發行端已撤銷這張證件，不應再使用。"
        StatusFinding.SUSPENDED -> "發行端暫停了這張證件，恢復前不應使用。"
        StatusFinding.NO_STATUS -> "這張證件沒有狀態清單，是否有效只能依有效期間判斷。"
        StatusFinding.UNKNOWN -> "狀態清單無法讀取，或回傳的值沒有定義。"
        StatusFinding.NOT_CHECKED -> "還沒有查詢過這張證件的狀態。"
    }

    fun risk(r: RiskLevel): String = when (r) {
        RiskLevel.LOW -> "低風險"
        RiskLevel.MEDIUM -> "中風險"
        RiskLevel.HIGH -> "高風險"
    }

    fun riskExamples(r: RiskLevel): String = when (r) {
        RiskLevel.LOW -> "會員、出席、優惠"
        RiskLevel.MEDIUM -> "政府服務、臨櫃取貨、年齡確認"
        RiskLevel.HIGH -> "身分核對、金融、門禁與病歷"
    }

    fun verdict(v: StatusVerdict): String = when (v) {
        StatusVerdict.ACCEPT -> "可接受"
        StatusVerdict.CAUTION -> "需留意"
        StatusVerdict.REJECT -> "不應接受"
    }

    /** One line: the finding, the verdict at the risk, staleness and the test environment. */
    fun summary(d: StatusDecision): String =
        finding(d.finding) + "，依${risk(d.risk)}用途" + verdict(d.verdict) + qualifiers(d)

    /** Why a pass shows as caution: a stale result or a test list. */
    fun qualifiers(d: StatusDecision): String = buildList {
        if (d.test) add("測試環境")
        if (d.stale) add("查詢結果已過時")
    }.let { if (it.isEmpty()) "" else "（" + it.joinToString("，") + "）" }
}

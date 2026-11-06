package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.legal.Integration
import diw.wallet.app.legal.LegalDocument
import diw.wallet.app.legal.LegalStrings
import diw.wallet.app.legal.LegalTexts
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.util.DiwJson
import diw.wallet.core.oid4vci.issuanceRecord
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import org.multipaz.document.Document
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec
import kotlin.time.Clock
import kotlin.time.Instant

/** One decision on one version of a legal text. */
@Serializable
data class ConsentRecord(val version: Int, val accepted: Boolean, val epochSeconds: Long) {
    val date: String get() = Instant.fromEpochSeconds(epochSeconds).toString().take(10)
}

/**
 * The holder's decisions on the terms, the privacy policy and each integration statement (by Integration.id), and the
 * integrations whose one-time reminder before the first request the holder has seen ([notices]).
 */
@Serializable
data class LegalConsent(
    val terms: ConsentRecord? = null,
    val privacy: ConsentRecord? = null,
    val integrations: Map<String, ConsentRecord> = emptyMap(),
    val notices: Set<String> = emptySet(),
) {
    fun current(doc: LegalDocument, record: ConsentRecord?) = record != null && record.accepted && record.version == doc.version

    /** The terms and the privacy policy are accepted in their current versions. */
    val basicsAccepted: Boolean get() = current(LegalTexts.terms, terms) && current(LegalTexts.privacy, privacy)

    fun record(i: Integration): ConsentRecord? = integrations[i.id]

    /** The holder agreed to the current statement of [i]. */
    fun enabled(i: Integration): Boolean = current(LegalTexts.statement(i).document, record(i))

    /** Statements of the shipped integrations with no decision on their current version. */
    val undecided: List<Integration>
        get() = Integration.entries.filter { it.available && record(it)?.version != LegalTexts.statement(it).document.version }

    /** Nothing is left to decide: the app may contact other parties and handle links. */
    val complete: Boolean get() = basicsAccepted && undecided.isEmpty()
}

/**
 * Consent to the legal texts and the integration statements. Until the first-start pages are done the wallet handles
 * no link or request and contacts no one; an integration whose current statement the holder did not accept stays off.
 */
class LegalModel(private val model: WalletModel) {
    val consent = MutableStateFlow(LegalConsent())
    private val lock = Mutex()
    private lateinit var storage: Storage

    val complete: Boolean get() = consent.value.complete

    fun enabled(i: Integration): Boolean = consent.value.enabled(i)

    suspend fun load(storage: Storage) {
        this.storage = storage
        val raw = storage.getTable(table).get(KEY) ?: return
        consent.value = runCatching { DiwJson.decodeFromString(LegalConsent.serializer(), raw.decodeToString()) }.getOrDefault(LegalConsent())
    }

    /** Suspends until the first-start pages are done. */
    suspend fun awaitComplete() {
        consent.first { it.complete }
    }

    fun acceptBasics() = update { c ->
        val now = now()
        c.copy(terms = ConsentRecord(LegalTexts.terms.version, true, now), privacy = ConsentRecord(LegalTexts.privacy.version, true, now))
    }

    fun decide(i: Integration, accepted: Boolean) = update { c ->
        c.copy(integrations = c.integrations + (i.id to ConsentRecord(LegalTexts.statement(i).document.version, accepted, now())))
    }

    /** The holder has seen the reminder shown before the first request of [i]. */
    fun noticed(i: Integration): Boolean = i.id in consent.value.notices

    fun acknowledge(i: Integration) = update { c -> c.copy(notices = c.notices + i.id) }

    /** Accepts every text; used by tests that run the wallet without the first-start pages. */
    internal suspend fun acceptAll() {
        acceptBasics().join()
        Integration.entries.filter { it.available }.forEach {
            decide(it, true).join()
            acknowledge(it).join()
        }
    }

    private fun update(transform: (LegalConsent) -> LegalConsent) = model.scope.launch {
        lock.withLock {
            val next = transform(consent.value)
            consent.value = next
            val t = storage.getTable(table)
            val bytes = DiwJson.encodeToString(LegalConsent.serializer(), next).encodeToByteString()
            if (t.get(KEY) == null) t.insert(KEY, bytes) else t.update(KEY, bytes)
        }
    }

    /** The integration a held credential belongs to, from the profile it was issued under. */
    fun integrationOf(doc: Document): Integration? = when (doc.issuanceRecord?.profile) {
        TaiwanModel.TWDIW -> Integration.TWDIW
        TaiwanModel.MSVID -> Integration.MS_VERIFIED_ID
        else -> null
    }

    /** The credential may be used with its issuer's services (status lists, issuer checks) now. */
    fun allows(doc: Document): Boolean = integrationOf(doc)?.let { enabled(it) } ?: true

    fun name(i: Integration): String = LegalTexts.statement(i).name

    /** Message for a link, request or action that needs a switched-off service. */
    fun disabledMessage(i: Integration): String = tr(Res.string.legal_not_enabled, name(i))

    private fun now() = Clock.System.now().epochSeconds

    companion object {
        private val table = StorageTableSpec(name = "DiwLegal", supportPartitions = false, supportExpiration = false)
        private const val KEY = "consent"
        private val HOST = Regex("""https?://([A-Za-z0-9.-]+)""")

        /**
         * [uri] names a wallet.gov.tw address anywhere in it (credential_offer_uri, request_uri, an offer by value),
         * also when percent-encoded or JSON-escaped.
         */
        fun namesTwdiwHost(uri: String): Boolean {
            var text = uri
            repeat(3) { text = percentDecode(text) }
            text = text.replace("\\/", "/")
            return HOST.findAll(text).any { TwdiwDialect.isTwdiwHost(it.groupValues[1]) }
        }

        /** Decodes %XX sequences as UTF-8; anything malformed stays as it is. */
        private fun percentDecode(text: String): String {
            if ('%' !in text) return text
            val out = StringBuilder(text.length)
            val bytes = ArrayList<Byte>()
            fun flush() {
                if (bytes.isNotEmpty()) out.append(bytes.toByteArray().decodeToString())
                bytes.clear()
            }
            var i = 0
            while (i < text.length) {
                val hex = if (text[i] == '%' && i + 2 < text.length) text.substring(i + 1, i + 3).toIntOrNull(16) else null
                if (hex != null) {
                    bytes.add(hex.toByte())
                    i += 3
                } else {
                    flush()
                    out.append(text[i])
                    i++
                }
            }
            flush()
            return out.toString()
        }
    }
}

/** A link, request or action needs [integration], whose statement the holder did not accept. */
class IntegrationDisabledException(val integration: Integration, message: String) : Exception(message)

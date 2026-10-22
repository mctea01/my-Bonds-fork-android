package diw.wallet.core.trust

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.util.ProtocolException
import org.multipaz.mdoc.vical.SignedVical
import org.multipaz.mdoc.rical.SignedRical
import org.multipaz.trustmanagement.TrustEntryVical
import org.multipaz.trustmanagement.TrustEntryRical
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.env.TrustEnvironment
import kotlinx.io.bytestring.ByteString
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.Storage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustEntryAlreadyExistsException
import org.multipaz.trustmanagement.TrustEntryX509Cert
import diw.wallet.core.x509.displaySubject
import kotlin.time.Clock
import kotlin.time.Instant

/** What a trust anchor is used for. Anchors are never shared across roles. */
enum class TrustRole(val id: String) {
    ISSUER("issuer"),
    VERIFIER("verifier"),
    WALLET_PROVIDER("wallet-provider"),
    /** Only roots explicitly authorized to sign lists of other issuer/reader roots. */
    TRUST_LIST_PROVIDER("trust-list-provider"),
    STATUS_LIST("status-list"),
    TSA("tsa"),
    /** Signers of documents (PDF, CMS, XML, OFD signatures and seals). */
    DOCUMENT("document"),
}

/** Metadata extension keys stored in [TrustMetadata.extensions]. */
object TrustMetadataKeys {
    const val ENVIRONMENT = "diw.environment"
    const val OFFICIAL = "diw.official"
    const val SOURCE = "diw.source"
    /** "true": the anchor certifies the identity of the parties below it (T2), not that they are listed (T1). */
    const val IDENTITY = "diw.identity"
    /** Region of a built-in public CA ("CN" for mainland China). */
    const val REGION = "diw.region"
    /** The [TrustListKind.id] of the trust list that names the anchor. */
    const val LIST = "diw.list"
    /** "true": the trust list names the service as qualified (eIDAS). */
    const val QUALIFIED = "diw.qualified"
}

fun trustMetadata(
    displayName: String,
    environment: TrustEnvironment,
    official: Boolean,
    source: String,
    privacyPolicyUrl: String? = null,
    identity: Boolean = false,
    region: String? = null,
): TrustMetadata = TrustMetadata(
    displayName = displayName,
    privacyPolicyUrl = privacyPolicyUrl,
    testOnly = environment == TrustEnvironment.TEST,
    extensions = buildMap {
        put(TrustMetadataKeys.ENVIRONMENT, environment.id)
        put(TrustMetadataKeys.OFFICIAL, official.toString())
        put(TrustMetadataKeys.SOURCE, source)
        if (identity) put(TrustMetadataKeys.IDENTITY, "true")
        region?.let { put(TrustMetadataKeys.REGION, it) }
    }
)

/** Result of a chain lookup in one role across enabled environments. */
data class AnchorMatch(
    val environment: TrustEnvironment,
    val metadata: TrustMetadata,
    val official: Boolean,
    val anchor: X509Cert,
)

/** An intermediate CA certificate the user imported: it only links chains to anchors and never sets a tier. */
data class StoredIntermediate(
    val certificate: X509Cert,
    val name: String,
    val source: String?,
    val identifier: String,
)

/** An X.509 anchor as stored: the role and environment it applies to, and its metadata. */
data class StoredAnchor(
    val role: TrustRole,
    val environment: TrustEnvironment,
    val certificate: X509Cert,
    val metadata: TrustMetadata,
    val identifier: String,
) {
    val official: Boolean get() = metadata.extensions[TrustMetadataKeys.OFFICIAL] == "true" && environment == TrustEnvironment.PRODUCTION
    val source: String? get() = metadata.extensions[TrustMetadataKeys.SOURCE]
}

/**
 * Holds one Multipaz [TrustManager] per (role, environment). Lookups consult the environments enabled by the
 * current [EnvironmentPolicy] (TEST always, marked as test), in the order PRODUCTION, USER, the trust lists
 * ([trustLists], document signers and time-stamp authorities only), SYSTEM, TEST.
 *
 * Intermediate CA certificates (built in, [BuiltInPublicRoots.intermediates], and imported by the user) fill the gap
 * when a chain leaves its issuers out. They are not anchors: a chain they complete is trusted only when it reaches an
 * anchor, and the tier is the anchor's.
 */
class TrustRegistry(
    private val storage: Storage,
    var policy: EnvironmentPolicy,
) {
    companion object {
        /** A CA certificate that is not self-issued: what [addIntermediate] accepts. */
        fun isIntermediate(c: X509Cert): Boolean =
            c.subject != c.issuer && runCatching { c.basicConstraints?.first == true }.getOrDefault(false)

        /** A self-issued CA certificate (or a self-issued one without basic constraints, as older roots are). */
        fun isRoot(c: X509Cert): Boolean =
            c.subject == c.issuer && runCatching { c.basicConstraints?.first != false }.getOrDefault(true)

        /**
         * The system store holds web PKI CAs: they may identify issuers, verifiers, status list signers, document
         * signers and time-stamp authorities, nothing else (never a wallet provider).
         */
        private val SYSTEM_ROLES = setOf(TrustRole.ISSUER, TrustRole.VERIFIER, TrustRole.STATUS_LIST, TrustRole.DOCUMENT, TrustRole.TSA)

        /** Roles whose chains are validated with PKIX only (RFC 5280), not with the mdoc trust profile. */
        private val PKIX_ROLES = setOf(TrustRole.DOCUMENT, TrustRole.TSA)

        private const val MAX_FETCHES = 3
        private const val MAX_CHAIN = 8
    }

    private val managers = mutableMapOf<Pair<TrustRole, TrustEnvironment>, TrustManager>()

    /** The verified AATL and EUTL snapshots in use; consulted for the lists [EnvironmentPolicy.trustLists] enables. */
    val trustLists = TrustLists()

    /** The user's intermediate certificates, kept in a store of their own that no lookup treats as anchors. */
    private val intermediateStore by lazy { TrustManager(storage, identifier = "intermediates") }

    /** Built-in and user intermediates, loaded once and reset when the user adds or removes one. */
    private var pool: List<X509Cert>? = null

    /**
     * Downloads what an AIA caIssuers URL publishes (a DER or PEM certificate, or PKCS#7 certs-only); null leaves
     * chains as presented. Used by [decide] when a chain stops short of every anchor because the sender left out an
     * intermediate certificate.
     */
    var issuerFetcher: (suspend (String) -> ByteArray?)? = null

    /** Certificates fetched per URL in this run, so one missing intermediate is downloaded once. */
    private val fetched = mutableMapOf<String, List<X509Cert>>()

    fun manager(role: TrustRole, environment: TrustEnvironment): TrustManager =
        managers.getOrPut(role to environment) {
            TrustManager(storage, identifier = "${role.id}-${environment.id}")
        }

    /**
     * Signed lists (VICAL, RICAL) as imported, by role and environment. The verifying [manager] holds a list only
     * while it is valid; this copy keeps the source so an expired list can still be refreshed or removed.
     */
    private fun listArchive(role: TrustRole, environment: TrustEnvironment): TrustManager =
        archives.getOrPut(role to environment) {
            TrustManager(storage, identifier = "signed-lists-${role.id}-${environment.id}")
        }
    private val archives = mutableMapOf<Pair<TrustRole, TrustEnvironment>, TrustManager>()

    /** notAfter of each installed list entry, parsed once per entry. */
    private val listExpiry = mutableMapOf<String, Instant?>()

    /** Installs a signed issuer/reader CA list only after verifying the provider's separately pinned trust root. */
    suspend fun importSignedMdocTrustList(
        kind: String,
        bytes: ByteArray,
        name: String,
        sourceUrl: String,
        environment: TrustEnvironment = TrustEnvironment.USER,
    ): String {
        if (bytes.isEmpty() || bytes.size > 4 * 1024 * 1024)
            throw ProtocolException("invalid_trust_list", "Signed trust list must be at most 4 MiB")
        val now = Clock.System.now()
        val list = when (kind) {
            "vical" -> SignedListInfo.vical(bytes).also {
                if (SignedVical.parse(bytes).vical.certificateInfos.isEmpty())
                    throw ProtocolException("invalid_trust_list", "VICAL contains no issuer CAs")
            }
            "rical" -> SignedListInfo.rical(bytes).also {
                val infos = SignedRical.parse(bytes).rical.certificateInfos
                if (infos.isEmpty() || infos.any { !it.isTrustAnchor })
                    throw ProtocolException("invalid_trust_list", "RICAL requires explicit trust anchors; non-anchor entries cannot be installed as roots")
            }
            else -> throw ProtocolException("invalid_trust_list", "Unsupported signed trust list format")
        }
        if (list.notAfter != null && list.notAfter <= now)
            throw ProtocolException("expired_trust_list", "Signed trust list has expired")
        val publisherAnchor = if (list.signer.isEmpty()) null else match(TrustRole.TRUST_LIST_PROVIDER, list.signer)
        if (publisherAnchor == null || publisherAnchor.environment != environment)
            throw ProtocolException("untrusted_trust_list", "Signed trust list requires a publisher root in the same trust environment")
        val role = list.role
        val archive = listArchive(role, environment)
        val archived = archive.getEntries().firstOrNull { it.metadata.extensions[TrustMetadataKeys.SOURCE] == sourceUrl && list.sameKind(it) }
        if (archived != null) {
            val previous = SignedListInfo.of(archived) ?: error("unreachable")
            if (previous.provider != list.provider || previous.signer.first() != list.signer.first()) {
                throw ProtocolException("untrusted_trust_list", "Signed trust list publisher identity changed")
            }
            if (previous.issue != null && (list.issue == null || list.issue <= previous.issue))
                throw ProtocolException("stale_trust_list", "Signed trust list issue did not increase")
        }
        val metadata = trustMetadata(name.ifBlank { list.provider }, environment, official = false, source = sourceUrl)
        val encoded = ByteString(bytes)
        for (m in listOf(archive, manager(role, environment))) {
            val old = m.getEntries().firstOrNull { it.metadata.extensions[TrustMetadataKeys.SOURCE] == sourceUrl && list.sameKind(it) }
            when {
                old is TrustEntryVical -> m.updateVical(old, encoded)
                old is TrustEntryRical -> m.updateRical(old, encoded)
                kind == "vical" -> m.addVical(encoded, metadata)
                else -> m.addRical(encoded, metadata)
            }
        }
        listExpiry.clear()
        return "$kind: ${list.provider} (issue ${list.issue ?: "unversioned"})"
    }

    /** Every imported signed list, expired ones included. */
    suspend fun mdocTrustLists(): List<StoredSignedList> {
        val now = Clock.System.now()
        return listOf(TrustEnvironment.USER, TrustEnvironment.PRODUCTION).flatMap { env ->
            listOf(TrustRole.ISSUER, TrustRole.VERIFIER).flatMap { role ->
                listArchive(role, env).getEntries().mapNotNull { entry ->
                    val info = runCatching { SignedListInfo.of(entry) }.getOrNull() ?: return@mapNotNull null
                    StoredSignedList(
                        identifier = entry.identifier, kind = info.kind, environment = env,
                        name = entry.metadata.displayName ?: info.provider, provider = info.provider,
                        source = entry.metadata.extensions[TrustMetadataKeys.SOURCE], issue = info.issue,
                        notAfter = info.notAfter, nextUpdate = info.nextUpdate, certificates = info.certificates,
                        expired = info.notAfter != null && info.notAfter <= now,
                    )
                }
            }
        }
    }

    /** Removes an imported list from verification and from the archive. */
    suspend fun removeMdocTrustList(list: StoredSignedList): Boolean {
        val role = if (list.kind == "vical") TrustRole.ISSUER else TrustRole.VERIFIER
        val archive = listArchive(role, list.environment)
        val archived = archive.getEntries().firstOrNull { it.identifier == list.identifier } ?: return false
        val source = archived.metadata.extensions[TrustMetadataKeys.SOURCE]
        val m = manager(role, list.environment)
        m.getEntries().filter { (it is TrustEntryVical || it is TrustEntryRical) && it.metadata.extensions[TrustMetadataKeys.SOURCE] == source }
            .forEach { m.deleteEntry(it) }
        listExpiry.clear()
        return archive.deleteEntry(archived)
    }

    /**
     * Fetches lists whose announced next update (or expiry) has passed from the HTTPS address they were imported
     * from. One failing list does not stop the others; each failure is reported with the list's name.
     */
    suspend fun refreshDueMdocTrustLists(fetch: suspend (String) -> ByteArray): SignedListRefresh {
        var refreshed = 0
        val failures = mutableListOf<String>()
        val now = Clock.System.now()
        for (list in mdocTrustLists()) {
            val source = list.source?.takeIf { it.startsWith("https://") } ?: continue
            val due = (list.nextUpdate == null || list.nextUpdate <= now) || list.expired
            if (!due) continue
            try {
                importSignedMdocTrustList(list.kind, fetch(source), list.name, source, list.environment)
                refreshed++
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: ProtocolException) {
                if (e.code != "stale_trust_list") failures += "${list.name}: ${e.message}"
            } catch (e: Exception) {
                failures += "${list.name}: ${e.message ?: e::class.simpleName}"
            }
        }
        return SignedListRefresh(refreshed, failures)
    }

    /**
     * Multipaz does not enforce a signed list's notAfter while verifying certificates. An expired list is taken out
     * of the verifying manager (the archive keeps it for refresh), so it fails closed without losing its source.
     */
    private suspend fun retireExpiredMdocTrustLists(role: TrustRole, atTime: Instant) {
        if (role != TrustRole.ISSUER && role != TrustRole.VERIFIER) return
        for (env in listOf(TrustEnvironment.USER, TrustEnvironment.PRODUCTION)) {
            if (env !in policy.enabledEnvironments()) continue
            val m = manager(role, env)
            for (entry in m.getEntries()) {
                if (entry !is TrustEntryVical && entry !is TrustEntryRical) continue
                val notAfter = listExpiry.getOrPut(entry.identifier) { runCatching { SignedListInfo.of(entry)?.notAfter }.getOrNull() }
                if (notAfter != null && atTime >= notAfter && Clock.System.now() >= notAfter) {
                    m.deleteEntry(entry)
                    listExpiry.remove(entry.identifier)
                }
            }
        }
    }

    suspend fun addAnchor(
        role: TrustRole,
        environment: TrustEnvironment,
        certificate: X509Cert,
        displayName: String,
        official: Boolean,
        source: String,
        identity: Boolean = false,
    ): Boolean = try {
        manager(role, environment).addX509Cert(
            certificate,
            trustMetadata(displayName, environment, official, source, identity = identity)
        )
        true
    } catch (_: TrustEntryAlreadyExistsException) {
        false
    }

    /**
     * Adds the [BuiltInAnchors] (Taiwan GPKI) as PRODUCTION identity anchors and the [BuiltInTestAnchors] (Multipaz
     * issuers and readers) as TEST anchors for their roles, except the production Google and Apple ID pass issuers,
     * which are PRODUCTION anchors that are not official; anchors already stored are left as they are. Returns how
     * many were added.
     */
    suspend fun seedBuiltInAnchors(): Int {
        var added = 0
        for (a in BuiltInAnchors.all) for (role in a.roles) {
            if (addAnchor(role, TrustEnvironment.PRODUCTION, a.certificate, a.name, official = false, source = BuiltInAnchors.SOURCE, identity = true)) added++
        }
        for (a in BuiltInTestAnchors.all) for (role in a.roles) {
            val env = if (a.production) TrustEnvironment.PRODUCTION else TrustEnvironment.TEST
            if (addAnchor(role, env, a.certificate, a.name, official = false, source = a.source)) added++
        }
        return added
    }

    /**
     * Stores [certificate] as an intermediate: it must be a CA certificate that is not self-issued (a self-issued
     * certificate is a root and is imported as an anchor). False when it is already stored.
     */
    suspend fun addIntermediate(certificate: X509Cert, name: String, source: String): Boolean {
        require(isIntermediate(certificate)) { "Not an intermediate CA certificate" }
        if (BuiltInPublicRoots.intermediates.any { it.certificate == certificate }) return false
        return try {
            intermediateStore.addX509Cert(certificate, TrustMetadata(displayName = name, extensions = mapOf(TrustMetadataKeys.SOURCE to source)))
            pool = null
            true
        } catch (_: TrustEntryAlreadyExistsException) {
            false
        }
    }

    suspend fun intermediates(): List<StoredIntermediate> = intermediateStore.getEntries().filterIsInstance<TrustEntryX509Cert>()
        .map { StoredIntermediate(it.certificate, it.metadata.displayName ?: it.certificate.displaySubject(), it.metadata.extensions[TrustMetadataKeys.SOURCE], it.identifier) }

    suspend fun removeIntermediate(intermediate: StoredIntermediate): Boolean {
        val entry = intermediateStore.getEntries().firstOrNull { it.identifier == intermediate.identifier } ?: return false
        return intermediateStore.deleteEntry(entry).also { pool = null }
    }

    private suspend fun pool(): List<X509Cert> = pool ?: (BuiltInPublicRoots.intermediates.map { it.certificate } +
        intermediateStore.getEntries().filterIsInstance<TrustEntryX509Cert>().map { it.certificate } +
        BuiltInPublicRoots.importableRoots.map { it.certificate }).also { pool = it }

    /**
     * The certificates that complete chains: built-in and user intermediates, and the built-in roots that are offered
     * for import (untrusted until the user imports one as an anchor).
     */
    suspend fun chainCertificates(): List<X509Cert> = pool()

    /**
     * [chain] extended towards a root with the built-in and user intermediates that issued its last certificate; the
     * chain itself when none did. Validity and signatures are checked when the longer chain is evaluated.
     */
    suspend fun extendFromPool(chain: List<X509Cert>): List<X509Cert> {
        if (chain.isEmpty()) return chain
        val candidates = pool()
        if (candidates.isEmpty()) return chain
        val out = chain.toMutableList()
        while (out.size < MAX_CHAIN) {
            val last = out.last()
            if (last.subject == last.issuer) break
            out.add(candidates.firstOrNull { c -> c !in out && issues(c, last) } ?: break)
        }
        return out
    }

    suspend fun anchors(role: TrustRole, environment: TrustEnvironment): List<Pair<X509Cert, TrustMetadata>> =
        manager(role, environment).getTrustPoints().map { it.certificate to it.metadata }

    /** Every stored X.509 anchor of every role and environment, enabled or not (the system store is not stored here). */
    suspend fun allAnchors(): List<StoredAnchor> = TrustEnvironment.entries.filter { it != TrustEnvironment.SYSTEM }.flatMap { env ->
        TrustRole.entries.flatMap { role ->
            manager(role, env).getEntries().filterIsInstance<TrustEntryX509Cert>()
                .map { StoredAnchor(role, env, it.certificate, it.metadata, it.identifier) }
        }
    }

    /** Removes [anchor]; false when it was not stored. */
    suspend fun removeAnchor(anchor: StoredAnchor): Boolean {
        val m = manager(anchor.role, anchor.environment)
        val entry = m.getEntries().firstOrNull { it.identifier == anchor.identifier } ?: return false
        return m.deleteEntry(entry)
    }

    /**
     * Finds a trusted anchor for [chain] (leaf first, root may be omitted), completed from the built-in and user
     * intermediates when it stops short of every anchor. Returns null when no enabled environment trusts the chain.
     */
    suspend fun match(
        role: TrustRole,
        chain: List<X509Cert>,
        atTime: Instant = Clock.System.now(),
        docType: String? = null,
    ): AnchorMatch? {
        if (chain.isEmpty()) return null
        retireExpiredMdocTrustLists(role, atTime)
        matchChain(role, chain, atTime, docType)?.let { return it }
        val longer = extendFromPool(chain)
        return if (longer.size > chain.size) matchChain(role, longer, atTime, docType) else null
    }

    private suspend fun matchChain(role: TrustRole, chain: List<X509Cert>, atTime: Instant, docType: String?): AnchorMatch? {
        var listsChecked = false
        for (env in policy.enabledEnvironments()) {
            if (!listsChecked && (env == TrustEnvironment.SYSTEM || env == TrustEnvironment.TEST)) {
                listsChecked = true
                listMatch(role, chain, atTime)?.let { return it }
            }
            if (env == TrustEnvironment.SYSTEM) {
                if (role !in SYSTEM_ROLES) continue
                val found = runCatching {
                    PublicRoots.anchorOf(chain, atTime, platform = policy.systemStoreEnabled, mainlandChina = policy.mainlandChinaRootsEnabled,
                        timestamping = role == TrustRole.TSA)
                }.getOrNull() ?: continue
                val metadata = trustMetadata(found.label, env, official = false, source = found.source, region = found.region)
                return AnchorMatch(env, metadata, false, found.certificate)
            }
            val m = manager(role, env)
            // Multipaz handles EC chains; an RSA chain (GPKI, web PKI) makes it throw and is validated with PKIX.
            // Document signers and time-stamp authorities are plain PKIX chains: Multipaz's mdoc profile checks
            // (signing key usage of the leaf) do not apply to them.
            val result = if (role in PKIX_ROLES) null else runCatching { m.verify(chain, atTime, validateCaValidity = true, docType = docType) }.getOrNull()
            // Only when Multipaz could not evaluate the chain: an EC chain it found untrusted stays untrusted.
            val point = if (result != null) result.trustPoints.firstOrNull()?.takeIf { result.isTrusted } else {
                val points = m.getTrustPoints()
                Pkix.anchorOf(chain, points.map { it.certificate }, atTime)?.let { a -> points.first { it.certificate == a } }
            }
            if (point != null) {
                val official = point.metadata.extensions[TrustMetadataKeys.OFFICIAL] == "true" &&
                    env == TrustEnvironment.PRODUCTION
                return AnchorMatch(env, point.metadata, official, point.certificate)
            }
        }
        return null
    }

    /** A match through an enabled trust list: a PRODUCTION anchor that is not official (T2), tagged with the list. */
    private fun listMatch(role: TrustRole, chain: List<X509Cert>, atTime: Instant): AnchorMatch? {
        if (role !in PKIX_ROLES || policy.trustLists.isEmpty()) return null
        val found = trustLists.anchorOf(role, chain, atTime, policy.trustLists) ?: return null
        val s = found.service
        val name = listOfNotNull(s.name, s.provider?.takeIf { it != s.name }, s.country).joinToString("・")
        val metadata = TrustMetadata(
            displayName = name,
            extensions = buildMap {
                put(TrustMetadataKeys.ENVIRONMENT, TrustEnvironment.PRODUCTION.id)
                put(TrustMetadataKeys.OFFICIAL, "false")
                put(TrustMetadataKeys.SOURCE, found.kind.title)
                put(TrustMetadataKeys.LIST, found.kind.id)
                if (s.qualified) put(TrustMetadataKeys.QUALIFIED, "true")
            }
        )
        return AnchorMatch(TrustEnvironment.PRODUCTION, metadata, false, found.certificate)
    }

    /**
     * [chain] extended towards a root with the issuers its last certificate names in AIA caIssuers links (at most
     * [MAX_FETCHES] downloads); the chain itself when nothing was added. An added certificate must carry the issuer
     * name of the certificate below it, and its key identifier must match when both certificates state one; the
     * signatures are checked when the longer chain is evaluated.
     */
    suspend fun complete(chain: List<X509Cert>): List<X509Cert> {
        val fetcher = issuerFetcher ?: return chain
        if (chain.isEmpty()) return chain
        val out = chain.toMutableList()
        var downloads = 0
        while (out.size < MAX_CHAIN && downloads < MAX_FETCHES) {
            val last = out.last()
            if (last.subject == last.issuer) break
            val urls = runCatching { DocCrypto.caIssuerUrls(last.encoded.toByteArray()) }.getOrDefault(emptyList())
            var next: X509Cert? = null
            for (url in urls) {
                if (downloads >= MAX_FETCHES) break
                val known = fetched[url]
                val certs = known ?: run {
                    downloads++
                    val bytes = runCatching { fetcher(url) }.getOrNull()
                    val list = bytes?.let { b -> DocCrypto.certificatesIn(b).mapNotNull { runCatching { X509Cert(ByteString(it)) }.getOrNull() } }.orEmpty()
                    list.also { fetched[url] = it }
                }
                next = certs.firstOrNull { c -> c !in out && issues(c, last) }
                if (next != null) break
            }
            out.add(next ?: break)
        }
        return out
    }

    private fun issues(issuer: X509Cert, child: X509Cert): Boolean {
        if (issuer.subject != child.issuer) return false
        val aki = runCatching { child.authorityKeyIdentifier }.getOrNull()
        val ski = runCatching { issuer.subjectKeyIdentifier }.getOrNull()
        return aki == null || ski == null || aki.contentEquals(ski)
    }

    /**
     * Evaluates a chain whose signature binding has already been verified by the caller. A chain that leads to no
     * anchor is completed from AIA caIssuers links ([complete]) and evaluated once more. [docType] is the mdoc
     * document type the chain signs: an issuer CA from a VICAL is accepted only for the document types it lists.
     */
    suspend fun decide(
        role: TrustRole,
        chain: List<X509Cert>,
        atTime: Instant = Clock.System.now(),
        docType: String? = null,
    ): TrustDecision {
        var m = match(role, chain, atTime, docType)
        var completed = false
        if (m == null && issuerFetcher != null) {
            val longer = complete(extendFromPool(chain))
            if (longer.size > chain.size) {
                m = match(role, longer, atTime, docType)
                completed = m != null
            }
        }
        return decision(m, completed)
    }

    /**
     * The decision for a [match] result: what every component shows for a chain, so that a caller that needs the
     * anchor itself (to check a status list signed by it) still reports the same tier and labels as [decide].
     */
    fun decision(m: AnchorMatch?, completed: Boolean = false): TrustDecision {
        if (m == null) {
            return TrustDecision(
                tier = TrustTier.T3,
                environment = null,
                official = false,
                anchorName = null,
                labels = setOf(TrustLabel.UNKNOWN_ANCHOR),
                reasons = listOf("Certificate chain does not lead to an enabled trust anchor")
            )
        }
        // GPKI anchors are identity anchors: the tier is T2 as for any trust root, labelled as identity verified.
        val identity = m.environment == TrustEnvironment.PRODUCTION && m.metadata.extensions[TrustMetadataKeys.IDENTITY] == "true"
        val labels = buildSet {
            if (m.environment == TrustEnvironment.TEST) add(TrustLabel.TEST_ANCHOR)
            if (m.environment == TrustEnvironment.USER) add(TrustLabel.USER_ANCHOR)
            if (m.environment == TrustEnvironment.SYSTEM) add(TrustLabel.SYSTEM_ANCHOR)
            if (m.metadata.extensions[TrustMetadataKeys.REGION] == "CN") add(TrustLabel.MAINLAND_CHINA_CA)
            if (identity && !m.official) add(TrustLabel.IDENTITY_VERIFIED)
            when (m.metadata.extensions[TrustMetadataKeys.LIST]) {
                TrustListKind.AATL.id -> add(TrustLabel.AATL)
                TrustListKind.EUTL.id -> add(TrustLabel.EUTL)
            }
            if (m.metadata.extensions[TrustMetadataKeys.QUALIFIED] == "true") add(TrustLabel.EU_QUALIFIED)
        }
        return TrustDecision(
            tier = tierFor(m.environment, m.official, cryptographicallyVerified = true),
            environment = m.environment,
            official = m.official,
            anchorName = m.metadata.displayName,
            labels = labels,
            reasons = if (completed) listOf("Intermediate certificates were fetched from the AIA caIssuers link") else emptyList(),
        )
    }
}

/** An imported VICAL or RICAL. [expired] lists no longer take part in verification. */
data class StoredSignedList(
    val identifier: String,
    val kind: String,
    val environment: TrustEnvironment,
    val name: String,
    val provider: String,
    val source: String?,
    val issue: Long?,
    val notAfter: Instant?,
    val nextUpdate: Instant?,
    val certificates: Int,
    val expired: Boolean,
)

data class SignedListRefresh(val refreshed: Int, val failures: List<String>)

/** What the wallet reads from a signed VICAL or RICAL. */
private class SignedListInfo(
    val kind: String,
    val provider: String,
    val issue: Long?,
    val notAfter: Instant?,
    val nextUpdate: Instant?,
    val signer: List<X509Cert>,
    val certificates: Int,
) {
    val role: TrustRole get() = if (kind == "vical") TrustRole.ISSUER else TrustRole.VERIFIER

    fun sameKind(entry: org.multipaz.trustmanagement.TrustEntry): Boolean =
        if (kind == "vical") entry is TrustEntryVical else entry is TrustEntryRical

    companion object {
        suspend fun vical(bytes: ByteArray): SignedListInfo = SignedVical.parse(bytes).let {
            SignedListInfo("vical", it.vical.vicalProvider, it.vical.vicalIssueID, it.vical.notAfter, it.vical.nextUpdate,
                it.vicalProviderCertificateChain.certificates, it.vical.certificateInfos.size)
        }

        suspend fun rical(bytes: ByteArray): SignedListInfo = SignedRical.parse(bytes).let {
            SignedListInfo("rical", it.rical.provider, it.rical.id, it.rical.notAfter, it.rical.nextUpdate,
                it.ricalProviderCertificateChain.certificates, it.rical.certificateInfos.size)
        }

        suspend fun of(entry: org.multipaz.trustmanagement.TrustEntry): SignedListInfo? = when (entry) {
            is TrustEntryVical -> vical(entry.encodedSignedVical.toByteArray())
            is TrustEntryRical -> rical(entry.encodedSignedRical.toByteArray())
            else -> null
        }
    }
}

package diw.wallet.core.trust

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.Serializable
import org.multipaz.asn1.OID
import org.multipaz.crypto.X509Cert
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64
import kotlin.time.Instant

/** The public trust lists for document signatures and time stamps that the wallet can follow. */
enum class TrustListKind(val id: String, val title: String) {
    /** Adobe Approved Trust List: roots Acrobat trusts for document signatures and time stamps. */
    AATL("aatl", "Adobe 核可信任清單（AATL）"),

    /** The EU list of trusted lists (eIDAS): qualified CAs and time-stamp services of the member states. */
    EUTL("eutl", "歐盟信任清單（EUTL）"),
}

/** A period in which a listed service was granted (epoch seconds; [until] null while it still is). */
@Serializable
data class GrantedPeriod(val from: Long, val until: Long? = null) {
    fun contains(at: Long): Boolean = at >= from && (until == null || at < until)
}

/**
 * One trust service of a list: the certificate that anchors its chains, who runs it, the roles it is trusted for, and
 * when it was granted. [policies] are certificate policy OIDs one of which the chain must carry (AATL restrictions).
 */
@Serializable
data class ListedService(
    val certificate: String,
    val name: String,
    val provider: String? = null,
    val country: String? = null,
    val roles: Set<String>,
    val qualified: Boolean = false,
    val granted: List<GrantedPeriod> = emptyList(),
    val policies: List<String> = emptyList(),
) {
    val der: ByteArray get() = certificate.fromBase64()

    fun grantedAt(at: Long): Boolean = granted.isEmpty() || granted.any { it.contains(at) }
}

/**
 * One national list of the EUTL as fetched: its address, the cache validators for the next conditional download,
 * its services, and the signers the EU list named for it (to check a new version while the EU list is unchanged).
 */
@Serializable
data class TrustListPart(
    val territory: String,
    val url: String,
    val etag: String? = null,
    val lastModified: String? = null,
    val issued: Long? = null,
    val nextUpdate: Long? = null,
    val services: List<ListedService> = emptyList(),
    val error: String? = null,
    /** SHA-256 fingerprints of the certificates the EU list named for signing this list. */
    val signerPins: List<String> = emptyList(),
)

/**
 * A verified trust list as kept for offline use. [signerPins] are SHA-256 fingerprints (hex) of the certificates the
 * list announces for signing its next version (the EU list of trusted lists names its own signers).
 */
@Serializable
data class TrustListSnapshot(
    val kind: String,
    val fetchedAt: Long,
    val issued: Long? = null,
    val nextUpdate: Long? = null,
    val etag: String? = null,
    val lastModified: String? = null,
    val signer: String? = null,
    val signerPins: List<String> = emptyList(),
    val parts: List<TrustListPart> = emptyList(),
) {
    val listKind: TrustListKind? get() = TrustListKind.entries.firstOrNull { it.id == kind }
    val services: List<ListedService> get() = parts.flatMap { it.services }
    val errors: List<String> get() = parts.mapNotNull { p -> p.error?.let { "${p.territory}：$it" } }

    fun encode(): ByteArray = DiwJson.encodeToString(serializer(), this).encodeToByteArray()

    companion object {
        fun decode(bytes: ByteArray): TrustListSnapshot? =
            runCatching { DiwJson.decodeFromString(serializer(), bytes.decodeToString()) }.getOrNull()
    }
}

/**
 * The trust lists in use, indexed by certificate subject so that a chain is compared only with the services whose
 * certificate could have issued one of its certificates. Lists anchor document signatures and time stamps only.
 */
class TrustLists {
    private class Indexed(val kind: TrustListKind, val snapshot: TrustListSnapshot, val bySubject: Map<String, List<Pair<X509Cert, ListedService>>>)

    /** The anchor a chain led to and the service that listed it. */
    class Found(val kind: TrustListKind, val certificate: X509Cert, val service: ListedService)

    private var lists: Map<TrustListKind, Indexed> = emptyMap()

    val snapshots: List<TrustListSnapshot> get() = lists.values.map { it.snapshot }

    fun snapshot(kind: TrustListKind): TrustListSnapshot? = lists[kind]?.snapshot

    /** Puts [snapshot] in use in place of the list of the same kind. */
    fun install(snapshot: TrustListSnapshot) {
        val kind = snapshot.listKind ?: return
        val index = HashMap<String, MutableList<Pair<X509Cert, ListedService>>>()
        for (s in snapshot.services) {
            val cert = runCatching { X509Cert(ByteString(s.der)) }.getOrNull() ?: continue
            val subject = runCatching { cert.subject.name }.getOrNull() ?: continue
            index.getOrPut(subject) { ArrayList() }.add(cert to s)
        }
        lists = lists + (kind to Indexed(kind, snapshot, index))
    }

    fun remove(kind: TrustListKind) {
        lists = lists - kind
    }

    /**
     * The listed service [chain] (leaf first) validates to at [at] for [role], among the [enabled] lists: the service
     * must be listed for the role, granted at [at], and the chain must carry one of its required policies.
     */
    fun anchorOf(role: TrustRole, chain: List<X509Cert>, at: Instant, enabled: Set<TrustListKind>): Found? {
        if (chain.isEmpty()) return null
        val names = chain.flatMap { c -> listOfNotNull(runCatching { c.issuer.name }.getOrNull(), runCatching { c.subject.name }.getOrNull()) }.toSet()
        for (kind in TrustListKind.entries) {
            if (kind !in enabled) continue
            val list = lists[kind] ?: continue
            val candidates = names.flatMap { list.bySubject[it].orEmpty() }
                .filter { (_, s) -> role.id in s.roles && s.grantedAt(at.epochSeconds) }
            if (candidates.isEmpty()) continue
            val certs = candidates.map { it.first }.distinct()
            val anchor = runCatching { Pkix.anchorOf(chain, certs, at) }.getOrNull() ?: continue
            val service = candidates.filter { it.first == anchor }.map { it.second }
                .firstOrNull { s -> s.policies.isEmpty() || carriesPolicy(chain.takeWhile { it != anchor }, s.policies) } ?: continue
            return Found(kind, anchor, service)
        }
        return null
    }

    private fun carriesPolicy(path: List<X509Cert>, policies: List<String>): Boolean =
        path.any { c -> runCatching { DocCrypto.certificatePolicies(c.encoded.toByteArray()) }.getOrDefault(emptyList()).any { it in policies } }

    companion object {
        /** SHA-256 of [der] as lower-case hex, the form of [TrustListSnapshot.signerPins]. */
        fun pin(der: ByteArray): String = diw.wallet.core.document.DocCryptoUtil.hex(DocCrypto.digest("SHA-256", der))

        /** The common name of [c], or its whole subject. */
        fun nameOf(c: X509Cert): String = runCatching { c.subject.components[OID.COMMON_NAME.oid]?.value }.getOrNull() ?: c.subject.name

        fun encodeCertificate(der: ByteArray): String = der.toBase64()
    }
}

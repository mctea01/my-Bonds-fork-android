package diw.wallet.core.status

import diw.wallet.core.did.DidResolver
import diw.wallet.core.env.TrustEnvironment
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.oid4vci.X509CertChainCheck
import diw.wallet.core.trust.DidTrust
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.isAcceptableEndpoint
import diw.wallet.core.util.str
import diw.wallet.core.w3c.DataIntegrity
import diw.wallet.core.w3c.SdJwtDisclosures
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVc
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * One credentialStatus entry of a W3C credential: Bitstring Status List v1.0 (BitstringStatusListEntry),
 * Status List 2021 (StatusList2021Entry, used by TWDIW) or Revocation List 2020 (RevocationList2020Status).
 */
data class W3cStatusEntry(
    val type: String,
    /** statusPurpose as written by the issuer: revocation, suspension, message, ... */
    val purpose: String,
    val listUrl: String,
    val index: Long,
    /** Bits per entry (statusSize, 1 unless the issuer says otherwise). */
    val statusSize: Int,
    /** statusMessage values (status value to message) of message entries. */
    val messages: Map<Int, String>,
) {
    companion object {
        const val BITSTRING = "BitstringStatusListEntry"
        const val STATUS_LIST_2021 = "StatusList2021Entry"
        const val REVOCATION_LIST_2020 = "RevocationList2020Status"

        fun parse(o: JsonObject): W3cStatusEntry? {
            val types = when (val t = o["type"]) {
                is JsonPrimitive -> listOf(t.content)
                is JsonArray -> t.mapNotNull { (it as? JsonPrimitive)?.content }
                else -> emptyList()
            }
            val type = types.firstOrNull { it == BITSTRING || it == STATUS_LIST_2021 || it == REVOCATION_LIST_2020 } ?: return null
            val revocationList = type == REVOCATION_LIST_2020
            val url = o.str(if (revocationList) "revocationListCredential" else "statusListCredential") ?: return null
            val index = (o[if (revocationList) "revocationListIndex" else "statusListIndex"] as? JsonPrimitive)?.content?.trim()?.toLongOrNull()
                ?: return null
            if (index < 0) return null
            val size = (o["statusSize"] as? JsonPrimitive)?.content?.toIntOrNull() ?: 1
            if (size !in 1..8) return null
            val messages = (o["statusMessage"] as? JsonArray).orEmpty().filterIsInstance<JsonObject>().mapNotNull { m ->
                val v = m.str("status")?.removePrefix("0x")?.toIntOrNull(16) ?: return@mapNotNull null
                v to (m.str("message") ?: return@mapNotNull null)
            }.toMap()
            return W3cStatusEntry(type, if (revocationList) "revocation" else (o.str("statusPurpose") ?: "revocation"), url, index, size, messages)
        }

        fun parseAll(vc: JsonObject): List<W3cStatusEntry> = W3cVc.statusEntries(vc).mapNotNull { parse(it) }
    }
}

/** Status read for one entry, labelled with the specification's own terms (statusPurpose and status value). */
data class W3cEntryStatus(
    val entry: W3cStatusEntry,
    val value: Int?,
    val state: RevocationCheckState,
    val label: String,
    val trusted: Boolean,
    val detail: String?,
)

/**
 * Holder- and verifier-side checker for W3C status lists. The status list credential is fetched from the entry's
 * URL (a JWT, an SD-JWT, a JSON-LD credential, or a JSON wrapper holding one of these, as TWDIW serves it),
 * verified by x5c, the issuer DID or a Data Integrity proof, and must come from the credential's issuer. A list
 * whose key is only reachable through a jku header is read but reported as unverified, never trusted.
 */
class W3cStatusChecker(
    private val httpClient: HttpClient,
    private val trustRegistry: TrustRegistry,
    private val didTrust: DidTrust = DidTrust.NONE,
    private val maxCacheAge: Duration = 60.minutes,
) {
    private class StatusList(
        val bits: ByteArray,
        val issuer: String?,
        val purpose: String?,
        val verified: Boolean,
        val trusted: Boolean,
        val environment: TrustEnvironment?,
        val note: String?,
        val until: Instant,
    )

    private val cache = mutableMapOf<String, StatusList>()

    /** Combined status of all entries of [vc]; the most severe state wins. */
    suspend fun check(vc: JsonObject, issuer: String?, bypassCache: Boolean = false): CredentialStatus {
        val entries = W3cStatusEntry.parseAll(vc)
        if (entries.isEmpty()) {
            val detail = if (W3cVc.statusEntries(vc).isEmpty()) "Credential carries no status reference" else "Unsupported credentialStatus type"
            return CredentialStatus(RevocationCheckState.UNKNOWN, false, null, Clock.System.now(), detail)
        }
        val results = entries.map { checkEntry(it, issuer, bypassCache) }
        return combine(results)
    }

    suspend fun checkEntry(entry: W3cStatusEntry, issuer: String?, bypassCache: Boolean = false): W3cEntryStatus {
        val loopback = trustRegistry.policy.insecureLoopbackAllowed
        if (!isAcceptableEndpoint(entry.listUrl, loopback)) {
            return W3cEntryStatus(entry, null, RevocationCheckState.UNKNOWN, entry.purpose, false, "Status list URL is not https")
        }
        val now = Clock.System.now()
        val list = cache[entry.listUrl]?.takeIf { !bypassCache && it.until > now } ?: try {
            fetch(entry.listUrl).also { cache[entry.listUrl] = it }
        } catch (e: Exception) {
            return W3cEntryStatus(entry, null, RevocationCheckState.UNKNOWN, entry.purpose, false, e.message)
        }
        val notes = mutableListOf<String>()
        list.note?.let { notes += it }
        var trusted = list.trusted
        if (issuer != null && list.issuer != null && list.issuer != issuer) {
            trusted = false
            notes += "Status list issuer ${list.issuer} is not the credential issuer $issuer"
        }
        if (list.purpose != null && list.purpose != entry.purpose) {
            return W3cEntryStatus(entry, null, RevocationCheckState.UNKNOWN, entry.purpose, false,
                "Status list purpose ${list.purpose} does not match the entry purpose ${entry.purpose}")
        }
        val value = read(list.bits, entry.index, entry.statusSize)
            ?: return W3cEntryStatus(entry, null, RevocationCheckState.UNKNOWN, entry.purpose, false, "Index ${entry.index} outside the status list")
        val hex = "0x" + value.toString(16).uppercase()
        val state = when (entry.purpose) {
            "revocation" -> if (value == 0) RevocationCheckState.VALID else RevocationCheckState.INVALID
            "suspension" -> if (value == 0) RevocationCheckState.VALID else RevocationCheckState.SUSPENDED
            else -> RevocationCheckState.UNKNOWN
        }
        val label = entry.messages[value]?.let { "${entry.purpose} $hex ($it)" } ?: "${entry.purpose} $hex"
        return W3cEntryStatus(entry, value, state, label, trusted && list.verified, notes.joinToString("; ").ifEmpty { null })
    }

    private fun combine(results: List<W3cEntryStatus>): CredentialStatus {
        // revocation and suspension decide validity; message and other purposes are informational.
        val deciding = results.filter { it.entry.purpose == "revocation" || it.entry.purpose == "suspension" }
        val state = when {
            deciding.any { it.state == RevocationCheckState.INVALID } -> RevocationCheckState.INVALID
            deciding.any { it.state == RevocationCheckState.SUSPENDED } -> RevocationCheckState.SUSPENDED
            deciding.isEmpty() || deciding.any { it.state == RevocationCheckState.UNKNOWN } -> RevocationCheckState.UNKNOWN
            else -> RevocationCheckState.VALID
        }
        val first = results.first()
        return CredentialStatus(
            state = state,
            trusted = results.all { it.trusted },
            environment = null,
            checkedAt = Clock.System.now(),
            detail = results.mapNotNull { it.detail }.distinct().joinToString("; ").ifEmpty { null },
            code = first.value,
            uri = first.entry.listUrl,
            index = first.entry.index.toInt(),
            list = null,
            label = results.joinToString(", ") { it.label },
            w3cEntries = results,
        )
    }

    private suspend fun fetch(url: String): StatusList {
        val resp = httpClient.get(url) { header(HttpHeaders.Accept, "application/vc+jwt, application/vc+ld+json, application/json, application/jwt") }
        if (!resp.status.isSuccess()) error("Status list fetch returned ${resp.status.value}")
        val content = unwrap(resp.bodyAsText().trim())
        return if (content.startsWith("{")) jsonLdList(content) else jwtList(content)
    }

    /** The status list credential inside [body]: the body itself, or a JSON wrapper's statusList / credential / vc member. */
    private fun unwrap(body: String): String {
        if (!body.startsWith("{")) return body.removeSurrounding("\"")
        val o = runCatching { DiwJson.parseToJsonElement(body) as JsonObject }.getOrNull() ?: return body
        if (o["@context"] != null || o["proof"] != null) return body
        for (name in listOf("statusList", "statusListCredential", "credential", "vc", "jwt", "data")) {
            when (val v = o[name]) {
                is JsonPrimitive -> if (v.isString) return v.content.trim()
                is JsonObject -> return v.toString()
                else -> {}
            }
        }
        return body
    }

    private suspend fun jwtList(compact: String): StatusList {
        val parts = if ('~' in compact) SdJwtDisclosures.parse(compact) else null
        val jws = Jws.parse(parts?.issuerJwt ?: compact)
        val payload = if (parts != null) SdJwtDisclosures.resolve(jws.payload, parts.disclosures) else jws.payload
        val vc = (payload["vc"] as? JsonObject) ?: payload
        val iss = payload.str("iss") ?: W3cVc.issuer(vc, null)
        val chain = jws.x5c?.certificates
        var trusted = false
        var env: TrustEnvironment? = null
        var note: String? = null
        val verified = when {
            chain != null -> {
                X509CertChainCheck.validate(chain)
                jws.verify(VerificationKey.fromCertificate(chain.first()))
                val m = trustRegistry.match(TrustRole.STATUS_LIST, chain) ?: trustRegistry.match(TrustRole.ISSUER, chain)
                if (m != null) { trusted = true; env = m.environment } else note = "Status list signer does not chain to an enabled anchor"
                true
            }
            iss != null && iss.startsWith("did:") -> {
                val method = DidResolver(httpClient, trustRegistry.policy.insecureLoopbackAllowed)
                    .resolveKey(iss, jws.kid?.takeIf { it.startsWith("did:") || it.startsWith("#") })
                jws.verify(method.key)
                val decision = didTrust.decide(iss, TrustRole.ISSUER)
                env = decision?.environment
                // Signed by the issuer DID: as trustworthy as the credential itself.
                trusted = true
                true
            }
            jws.header["jku"] != null -> {
                note = "unverified: the status list key is only published through jku, which is not followed"
                false
            }
            else -> {
                note = "unverified: no way to find the status list signing key"
                false
            }
        }
        val subject = subjectOf(vc)
        val ttl = (subject["ttl"] as? JsonPrimitive)?.longOrNull?.milliseconds
        val exp = (payload["exp"] as? JsonPrimitive)?.longOrNull?.let { Instant.fromEpochSeconds(it) }
            ?: W3cVc.validity(vc, payload).second
        exp?.let { if (it < Clock.System.now()) error("Status list credential expired") }
        return StatusList(
            bits = decodeList(subject),
            issuer = iss,
            purpose = subject.str("statusPurpose"),
            verified = verified,
            trusted = trusted,
            environment = env,
            note = note,
            until = cacheUntil(ttl, exp),
        )
    }

    private suspend fun jsonLdList(json: String): StatusList {
        val doc = DiwJson.parseToJsonElement(json) as JsonObject
        val issuer = W3cVc.issuer(doc, null)
        val loopback = trustRegistry.policy.insecureLoopbackAllowed
        val (verified, note) = try {
            val proof = DataIntegrity(DidResolver(httpClient, loopback)).verify(doc, expectedPurpose = "assertionMethod")
            if (issuer != null && proof.verificationMethod.substringBefore('#') != issuer) false to "unverified: proof key does not belong to $issuer"
            else true to null
        } catch (e: Exception) {
            false to "unverified: ${e.message}"
        }
        val subject = subjectOf(doc)
        val (_, until) = W3cVc.validity(doc, null)
        until?.let { if (it < Clock.System.now()) error("Status list credential expired") }
        val env = issuer?.takeIf { it.startsWith("did:") }?.let { didTrust.decide(it, TrustRole.ISSUER)?.environment }
        return StatusList(
            bits = decodeList(subject),
            issuer = issuer,
            purpose = subject.str("statusPurpose"),
            verified = verified,
            trusted = verified,
            environment = env,
            note = note,
            until = cacheUntil((subject["ttl"] as? JsonPrimitive)?.longOrNull?.milliseconds, until),
        )
    }

    private fun cacheUntil(ttl: Duration?, exp: Instant?): Instant {
        val now = Clock.System.now()
        var until = now + maxCacheAge
        ttl?.let { if (now + it < until) until = now + it }
        exp?.let { if (it < until) until = it }
        return until
    }

    companion object {
        private fun subjectOf(vc: JsonObject): JsonObject = when (val s = vc["credentialSubject"]) {
            is JsonObject -> s
            is JsonArray -> s.filterIsInstance<JsonObject>().firstOrNull { it["encodedList"] != null }
            else -> null
        } ?: error("Status list credential has no credentialSubject")

        /**
         * Bitstring of a status list credentialSubject. encodedList is GZIP compressed and base64url encoded,
         * with the multibase 'u' prefix in Bitstring Status List and without it in Status List 2021 /
         * Revocation List 2020 (some issuers use padded or standard base64).
         */
        fun decodeList(subject: JsonObject): ByteArray {
            val encoded = subject.str("encodedList") ?: error("Status list credential has no encodedList")
            val candidates = buildList {
                if (encoded.startsWith("u")) add(encoded.substring(1))
                add(encoded)
            }
            for (c in candidates) {
                val bytes = decodeBase64Any(c) ?: continue
                if (bytes.size >= 2 && bytes[0] == 0x1f.toByte() && bytes[1] == 0x8b.toByte()) {
                    return PlatformCrypto.gunzip(bytes)
                }
            }
            error("encodedList is not a GZIP compressed base64 bitstring")
        }

        private fun decodeBase64Any(s: String): ByteArray? {
            val t = s.trim()
            return runCatching { t.trimEnd('=').fromBase64Url() }.getOrNull()
                ?: runCatching { t.fromBase64() }.getOrNull()
        }

        /** Value at [index] with [size] bits per entry; index 0 is the left-most (most significant) bit of the first byte. */
        fun read(bits: ByteArray, index: Long, size: Int): Int? {
            val start = index * size
            if (start < 0 || start + size > bits.size.toLong() * 8) return null
            var v = 0
            for (i in 0 until size) {
                val pos = start + i
                val bit = (bits[(pos / 8).toInt()].toInt() shr (7 - (pos % 8).toInt())) and 1
                v = (v shl 1) or bit
            }
            return v
        }
    }
}

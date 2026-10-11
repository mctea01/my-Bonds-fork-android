package diw.wallet.core.did

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import kotlinx.serialization.json.JsonObject
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.EcPublicKeyOkp
import org.multipaz.util.fromBase64Url

/** A resolved DID verification method. */
data class DidVerificationMethod(val id: String, val key: VerificationKey, val jwk: JsonObject?)

/** Minimal DID document view: verification methods plus the methods allowed for assertions/authentication. */
data class DidService(val id: String, val type: String, val endpoints: List<String>)

data class DidDocument(
    val id: String,
    val methods: List<DidVerificationMethod>,
    val assertionMethodIds: Set<String>,
    val authenticationIds: Set<String>,
    val services: List<DidService> = emptyList(),
) {
    fun find(kidOrFragment: String): DidVerificationMethod? {
        val absolute = if (kidOrFragment.startsWith("#")) id + kidOrFragment else kidOrFragment
        return methods.firstOrNull { it.id == absolute } ?: methods.firstOrNull { it.id.endsWith(kidOrFragment) }
    }
}

/**
 * Resolves did:jwk, did:key (P-256, P-384, Ed25519, jwk_jcs-pub 0xEB51) and did:web.
 * did:web is fetched over HTTPS; loopback HTTP is allowed only when [allowInsecureLoopback] is set.
 */
class DidResolver(
    private val httpClient: HttpClient,
    private val allowInsecureLoopback: Boolean = false,
    private val ionResolver: String = "https://discover.did.msidentity.com/v1.0/identifiers/",
) {
    suspend fun resolve(did: String): DidDocument {
        val base = did.substringBefore('#')
        return when {
            base.startsWith("did:jwk:") -> resolveJwk(base)
            base.startsWith("did:key:") -> resolveKey(base)
            base.startsWith("did:web:") -> resolveWeb(base)
            base.startsWith("did:ion:") -> resolveIon(base)
            else -> throw ProtocolException("unsupported_did", "Unsupported DID method in '$base'")
        }
    }

    /** Resolves the verification key referenced by a JWS kid (absolute DID URL or fragment relative to [did]). */
    suspend fun resolveKey(did: String, kid: String?): DidVerificationMethod {
        val doc = resolve(did)
        val ref = kid ?: (doc.methods.singleOrNull()?.id ?: throw ProtocolException("invalid_request", "kid required for multi-key DID"))
        if (kid != null && kid.contains('#') && !kid.startsWith("#") && kid.substringBefore('#') != doc.id) {
            throw ProtocolException("invalid_request", "kid '$kid' does not belong to $did")
        }
        return doc.find(ref) ?: throw ProtocolException("invalid_request", "Verification method '$ref' not found in $did")
    }

    private fun resolveJwk(did: String): DidDocument {
        val jwk = DiwJson.parseToJsonElement(did.removePrefix("did:jwk:").fromBase64Url().decodeToString()) as JsonObject
        val vm = DidVerificationMethod("$did#0", VerificationKey.fromJwk(jwk), jwk)
        return DidDocument(did, listOf(vm), setOf(vm.id), setOf(vm.id))
    }

    private fun resolveKey(did: String): DidDocument {
        val mb = did.removePrefix("did:key:")
        if (!mb.startsWith("z")) throw ProtocolException("unsupported_did", "did:key must use base58btc multibase")
        val raw = Base58.decode(mb.substring(1))
        val (codec, offset) = readVarint(raw)
        val keyBytes = raw.copyOfRange(offset, raw.size)
        val (key, jwk) = when (codec) {
            0x1200L -> VerificationKey.Ec(
                EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(EcCurve.P256, PlatformCrypto.decompressEcPoint("secp256r1", keyBytes))
            ) to null
            0x1201L -> VerificationKey.Ec(
                EcPublicKeyDoubleCoordinate.fromUncompressedPointEncoding(EcCurve.P384, PlatformCrypto.decompressEcPoint("secp384r1", keyBytes))
            ) to null
            0xedL -> VerificationKey.Ec(EcPublicKeyOkp(EcCurve.ED25519, keyBytes)) to null
            0xeb51L -> {
                val jwk = DiwJson.parseToJsonElement(keyBytes.decodeToString()) as JsonObject
                VerificationKey.fromJwk(jwk) to jwk
            }
            else -> throw ProtocolException("unsupported_did", "did:key multicodec 0x${codec.toString(16)} not supported")
        }
        val vm = DidVerificationMethod("$did#$mb", key, jwk)
        return DidDocument(did, listOf(vm), setOf(vm.id), setOf(vm.id))
    }

    private suspend fun resolveWeb(did: String): DidDocument {
        val parts = did.removePrefix("did:web:").split(':').map { decodePercent(it) }
        val host = parts.first()
        val scheme = if (allowInsecureLoopback && (host.startsWith("localhost") || host.startsWith("127.0.0.1"))) "http" else "https"
        val url = if (parts.size == 1) "$scheme://$host/.well-known/did.json"
        else "$scheme://$host/" + parts.drop(1).joinToString("/") + "/did.json"
        val resp = httpClient.get(url)
        if (!resp.status.isSuccess()) throw ProtocolException("did_resolution_failed", "did:web fetch $url -> ${resp.status}")
        val doc = DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject
        if (doc.str("id") != did) throw ProtocolException("did_resolution_failed", "did:web document id mismatch")
        return parseDocument(did, doc)
    }

    /**
     * did:ion (Microsoft Entra Verified ID): resolved through Microsoft's public DID resolver, the resolver the
     * Microsoft wallet uses. The result is as trustworthy as that service and TLS.
     */
    private suspend fun resolveIon(did: String): DidDocument {
        val resp = httpClient.get(ionResolver + did.encodeURLPathPart())
        if (!resp.status.isSuccess()) throw ProtocolException("did_resolution_failed", "did:ion resolution returned ${resp.status}")
        val body = DiwJson.parseToJsonElement(resp.bodyAsText()) as JsonObject
        val doc = body.obj("didDocument") ?: body
        val id = doc.str("id") ?: did
        if (id != did && !did.startsWith("$id:") && !id.startsWith(did.substringBefore('?'))) {
            throw ProtocolException("did_resolution_failed", "did:ion document id mismatch")
        }
        return parseDocument(did, doc)
    }

    /** Verification methods and relationships of a DID document (JSON-LD or plain JSON). */
    fun parseDocument(did: String, doc: JsonObject): DidDocument {
        val methods = (doc.arr("verificationMethod") ?: emptyList()).mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            val id = o.str("id") ?: return@mapNotNull null
            val absolute = if (id.startsWith("#")) did + id else id
            if (o.str("type") == "EcdsaSecp256k1VerificationKey2019" && o["publicKeyJwk"] == null && o.str("publicKeyMultibase") == null) return@mapNotNull null
            val jwk = o["publicKeyJwk"] as? JsonObject
            val key = when {
                jwk != null -> VerificationKey.fromJwk(jwk)
                o.str("publicKeyMultibase") != null -> resolveKey("did:key:" + o.str("publicKeyMultibase")).methods.first().key
                else -> return@mapNotNull null
            }
            DidVerificationMethod(absolute, key, jwk)
        }
        fun refs(name: String): Set<String> = (doc.arr(name) ?: emptyList()).mapNotNull {
            val r = (it as? kotlinx.serialization.json.JsonPrimitive)?.content ?: (it as? JsonObject)?.str("id")
            r?.let { x -> if (x.startsWith("#")) did + x else x }
        }.toSet()
        val services = (doc.arr("service") ?: emptyList()).mapNotNull { e ->
            val o = e as? JsonObject ?: return@mapNotNull null
            val endpoints = when (val ep = o["serviceEndpoint"]) {
                is kotlinx.serialization.json.JsonPrimitive -> listOf(ep.content)
                is kotlinx.serialization.json.JsonArray -> ep.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                // LinkedDomains lists origins; Microsoft's IdentityHub lists instances.
                is JsonObject -> listOf("origins", "instances").flatMap { k ->
                    (ep[k] as? kotlinx.serialization.json.JsonArray)?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }.orEmpty()
                }
                else -> emptyList()
            }
            DidService(o.str("id") ?: "", o.str("type") ?: "", endpoints)
        }
        return DidDocument(did, methods, refs("assertionMethod"), refs("authentication"), services)
    }

    private fun decodePercent(s: String): String = s.replace("%3A", ":").replace("%3a", ":")

    private fun readVarint(b: ByteArray): Pair<Long, Int> {
        var value = 0L
        var shift = 0
        var i = 0
        while (i < b.size) {
            val byte = b[i].toInt() and 0xff
            value = value or ((byte and 0x7f).toLong() shl shift)
            i++
            if (byte and 0x80 == 0) return value to i
            shift += 7
        }
        throw ProtocolException("invalid_did", "Truncated multicodec varint")
    }
}

/** Bitcoin base58 alphabet decoder used by did:key. */
object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    fun decode(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        val zeros = input.takeWhile { it == '1' }.length
        val b256 = IntArray(input.length * 733 / 1000 + 1)
        var length = 0
        for (c in input) {
            var carry = ALPHABET.indexOf(c)
            if (carry < 0) throw ProtocolException("invalid_did", "Invalid base58 character '$c'")
            var i = 0
            var k = b256.size - 1
            while ((carry != 0 || i < length) && k >= 0) {
                carry += 58 * b256[k]
                b256[k] = carry % 256
                carry /= 256
                k--
                i++
            }
            length = i
        }
        var start = b256.size - length
        while (start < b256.size && b256[start] == 0) start++
        return ByteArray(zeros) + ByteArray(b256.size - start) { b256[start + it].toByte() }
    }

    fun encode(input: ByteArray): String {
        if (input.isEmpty()) return ""
        val digits = mutableListOf<Int>()
        for (b in input) {
            var carry = b.toInt() and 0xff
            for (j in digits.indices) {
                carry += digits[j] shl 8
                digits[j] = carry % 58
                carry /= 58
            }
            while (carry > 0) {
                digits.add(carry % 58)
                carry /= 58
            }
        }
        val sb = StringBuilder()
        input.takeWhile { it == 0.toByte() }.forEach { _ -> sb.append('1') }
        for (d in digits.reversed()) sb.append(ALPHABET[d])
        return sb.toString()
    }
}

package diw.wallet.core.jose

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcSignature
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/** A public key usable for JWS verification: EC/OKP via Multipaz, RSA via the platform. */
sealed class VerificationKey {
    data class Ec(val key: EcPublicKey) : VerificationKey()
    data class Rsa(val modulus: ByteArray, val exponent: ByteArray) : VerificationKey() {
        override fun equals(other: Any?) = other is Rsa && modulus.contentEquals(other.modulus) && exponent.contentEquals(other.exponent)
        override fun hashCode() = modulus.contentHashCode() * 31 + exponent.contentHashCode()
    }

    companion object {
        fun fromJwk(jwk: JsonObject): VerificationKey = when (jwk.str("kty")) {
            "EC", "OKP" -> Ec(EcPublicKey.fromJwk(jwk))
            "RSA" -> Rsa(
                modulus = (jwk.str("n") ?: throw ProtocolException("invalid_key", "RSA JWK without n")).fromBase64Url(),
                exponent = (jwk.str("e") ?: throw ProtocolException("invalid_key", "RSA JWK without e")).fromBase64Url(),
            )
            else -> throw ProtocolException("invalid_key", "Unsupported JWK kty '${jwk.str("kty")}'")
        }

        fun fromCertificate(cert: X509Cert): VerificationKey = try {
            Ec(cert.ecPublicKey)
        } catch (_: Exception) {
            PlatformCrypto.rsaPublicKeyFromCertificate(cert.encoded.toByteArray())
                ?: throw ProtocolException("invalid_key", "Unsupported certificate public key type")
        }
    }
}

/** Platform crypto that Multipaz common code does not offer (RSA, PKIX helpers). */
expect object PlatformCrypto {
    fun rsaPublicKeyFromCertificate(der: ByteArray): VerificationKey.Rsa?
    fun verifyRsa(alg: String, key: VerificationKey.Rsa, data: ByteArray, signature: ByteArray): Boolean
    fun sha256(data: ByteArray): ByteArray
    fun randomBytes(size: Int): ByteArray
    /** Decompresses a SEC1 compressed point for a named curve (secp256r1, secp384r1, secp521r1, secp256k1). */
    fun decompressEcPoint(curveName: String, compressed: ByteArray): ByteArray
}

/** A parsed compact JWS. */
class Jws private constructor(
    val compact: String,
    val header: JsonObject,
    val payloadBytes: ByteArray,
    val signingInput: ByteArray,
    val signature: ByteArray,
) {
    val alg: String get() = header.str("alg") ?: throw ProtocolException("invalid_request", "JWS without alg")
    val typ: String? get() = header.str("typ")
    val kid: String? get() = header.str("kid")

    val payload: JsonObject by lazy {
        try {
            DiwJson.parseToJsonElement(payloadBytes.decodeToString()) as JsonObject
        } catch (e: Exception) {
            throw ProtocolException("invalid_request", "JWS payload is not a JSON object", e)
        }
    }

    val x5c: X509CertChain? by lazy {
        (header["x5c"] as? JsonArray)?.let { X509CertChain.fromX5c(it) }
    }

    val jwk: JsonObject? get() = header["jwk"] as? JsonObject

    suspend fun verify(key: VerificationKey) {
        if (!verifySignature(alg, key, signingInput, signature)) {
            throw ProtocolException("invalid_signature", "JWS signature verification failed (alg=$alg)")
        }
    }

    companion object {
        fun parse(compact: String): Jws {
            val parts = compact.trim().split('.')
            if (parts.size != 3) throw ProtocolException("invalid_request", "Not a compact JWS (${parts.size} parts)")
            val header = try {
                DiwJson.parseToJsonElement(parts[0].fromBase64Url().decodeToString()) as JsonObject
            } catch (e: Exception) {
                throw ProtocolException("invalid_request", "Malformed JWS header", e)
            }
            if (header.str("alg") == "none") throw ProtocolException("invalid_request", "alg=none is not accepted")
            return Jws(
                compact = compact.trim(),
                header = header,
                payloadBytes = parts[1].fromBase64Url(),
                signingInput = "${parts[0]}.${parts[1]}".encodeToByteArray(),
                signature = parts[2].fromBase64Url(),
            )
        }

        /** Parses an unverified JWT payload (used where the signature is checked by another layer). */
        fun unverifiedPayload(compact: String): JsonObject = parse(compact).payload
    }
}

/** Maps a JOSE alg to a Multipaz algorithm for EC/OKP keys. */
fun ecAlgorithmFor(alg: String): Algorithm = when (alg) {
    "ES256", "ESP256" -> Algorithm.ES256
    "ES384", "ESP384" -> Algorithm.ES384
    "ES512", "ESP512" -> Algorithm.ES512
    "EdDSA" -> Algorithm.EDDSA
    "Ed25519" -> Algorithm.ED25519
    "Ed448" -> Algorithm.ED448
    "ESB256" -> Algorithm.ESB256
    "ESB320" -> Algorithm.ESB320
    "ESB384" -> Algorithm.ESB384
    "ESB512" -> Algorithm.ESB512
    "ES256K" -> throw ProtocolException("unsupported_alg", "ES256K requires the secp256k1 profile")
    else -> try {
        Algorithm.fromJoseAlgorithmIdentifier(alg)
    } catch (e: Exception) {
        throw ProtocolException("unsupported_alg", "Unsupported JWS alg '$alg'", e)
    }
}

suspend fun verifySignature(alg: String, key: VerificationKey, data: ByteArray, signature: ByteArray): Boolean = when (key) {
    is VerificationKey.Rsa -> {
        if (!alg.startsWith("RS") && !alg.startsWith("PS")) false
        else PlatformCrypto.verifyRsa(alg, key, data, signature)
    }
    is VerificationKey.Ec -> try {
        val algorithm = ecAlgorithmFor(alg)
        Crypto.checkSignature(key.key, data, algorithm, EcSignature.fromCoseEncoded(signature))
        true
    } catch (e: ProtocolException) {
        throw e
    } catch (_: Exception) {
        false
    }
}

/** RFC 7638 JWK thumbprint (SHA-256, base64url) for EC, OKP and RSA keys. */
fun jwkThumbprint(jwk: JsonObject): String {
    val canonical = when (jwk.str("kty")) {
        "EC" -> buildJsonObject {
            put("crv", jwk.str("crv")); put("kty", "EC"); put("x", jwk.str("x")); put("y", jwk.str("y"))
        }
        "OKP" -> buildJsonObject { put("crv", jwk.str("crv")); put("kty", "OKP"); put("x", jwk.str("x")) }
        "RSA" -> buildJsonObject { put("e", jwk.str("e")); put("kty", "RSA"); put("n", jwk.str("n")) }
        else -> throw ProtocolException("invalid_key", "Unsupported kty for thumbprint")
    }
    return PlatformCrypto.sha256(canonical.toString().encodeToByteArray()).toBase64Url()
}

/** Strips private members from a JWK. */
fun publicJwk(jwk: JsonObject): JsonObject = JsonObject(jwk.filterKeys { it !in setOf("d", "p", "q", "dp", "dq", "qi", "k") })

fun JsonPrimitive.contentOrNull(): String? = if (isString) content else null

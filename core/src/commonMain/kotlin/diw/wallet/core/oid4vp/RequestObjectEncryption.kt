package diw.wallet.core.oid4vp

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.SecretKey
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/**
 * A wallet-controlled key that a Verifier may encrypt a Request Object to (JAR, RFC 9101 section 4). The public half
 * is registered with the Verifier through wallet_metadata.jwks under request_uri_method=post (OpenID4VP 1.0 section
 * 5.10). The private half never leaves the wallet.
 */
class RequestDecryptionKey(val kid: String?, val key: AsymmetricKey) {
    /** The public JWK as it goes into wallet_metadata.jwks. */
    suspend fun publicJwk(): JsonObject = key.publicKey.toJwk(buildJsonObject {
        kid?.let { put("kid", it) }
        put("use", "enc")
        put("alg", RequestObjectEncryption.ALG)
    })

    companion object {
        /** A fresh P-256 key for one request_uri retrieval; it is not reused, so it cannot link requests. */
        suspend fun ephemeral(): RequestDecryptionKey {
            val private = Crypto.createEcPrivateKey(EcCurve.P256)
            return RequestDecryptionKey(
                PlatformCrypto.randomBytes(12).toBase64Url(),
                AsymmetricKey.anonymous(private, private.curve.defaultKeyAgreementAlgorithm),
            )
        }
    }
}

/** The content of a decrypted Request Object: claims of an unsigned JWT, or the compact JWS of a Nested JWT. */
sealed class DecryptedRequestObject {
    data class Claims(val claims: JsonObject) : DecryptedRequestObject()
    data class Signed(val compactJws: String) : DecryptedRequestObject()
}

/**
 * Compact JWE with direct key agreement (alg ECDH-ES, RFC 7518 section 4.6) and AES-GCM content encryption, for
 * Request Objects. Unlike Multipaz JsonWebEncryption the payload may be a Nested JWT (sign then encrypt, RFC 7519
 * section 11.2), which JAR requires when a Request Object is both signed and encrypted.
 */
object RequestObjectEncryption {
    const val ALG = "ECDH-ES"
    val ENC_VALUES = listOf("A128GCM", "A192GCM", "A256GCM")

    /** Request object encryption parameters of wallet_metadata (named as in OpenID Connect Discovery 1.0). */
    suspend fun metadata(keys: List<RequestDecryptionKey>): JsonObject {
        val jwks = keys.map { it.publicJwk() }
        return buildJsonObject {
        put("jwks", buildJsonObject { put("keys", JsonArray(jwks)) })
        putJsonArray("request_object_encryption_alg_values_supported") { add(ALG) }
        putJsonArray("request_object_encryption_enc_values_supported") { ENC_VALUES.forEach { add(it) } }
        }
    }

    /** True for the five-part compact serialization of a JWE. */
    fun isCompactJwe(value: String): Boolean = value.count { it == '.' } == 4

    /**
     * Encrypts [plaintext] to [recipient] (a Verifier using wallet_metadata.jwks). [contentType] is "JWT" for a
     * signed Request Object (Nested JWT) and null for an unsigned claims set.
     */
    suspend fun encrypt(
        plaintext: ByteArray,
        recipient: EcPublicKey,
        enc: String = "A256GCM",
        kid: String? = null,
        contentType: String? = null,
    ): String {
        val encAlg = encAlgorithm(enc)
        val ephemeral = Crypto.createEcPrivateKey(recipient.curve)
        val apu = PlatformCrypto.randomBytes(16)
        val header = buildJsonObject {
            put("alg", ALG)
            put("enc", enc)
            kid?.let { put("kid", it) }
            contentType?.let { put("cty", it) }
            put("epk", ephemeral.publicKey.toJwk())
            put("apu", apu.toBase64Url())
        }
        val headerB64 = header.toString().encodeToByteArray().toBase64Url()
        val shared = Crypto.keyAgreement(ephemeral, recipient)
        val cek = try {
            concatKdf(shared.toByteArray(), enc, apu, ByteArray(0))
        } finally {
            shared.close()
        }
        val iv = PlatformCrypto.randomBytes(12)
        val sealed = try {
            Crypto.encrypt(algorithm = encAlg, key = cek, nonce = iv, messagePlaintext = plaintext, aad = headerB64.encodeToByteArray())
        } finally {
            cek.close()
        }
        val ciphertext = sealed.copyOfRange(0, sealed.size - TAG_BYTES)
        val tag = sealed.copyOfRange(sealed.size - TAG_BYTES, sealed.size)
        return headerB64 + ".." + iv.toBase64Url() + "." + ciphertext.toBase64Url() + "." + tag.toBase64Url()
    }

    /** Encrypts a signed Request Object (compact JWS) as a Nested JWT. */
    suspend fun encryptSigned(compactJws: String, recipientJwk: JsonObject, enc: String = "A256GCM"): String =
        encrypt(compactJws.encodeToByteArray(), EcPublicKey.fromJwk(recipientJwk), enc, recipientJwk.str("kid"), "JWT")

    /**
     * The first usable encryption key in a wallet_metadata [walletMetadata]: an EC JWK for ECDH-ES ("use" and "alg"
     * may be absent, but must not say otherwise), or null when the wallet registered none.
     */
    fun recipientKey(walletMetadata: JsonObject?): JsonObject? {
        val keys = ((walletMetadata?.get("jwks") as? JsonObject)?.get("keys") as? JsonArray) ?: return null
        return keys.filterIsInstance<JsonObject>().firstOrNull { jwk ->
            jwk.str("kty") == "EC" && jwk.str("crv") in setOf("P-256", "P-384", "P-521") &&
                (jwk.str("use") ?: "enc") == "enc" && (jwk.str("alg") ?: ALG) == ALG && "d" !in jwk
        }
    }

    /**
     * Decrypts [compact] with a wallet-controlled [key]. A kid in the JWE header must name the key when the key has
     * one. Compression (zip), critical headers, key wrapping and other algorithms are refused.
     */
    suspend fun decrypt(compact: String, key: AsymmetricKey, kid: String? = null): DecryptedRequestObject {
        val parts = compact.split('.')
        require(parts.size == 5) { "Not a compact JWE" }
        val (headerB64, encryptedKey, ivB64, ciphertextB64, tagB64) = parts
        val header = DiwJson.parseToJsonElement(headerB64.fromBase64Url().decodeToString()) as? JsonObject
            ?: throw IllegalArgumentException("JWE header is not a JSON object")
        require(header.str("alg") == ALG) { "Unsupported JWE alg ${header.str("alg")}" }
        val enc = header.str("enc") ?: throw IllegalArgumentException("JWE enc is missing")
        val encAlg = encAlgorithm(enc)
        require(encryptedKey.isEmpty()) { "ECDH-ES must not carry an encrypted key" }
        require("zip" !in header) { "Compressed request objects are not accepted" }
        require("crit" !in header) { "Critical JWE header parameters are not supported" }
        val headerKid = header.str("kid")
        if (kid != null && headerKid != null) require(headerKid == kid) { "JWE kid names another key" }
        val epkJwk = header["epk"] as? JsonObject ?: throw IllegalArgumentException("JWE epk is missing")
        require("d" !in epkJwk) { "JWE epk must be a public key" }
        val epk = EcPublicKey.fromJwk(epkJwk)
        val apu = header.str("apu")?.fromBase64Url() ?: ByteArray(0)
        val apv = header.str("apv")?.fromBase64Url() ?: ByteArray(0)
        val iv = ivB64.fromBase64Url()
        val tag = tagB64.fromBase64Url()
        require(iv.size == 12 && tag.size == TAG_BYTES) { "Unexpected AES-GCM IV or tag length" }
        val shared = key.keyAgreement(epk)
        val cek = try {
            concatKdf(shared.toByteArray(), enc, apu, apv)
        } finally {
            shared.close()
        }
        val plaintext = try {
            Crypto.decrypt(algorithm = encAlg, key = cek, nonce = iv, messageCiphertext = ciphertextB64.fromBase64Url() + tag, aad = headerB64.encodeToByteArray())
        } finally {
            cek.close()
        }
        val text = plaintext.decodeToString().trim()
        val cty = header.str("cty")
        return when {
            text.startsWith("{") && cty == null -> DecryptedRequestObject.Claims(
                DiwJson.parseToJsonElement(text) as? JsonObject ?: throw IllegalArgumentException("Payload is not a JSON object")
            )
            text.count { it == '.' } == 2 -> DecryptedRequestObject.Signed(text)
            else -> throw IllegalArgumentException("Encrypted payload is neither a claims set nor a signed JWT")
        }
    }

    private const val TAG_BYTES = 16

    private fun encAlgorithm(enc: String): Algorithm = when (enc) {
        "A128GCM" -> Algorithm.A128GCM
        "A192GCM" -> Algorithm.A192GCM
        "A256GCM" -> Algorithm.A256GCM
        else -> throw IllegalArgumentException("Unsupported JWE enc $enc")
    }

    private fun keyBits(enc: String): Int = when (enc) {
        "A128GCM" -> 128
        "A192GCM" -> 192
        "A256GCM" -> 256
        else -> throw IllegalArgumentException("Unsupported JWE enc $enc")
    }

    /** Concat KDF of RFC 7518 section 4.6.2 with SHA-256; AlgorithmID is the enc value for direct key agreement. */
    private suspend fun concatKdf(z: ByteArray, enc: String, apu: ByteArray, apv: ByteArray): SecretKey {
        val bits = keyBits(enc)
        val algId = enc.encodeToByteArray()
        val otherInfo = lengthPrefixed(algId) + lengthPrefixed(apu) + lengthPrefixed(apv) + int32(bits)
        val out = ArrayList<Byte>()
        var round = 1
        try {
            while (out.size < bits / 8) {
                out.addAll(Crypto.digest(Algorithm.SHA256, int32(round) + z + otherInfo).toList())
                round++
            }
            val keyBytes = out.take(bits / 8).toByteArray()
            return SecretKey(keyBytes).also { keyBytes.fill(0) }
        } finally {
            z.fill(0)
        }
    }

    private fun int32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    private fun lengthPrefixed(data: ByteArray) = int32(data.size) + data
}

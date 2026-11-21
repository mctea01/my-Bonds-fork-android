package diw.wallet.core.verifier.declaration

import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcSignature
import org.multipaz.util.toBase64
import org.multipaz.util.toBase64Url

/**
 * A key that signs compact JWS for a verifier identity: the wallet's own key named by a DID (kid), or an X.509
 * certificate and its key from any [DocumentSigner] (x5c). The same signer signs the request object, the verifier
 * declaration and, for a principal, a mandate.
 */
interface JwsSigner {
    /** JOSE alg of the signature. */
    val alg: String
    /** Header members naming the key (kid, or x5c with the certificate chain). */
    val keyHeader: Map<String, JsonElement>
    /** DER certificate chain, signer first; empty for a key named by a DID. */
    val certificateChain: List<ByteArray>

    /** Signs [input] and returns the JWS signature value (raw r||s for ECDSA, PKCS#1 v1.5 for RSA). */
    suspend fun sign(input: ByteArray): ByteArray

    /** OpenID4VP client identifier this key authenticates: x509_hash of the leaf, or the DID. */
    val clientId: String
}

/** Signs with a Multipaz key named by [did] and [kid] (a verification method of the DID). */
class DidJwsSigner(private val key: AsymmetricKey, val did: String, private val kid: String) : JwsSigner {
    override val alg: String get() = key.algorithm.joseAlgorithmIdentifier ?: "ES256"
    override val keyHeader: Map<String, JsonElement> get() = mapOf("kid" to JsonPrimitive(kid))
    override val certificateChain: List<ByteArray> get() = emptyList()
    override val clientId: String get() = "decentralized_identifier:$did"
    override suspend fun sign(input: ByteArray): ByteArray = key.sign(input).toCoseEncoded()
}

/**
 * Signs with a [DocumentSigner]: RS256 for RSA keys, ES256 for P-256 keys (the DER signature is converted to the JWS
 * form). SM2 keys are only used for OFD and cannot sign a JWS. The client identifier is x509_hash of the leaf.
 * [chain] is what x5c carries, leaf first: the signer's own chain unless the caller completed it with the
 * intermediates (TrustRegistry.chainToSend), since a card or key store often returns the leaf alone.
 */
class CertificateJwsSigner(
    private val signer: DocumentSigner,
    chain: List<ByteArray> = signer.certificateChain,
) : JwsSigner {
    init {
        if (signer.keyType == SignerKeyType.SM2) throw ProtocolException("unsupported_key", "SM2 keys cannot sign a JWS")
        if (signer.certificateChain.isEmpty()) throw ProtocolException("unsupported_key", "The signer has no certificate")
        if (chain.isEmpty() || !chain.first().contentEquals(signer.certificateChain.first())) {
            throw ProtocolException("unsupported_key", "The chain must start with the signer's certificate")
        }
    }

    override val alg: String get() = if (signer.keyType == SignerKeyType.RSA) "RS256" else "ES256"
    override val certificateChain: List<ByteArray> = chain
    override val keyHeader: Map<String, JsonElement>
        get() = mapOf("x5c" to kotlinx.serialization.json.buildJsonArray { certificateChain.forEach { add(it.toBase64()) } })
    override val clientId: String get() = x509HashClientId(certificateChain.first())

    override suspend fun sign(input: ByteArray): ByteArray {
        val signature = signer.sign(input)
        return if (signer.keyType == SignerKeyType.RSA) signature else EcSignature.fromDerEncoded(256, signature).toCoseEncoded()
    }
}

/** x509_hash client identifier of a leaf certificate (OpenID4VP 1.0 section 5.9.3). */
fun x509HashClientId(leafDer: ByteArray): String = "x509_hash:" + PlatformCrypto.sha256(leafDer).toBase64Url()

/** Signs [payload] as a compact JWS with [typ] and the signer's key header. */
suspend fun JwsSigner.signCompact(typ: String, payload: JsonObject, extraHeader: Map<String, JsonElement> = emptyMap()): String {
    val header = buildJsonObject {
        put("alg", alg)
        put("typ", typ)
        for ((k, v) in keyHeader) put(k, v)
        for ((k, v) in extraHeader) put(k, v)
    }
    val input = header.toString().encodeToByteArray().toBase64Url() + "." + payload.toString().encodeToByteArray().toBase64Url()
    return input + "." + sign(input.encodeToByteArray()).toBase64Url()
}


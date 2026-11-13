package diw.wallet.core.document.sign

import diw.wallet.core.i18n.ct
import java.security.PrivateKey
import java.security.Provider
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

/**
 * A [DocumentSigner] over a JCA private key: Android KeyChain, the Windows or macOS certificate store, or a PKCS#11
 * token. [provider] is the token's provider; null lets JCA pick the provider that owns the key (KeyChain and
 * SunMSCAPI keys cannot be used by another provider). Every signature is checked against the certificate, so a token
 * that signs with another key is caught before the signature is written.
 */
class JcaDocumentSigner(
    private val key: PrivateKey,
    chain: List<X509Certificate>,
    override val source: SignerSource,
    private val provider: Provider? = null,
) : DocumentSigner {
    private val certificate = chain.firstOrNull() ?: throw SigningException(ct("core_key_no_certificate"))
    override val certificateChain: List<ByteArray> = chain.map { it.encoded }
    override val keyType: SignerKeyType = typeOf(certificate)

    override suspend fun sign(data: ByteArray): ByteArray {
        val alg = when (keyType) { SignerKeyType.RSA -> "SHA256withRSA"; SignerKeyType.SM2 -> "SM3withSM2"; else -> "SHA256withECDSA" }
        val signature = try {
            val s = if (provider != null) Signature.getInstance(alg, provider) else Signature.getInstance(alg)
            s.initSign(key)
            s.update(data)
            s.sign()
        } catch (e: Exception) {
            throw SigningException(ct("core_jds_sign_failed") + (e.message ?: e::class.simpleName), e)
        }
        val ok = runCatching {
            (if (keyType == SignerKeyType.SM2) Signature.getInstance(alg, diw.wallet.core.document.Bc.provider) else Signature.getInstance(alg))
                .run { initVerify(certificate.publicKey); update(data); verify(signature) }
        }.getOrDefault(false)
        if (!ok) throw SigningException(ct("core_jds_mismatch"))
        return signature
    }

    companion object {
        /** RSA, or EC on P-256; other keys are refused with a message. */
        fun typeOf(certificate: X509Certificate): SignerKeyType {
            val pub = certificate.publicKey
            return when (pub.algorithm) {
                "RSA" -> SignerKeyType.RSA
                "EC", "ECDSA", "SM2" -> {
                    if (OfdSigning.isSm2Key(pub.encoded)) return SignerKeyType.SM2
                    val bits = (pub as? ECPublicKey)?.params?.curve?.field?.fieldSize
                    if (bits != null && bits != 256) throw SigningException(ct("core_jds_p256_only", bits))
                    SignerKeyType.EC_P256
                }
                else -> throw SigningException(ct("core_key_type_unsupported", pub.algorithm))
            }
        }
    }
}

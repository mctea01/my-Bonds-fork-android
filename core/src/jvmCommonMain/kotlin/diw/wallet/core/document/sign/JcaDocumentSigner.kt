package diw.wallet.core.document.sign

import diw.wallet.core.i18n.ct
import java.security.PrivateKey
import java.security.Provider
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

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

    /**
     * PS256 with the key's own provider: the JCA name RSASSA-PSS with parameters, or the Android KeyStore and
     * KeyChain name SHA256withRSA/PSS (whose parameters are fixed to SHA-256, MGF1-SHA-256 and a 32-byte salt).
     * Checked against the certificate like [sign].
     */
    override suspend fun signRsaPss(data: ByteArray): ByteArray? {
        if (keyType != SignerKeyType.RSA) return null
        val attempts = listOf<() -> Signature>(
            { (if (provider != null) Signature.getInstance("RSASSA-PSS", provider) else Signature.getInstance("RSASSA-PSS")).apply { setParameter(PSS_SHA256) } },
            { if (provider != null) Signature.getInstance("SHA256withRSA/PSS", provider) else Signature.getInstance("SHA256withRSA/PSS") },
        )
        var last: Exception? = null
        for (make in attempts) {
            val signature = try {
                make().run { initSign(key); update(data); sign() }
            } catch (e: Exception) {
                last = e
                continue
            }
            val ok = runCatching {
                Signature.getInstance("RSASSA-PSS", diw.wallet.core.document.Bc.provider).run {
                    setParameter(PSS_SHA256); initVerify(certificate.publicKey); update(data); verify(signature)
                }
            }.getOrDefault(false)
            if (!ok) throw SigningException(ct("core_jds_mismatch"))
            return signature
        }
        throw SigningException(ct("core_jds_sign_failed") + (last?.message ?: last?.let { it::class.simpleName } ?: "RSASSA-PSS"), last)
    }

    companion object {
        /** RSASSA-PSS parameters of PS256 (RFC 8017, RFC 8230): SHA-256, MGF1 with SHA-256, 32-byte salt, trailer 1. */
        val PSS_SHA256 = PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)

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

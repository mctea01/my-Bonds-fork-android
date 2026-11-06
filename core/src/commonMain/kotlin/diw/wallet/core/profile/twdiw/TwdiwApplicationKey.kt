package diw.wallet.core.profile.twdiw

import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.PlatformCrypto
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcSignature

/** An application's own P-256 ecosystem signing key, independent of its holder identity. */
class TwdiwApplicationKey private constructor(val publicKey: EcPublicKey, val signingKey: AsymmetricKey) {
    /** The SDK hashes the normalized Base64 SPKI text, rather than the DER bytes or holder DID. */
    val keyId: String = DocCryptoUtil.hex(PlatformCrypto.sha256(
        publicKey.toPem().lineSequence().filterNot { it.startsWith("-----") }
            .joinToString("") { it.trim() }.encodeToByteArray(),
    ))

    companion object {
        fun fromPrivateKey(key: EcPrivateKey): TwdiwApplicationKey {
            require(key.curve == EcCurve.P256) { "TWDIW application signatures require P-256" }
            return TwdiwApplicationKey(key.publicKey, AsymmetricKey.AnonymousExplicit(key, Algorithm.ES256))
        }

        /** Imports a caller-owned pair and checks possession against the supplied public key. */
        suspend fun fromPem(privateKeyPem: String, publicKeyPem: String): TwdiwApplicationKey {
            val publicKey = EcPublicKey.fromPem(publicKeyPem)
            require(publicKey.curve == EcCurve.P256) { "TWDIW application signatures require P-256" }
            val privateKey = EcPrivateKey.fromPem(privateKeyPem, publicKey)
            require(privateKey.curve == EcCurve.P256) { "TWDIW application signatures require P-256" }
            val signer = AsymmetricKey.AnonymousExplicit(privateKey, Algorithm.ES256)
            val challenge = "DIW TWDIW application key-pair validation".encodeToByteArray()
            Crypto.checkSignature(publicKey, challenge, Algorithm.ES256, signer.sign(challenge) as EcSignature)
            return TwdiwApplicationKey(publicKey, signer)
        }
    }
}

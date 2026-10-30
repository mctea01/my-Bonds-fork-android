package diw.wallet.core.oid4vci

import diw.wallet.core.jose.PlatformCrypto
import kotlinx.serialization.json.add
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.securearea.KeyAttestation
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

/**
 * A self-signed wallet provider: it mints a wallet attestation, a client assertion and a key attestation with an
 * ephemeral key of its own, and carries that key in each JWT header (jwk) so a verifier can check self-consistency.
 *
 * No real issuer trusts this key, so these attestations only unblock issuers that require attestation yet do not
 * check which wallet provider signed it (sandbox and demo issuers). It is a last-resort fallback the user turns on,
 * never a substitute for a registered provider, and it is used only for issuers no configured provider vouches for.
 */
class SelfAttestationWalletProvider(override val clientId: String) : WalletProvider {
    /** Ephemeral attester key, generated once per instance; the wallet itself is the (untrusted) attester. */
    private var attesterKey: AsymmetricKey? = null

    /** Bound into the wallet attestation (cnf) and signs its PoP; lives as long as this provider. */
    private var instanceKey: AsymmetricKey? = null

    private suspend fun attester(): AsymmetricKey =
        attesterKey ?: AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), Algorithm.ES256).also { attesterKey = it }

    override suspend fun walletAttestation(): WalletAttestation {
        val attester = attester()
        val key = instanceKey
            ?: AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), Algorithm.ES256).also { instanceKey = it }
        val cnfJwk = key.publicKey.toJwk()
        val jwt = buildJwt(
            type = "oauth-client-attestation+jwt",
            key = attester,
            expiresIn = 1.days,
            header = { put("jwk", attester.publicKey.toJwk()) },
        ) {
            put("iss", clientId)
            put("sub", clientId)
            putJsonObject("cnf") { put("jwk", cnfJwk) }
            put("wallet_name", "DIW MY WALLET")
            put("wallet_link", "https://github.com/mctea01/my-Bonds-fork-android")
        }
        return WalletAttestation(jwt, key)
    }

    override suspend fun clientAssertion(audience: String): String {
        val attester = attester()
        return buildJwt(
            type = "JWT",
            key = attester,
            expiresIn = 5.minutes,
            header = { put("jwk", attester.publicKey.toJwk()) },
        ) {
            put("jti", PlatformCrypto.randomBytes(18).toBase64Url())
            put("iss", clientId)
            put("sub", clientId)
            put("aud", audience)
        }
    }

    override suspend fun keyAttestation(keys: List<KeyAttestation>, nonce: String?, userAuthentication: Boolean): String? {
        if (keys.isEmpty()) return null
        val attester = attester()
        val jwks = keys.map { it.publicKey.toJwk() }
        return buildJwt(
            type = "key-attestation+jwt",
            key = attester,
            expiresIn = 5.minutes,
            header = { put("jwk", attester.publicKey.toJwk()) },
        ) {
            putJsonArray("attested_keys") { jwks.forEach { add(it) } }
            nonce?.let { put("nonce", it) }
            putJsonArray("user_authentication") { add(if (userAuthentication) "iso_18045_high" else "iso_18045_basic") }
        }
    }
}

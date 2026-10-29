package diw.wallet.core.oid4vci

import diw.wallet.core.jose.PlatformCrypto
import io.ktor.http.Url
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
 * The test identity Multipaz publishes in its open-source TestApp (samples/testapp ProvisioningSupport.kt,
 * Apache-2.0), which the Multipaz sample issuer (issuer.multipaz.org) trusts for client assertions, wallet
 * attestations and key attestations. Multipaz states these keys are for testing only and that no real
 * provisioning server can trust them, so the wallet uses them only in the test environment, only for
 * [HOSTS], and only when the user turns them on.
 */
class MultipazTestWalletProvider : WalletProvider {
    override val clientId: String = CLIENT_ID

    /** Bound into the wallet attestation (cnf) and signs its PoP; lives as long as this provider. */
    private var instanceKey: AsymmetricKey? = null

    override suspend fun walletAttestation(): WalletAttestation {
        val key = instanceKey ?: AsymmetricKey.AnonymousExplicit(Crypto.createEcPrivateKey(EcCurve.P256), Algorithm.ES256)
            .also { instanceKey = it }
        val cnfJwk = key.publicKey.toJwk()
        val jwt = buildJwt(type = "oauth-client-attestation+jwt", key = attestationKey, expiresIn = 1.days) {
            put("iss", attestationKey.subject)
            put("sub", clientId)
            putJsonObject("cnf") { put("jwk", cnfJwk) }
            put("wallet_name", "DIW MY WALLET")
            put("wallet_link", "https://github.com/mctea01/my-Bonds-fork-android")
        }
        return WalletAttestation(jwt, key)
    }

    override suspend fun clientAssertion(audience: String): String =
        buildJwt(type = "JWT", key = clientAssertionKey, expiresIn = 5.minutes) {
            put("jti", PlatformCrypto.randomBytes(18).toBase64Url())
            put("iss", clientId)
            put("sub", clientId)
            put("aud", audience)
        }

    override suspend fun keyAttestation(keys: List<KeyAttestation>, nonce: String?, userAuthentication: Boolean): String? {
        if (keys.isEmpty()) return null
        val jwks = keys.map { it.publicKey.toJwk() }
        return buildJwt(type = "key-attestation+jwt", key = attestationKey, expiresIn = 5.minutes) {
            put("iss", attestationKey.subject)
            putJsonArray("attested_keys") { jwks.forEach { add(it) } }
            nonce?.let { put("nonce", it) }
            putJsonArray("user_authentication") { add(if (userAuthentication) "iso_18045_high" else "iso_18045_basic") }
        }
    }

    companion object {
        const val CLIENT_ID = "urn:uuid:418745b8-78a3-4810-88df-7898aff3ffb4"

        /** Issuers that trust this identity. */
        val HOSTS = setOf("issuer.multipaz.org")

        fun appliesTo(credentialIssuer: String, authorizationServer: String): Boolean =
            listOf(credentialIssuer, authorizationServer).all { runCatching { Url(it).host in HOSTS }.getOrDefault(false) }

        private val clientAssertionKey: AsymmetricKey by lazy {
            AsymmetricKey.parseExplicit(
                """
                {
                    "kty": "EC",
                    "alg": "ES256",
                    "kid": "895b72b9-0808-4fcc-bb19-960d14a9e28f",
                    "crv": "P-256",
                    "x": "nSmAFnZx-SqgTEyqqOSmZyLESdbiSUIYlRlLLoWy5uc",
                    "y": "FN1qcif7nyVX1MHN_YSbo7o7RgG2kPJUjg27YX6AKsQ",
                    "d": "TdQhxDqbAUpzMJN5XXQqLea7-6LvQu2GFKzj5QmFDCw"
                }
                """.trimIndent()
            )
        }

        private val attestationKey: AsymmetricKey by lazy {
            AsymmetricKey.parseExplicit(
                """
                {
                    "kty": "EC",
                    "alg": "ES256",
                    "crv": "P-256",
                    "x": "CoLFZ9sJfTqax-GarKIyw7_fX8-L446AoCTSHKJnZGs",
                    "y": "ALEJB1_YQMO_0qSFQb3urFTxRfANN8-MSeWLHYU7MVI",
                    "d": "nJXw7FqLff14yQLBEAwu70mu1gzlfOONh9UuealdsVM",
                    "x5c": [
                        "MIIBtDCCATugAwIBAgIJAPosC/l8rotwMAoGCCqGSM49BAMCMDgxNjA0BgNVBAMTLXVybjp1dWlkOjYwZjhjMTE3LWI2OTItNGRlOC04ZjdmLTYzNmZmODUyYmFhNjAeFw0yNTA5MzAwMjUxNDRaFw0zNTA5MjgwMjUxNDRaMDgxNjA0BgNVBAMMLXVybjp1dWlkOjRjNDY0NzJiLTdlYjItNDRiNi04NTNhLWY3ZGZlMTEzYzU3NTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAqCxWfbCX06msfhmqyiMsO/31/Pi+OOgKAk0hyiZ2RrALEJB1/YQMO/0qSFQb3urFTxRfANN8+MSeWLHYU7MVKjLjAsMB8GA1UdIwQYMBaAFPqAK5EjiQbxFAeWt//DCaWtC57aMAkGA1UdEwQCMAAwCgYIKoZIzj0EAwIDZwAwZAIwfDEviit5J188zK5qKjkzFWkPy3ljshUg650p2kNuQq7CiQvbKyVDIlCGgOhMZyy+AjBm6ehDicFMPVBEHLUEiXO4cHw7Ed6dFpPm/6GknWcADhax62KN1tIzExo6T1l06G4=",
                        "MIIBxTCCAUugAwIBAgIJAOQTL9qcQopZMAoGCCqGSM49BAMDMDgxNjA0BgNVBAMTLXVybjp1dWlkOjYwZjhjMTE3LWI2OTItNGRlOC04ZjdmLTYzNmZmODUyYmFhNjAeFw0yNDA5MjMyMjUxMzFaFw0zNDA5MjMyMjUxMzFaMDgxNjA0BgNVBAMTLXVybjp1dWlkOjYwZjhjMTE3LWI2OTItNGRlOC04ZjdmLTYzNmZmODUyYmFhNjB2MBAGByqGSM49AgEGBSuBBAAiA2IABN4D7fpNMAv4EtxyschbITpZ6iNH90rGapa6YEO/uhKnC6VpPt5RUrJyhbvwAs0edCPthRfIZwfwl5GSEOS0mKGCXzWdRv4GGX/Y0m7EYypox+tzfnRTmoVX3v6OxQiapKMhMB8wHQYDVR0OBBYEFPqAK5EjiQbxFAeWt//DCaWtC57aMAoGCCqGSM49BAMDA2gAMGUCMEO01fJKCy+iOTpaVp9LfO7jiXcXksn2BA22reiR9ahDRdGNCrH1E3Q2umQAssSQbQIxAIz1FTHbZPcEbA5uE5lCZlRG/DQxlZhk/rZrkPyXFhqEgfMnQ45IJ6f8Utlg+4Wiiw=="
                    ]
                }
                """.trimIndent()
            )
        }
    }
}

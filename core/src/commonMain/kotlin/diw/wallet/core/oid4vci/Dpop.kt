package diw.wallet.core.oid4vci

import diw.wallet.core.jose.PlatformCrypto
import io.ktor.http.Url
import kotlinx.serialization.json.put
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt

/**
 * RFC 9449 DPoP proof signer. One key per issuance session; server nonces are tracked per origin
 * (authorization server and credential issuer keep separate nonces).
 */
class DpopSigner(val key: AsymmetricKey) {
    private val nonces = mutableMapOf<String, String>()

    fun nonceFor(url: String): String? = nonces[origin(url)]

    fun updateNonce(url: String, nonce: String?) {
        if (nonce != null) nonces[origin(url)] = nonce
    }

    suspend fun proof(method: String, url: String, accessToken: String? = null): String = buildJwt(
        type = "dpop+jwt",
        key = key,
        header = { put("jwk", key.publicKey.toJwk()) },
    ) {
        put("htm", method)
        put("htu", htu(url))
        put("jti", PlatformCrypto.randomBytes(16).toBase64Url())
        nonceFor(url)?.let { put("nonce", it) }
        if (accessToken != null) {
            put("ath", PlatformCrypto.sha256(accessToken.encodeToByteArray()).toBase64Url())
        }
    }

    companion object {
        /** htu is the request URL without query and fragment (RFC 9449 Section 4.2). */
        fun htu(url: String): String = url.substringBefore('#').substringBefore('?')

        private fun origin(url: String): String {
            val u = Url(url)
            return "${u.protocol.name}://${u.host}:${u.port}"
        }
    }
}

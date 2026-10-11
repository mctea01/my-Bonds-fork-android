package diw.testservers

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.arr
import diw.wallet.core.util.bool
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.device.AndroidKeystoreSecurityLevel
import org.multipaz.util.AndroidAttestationExtensionParser
import org.multipaz.util.fromBase64
import org.multipaz.util.toBase64Url
import org.multipaz.webtoken.buildJwt
import kotlin.time.Duration.Companion.hours

/**
 * Test wallet provider (TEST environment). Vouches for wallet instances and their keys.
 * Policy (project decision): a key is accepted when its platform attestation chain is valid and binds the
 * presented key; there is no RKP or revocation check. Keys without a platform chain are software keys and
 * are attested as iso_18045_basic, which only the test environment accepts.
 */
class WalletProviderService(
    private val baseUrl: String,
    private val pki: TestPki,
    /** Require the Android attestation chain to end in a Google root (off for emulators and tests). */
    private val requireGoogleRoot: Boolean = false,
) {
    val issuerId: String get() = "$baseUrl/wallet-provider"

    enum class KeyStorage(val wire: String) {
        SOFTWARE("iso_18045_basic"),
        TEE("iso_18045_moderate"),
        STRONGBOX("iso_18045_high"),
    }

    suspend fun walletAttestation(body: JsonObject): JsonObject {
        val clientId = body.str("client_id") ?: throw ProtocolException("invalid_request", "client_id required")
        val jwk = body.obj("jwk") ?: throw ProtocolException("invalid_request", "jwk required")
        val storage = checkKey(EcPublicKey.fromJwk(jwk), body.arr("x5c"))
        val jwt = buildJwt(
            type = "oauth-client-attestation+jwt",
            key = pki.walletProviderSigner,
            expiresIn = 1.hours,
        ) {
            put("iss", issuerId)
            put("sub", clientId)
            putJsonObject("cnf") { put("jwk", jwk) }
            put("wallet_name", "DIW MY WALLET")
            put("wallet_link", "https://github.com/mctea01/my-Bonds-fork-android")
            put("key_storage_level", storage.wire)
        }
        return kotlinx.serialization.json.buildJsonObject {
            put("wallet_attestation", jwt)
            put("client_id", clientId)
        }
    }

    suspend fun keyAttestation(body: JsonObject): JsonObject {
        val keys = body.arr("keys")?.filterIsInstance<JsonObject>().orEmpty()
        if (keys.isEmpty()) throw ProtocolException("invalid_request", "keys required")
        var weakest = KeyStorage.STRONGBOX
        val jwks = keys.map { k ->
            val jwk = k.obj("jwk") ?: throw ProtocolException("invalid_request", "jwk required")
            val s = checkKey(EcPublicKey.fromJwk(jwk), k.arr("x5c"))
            if (s.ordinal < weakest.ordinal) weakest = s
            jwk
        }
        val userAuth = body.bool("user_authentication") ?: false
        val jwt = buildJwt(
            type = "key-attestation+jwt",
            key = pki.walletProviderSigner,
            expiresIn = 1.hours,
        ) {
            put("iss", issuerId)
            putJsonArray("attested_keys") { jwks.forEach { add(it) } }
            putJsonArray("key_storage") { add(weakest.wire) }
            putJsonArray("user_authentication") { add(if (userAuth) "iso_18045_high" else "iso_18045_basic") }
            body.str("nonce")?.let { put("nonce", it) }
            put("jti", PlatformCrypto.randomBytes(12).toBase64Url())
        }
        return kotlinx.serialization.json.buildJsonObject { put("key_attestation", jwt) }
    }

    /** Validates an optional Android attestation chain for [key]; returns the storage level. */
    private suspend fun checkKey(key: EcPublicKey, x5c: JsonArray?): KeyStorage {
        if (x5c == null || x5c.isEmpty()) return KeyStorage.SOFTWARE
        val chain = X509CertChain(x5c.map { X509Cert(kotlinx.io.bytestring.ByteString((it as JsonPrimitive).content.fromBase64())) })
        try {
            chain.validate(validateCaValidity = false)
        } catch (e: Exception) {
            throw ProtocolException("invalid_key_attestation", "Attestation chain is invalid: ${e.message}", e)
        }
        if (chain.certificates.first().ecPublicKey != key) {
            throw ProtocolException("invalid_key_attestation", "Attestation chain does not certify the presented key")
        }
        if (requireGoogleRoot) {
            org.multipaz.util.validateAndroidKeyAttestation(
                chain = chain, challenge = null, requireGmsAttestation = true, requireVerifiedBootGreen = false,
                requireKeyMintSecurityLevel = AndroidKeystoreSecurityLevel.TRUSTED_ENVIRONMENT,
                requireAppSignatureCertificateDigests = emptySet(), requireAppPackages = emptySet(),
            )
        }
        val parser = runCatching { AndroidAttestationExtensionParser(chain.certificates.first()) }.getOrNull()
            ?: return KeyStorage.SOFTWARE
        return when (parser.keymasterSecurityLevel) {
            AndroidKeystoreSecurityLevel.STRONG_BOX -> KeyStorage.STRONGBOX
            AndroidKeystoreSecurityLevel.TRUSTED_ENVIRONMENT -> KeyStorage.TEE
            else -> KeyStorage.SOFTWARE
        }
    }
}

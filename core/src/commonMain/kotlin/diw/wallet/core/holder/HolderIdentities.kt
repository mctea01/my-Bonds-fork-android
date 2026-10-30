package diw.wallet.core.holder

import diw.wallet.core.did.DidKeys
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcPublicKey
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec

/**
 * A holder key in a secure area: per credential, or [shared] by every credential of a profile.
 * [did] is the holder identifier issuers bind to when they bind to a DID.
 */
class HolderKey(
    val secureArea: SecureArea,
    val keyInfo: KeyInfo,
    val shared: Boolean,
    val did: String? = null,
) {
    val alias: String get() = keyInfo.alias
    val publicKey: EcPublicKey get() = keyInfo.ecPublicKey

    /** Signing key for JOSE/COSE with [alg] (a JOSE name); the key's own algorithm when null. */
    fun signingKey(alg: String? = null): AsymmetricKey.AnonymousSecureAreaBased = AsymmetricKey.AnonymousSecureAreaBased(
        alias = alias,
        secureArea = secureArea,
        keyInfo = keyInfo,
        algorithm = alg?.let { Algorithm.fromJoseAlgorithmIdentifier(it) } ?: keyInfo.algorithm.let { if (it == Algorithm.UNSET) Algorithm.ES256 else it },
    )

    fun withDid(did: String?): HolderKey = HolderKey(secureArea, keyInfo, shared, did)

    companion object {
        /** Holder DID of [key] for [method]: did:key:jwk_jcs (TWDIW), did:key (curve multicodec) or did:jwk. */
        suspend fun didFor(key: EcPublicKey, method: String): String = when (method) {
            DID_KEY_JWK_JCS -> DidKeys.didKeyJwkJcs(key)
            "did:key" -> DidKeys.didKey(key)
            "did:jwk", "did" -> DidKeys.didJwk(key)
            else -> throw ProtocolException("unsupported_did", "Cannot create a holder DID with method $method")
        }

        const val DID_KEY_JWK_JCS = "did:key:jwk_jcs"
    }
}

@Serializable
private data class StoredIdentity(val secureArea: String, val alias: String, val didMethod: String)

/**
 * Wallet-level holder identities, one per profile (e.g. twdiw, msvid): the profile's own wallet binds every
 * credential to one key and one DID, and its verifiers expect all presented credentials to share that holder.
 */
class HolderIdentities(
    private val storage: Storage,
    private val secureAreas: SecureAreaRepository,
) {
    private suspend fun table() = storage.getTable(TABLE)

    /** The profile's key, created in [secureArea] with [settings] the first time. */
    suspend fun getOrCreate(profile: String, didMethod: String, secureArea: SecureArea, settings: CreateKeySettings): HolderKey {
        find(profile)?.let { return it }
        val info = secureArea.createKey(null, settings)
        val stored = StoredIdentity(secureArea.identifier, info.alias, didMethod)
        val t = table()
        val bytes = DiwJson.encodeToString(StoredIdentity.serializer(), stored).encodeToByteString()
        if (t.get(profile) == null) t.insert(profile, bytes) else t.update(profile, bytes)
        return HolderKey(secureArea, info, shared = true, did = HolderKey.didFor(info.ecPublicKey, didMethod))
    }

    /** The profile's key, or null when it was never created or its key is gone. */
    suspend fun find(profile: String): HolderKey? {
        val stored = table().get(profile)?.let { DiwJson.decodeFromString(StoredIdentity.serializer(), it.decodeToString()) } ?: return null
        val area = secureAreas.getImplementation(stored.secureArea) ?: return null
        val info = runCatching { area.getKeyInfo(stored.alias) }.getOrNull() ?: return null
        return HolderKey(area, info, shared = true, did = HolderKey.didFor(info.ecPublicKey, stored.didMethod))
    }

    /** The shared key of whichever profile holds [publicKey]. */
    suspend fun findByPublicKey(publicKey: EcPublicKey): HolderKey? {
        for (p in table().enumerate()) find(p)?.let { if (it.publicKey == publicKey) return it }
        return null
    }

    suspend fun profiles(): List<String> = table().enumerate()

    companion object {
        const val TWDIW = "twdiw"
        const val MS_VERIFIED_ID = "msvid"
        const val BONDS_SELF_ISSUED = "bonds-self"
        /** Issuer DID (did:key) of the credentials the wallet derives from stored documents. */
        const val DOCUMENT_ISSUER = "document-issuer"
        /** The wallet's own document signing key, certified by a self-issued certificate. */
        const val DOCUMENT_SIGNER = "document-signer"
        /** Self-issued OpenID Provider identity for id_token-only (sign in) requests. */
        const val SIOP = "siop"

        private val TABLE = StorageTableSpec("DiwHolderIdentities", supportPartitions = false, supportExpiration = false)
    }
}

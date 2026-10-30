package diw.wallet.core.profile.twdiw

import diw.wallet.core.compat.TwdiwAppIdentity
import diw.wallet.core.compat.TwdiwDialect
import diw.wallet.core.did.DidKeys
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.signJws
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.io.bytestring.encodeToByteString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureArea
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.storage.Storage
import org.multipaz.storage.StorageTableSpec
import kotlin.io.encoding.Base64
import kotlin.time.Clock

/** Where a device key can be created, strongest first; [protection] is recorded as the key's backing (StrongBox, TEE, software). */
class TwdiwKeyBackend(
    val secureArea: SecureArea,
    val protection: String,
    /** Settings for a key without per-use user authentication whose attestation binds [challenge]. */
    val settings: suspend (challenge: ByteString) -> CreateKeySettings,
)

/** The registration state of the device key for one ecosystem host, with the server's last answer kept verbatim. */
@Serializable
data class TwdiwDeviceKeyRecord(
    val host: String,
    val secureArea: String,
    val alias: String,
    /** StrongBox, TEE or software. */
    val protection: String,
    val keyType: String = KEY_TYPE,
    val keyPrefix: String,
    val did: String,
    val keyId: String? = null,
    val status: String? = null,
    val registeredAt: Long? = null,
    val lastAttemptAt: Long? = null,
    val lastHttpStatus: Int? = null,
    /** The registration response body (first 4000 characters), to compare with the official app on a device. */
    val lastResponse: String? = null,
    val lastError: String? = null,
) {
    val registered: Boolean get() = keyId != null

    companion object {
        const val KEY_TYPE = "EC"
    }
}

/** A registered device key ready to sign the ecosystem header. */
class TwdiwDeviceSigningKey(val keyId: String, val key: AsymmetricKey)

/**
 * The device key of TWDIW's ecosystem signature (Twdiw-Signature), as the official wallet manages it: a P-256 key the
 * device creates itself (StrongBox first, then the TEE, then a software key) with a key attestation bound to an
 * ecosystem nonce, registered at the platform's `api/did/` endpoint, which answers with the keyId the header names.
 *
 * The registration request is inferred from the official app's structure (key type, key prefix, public key, DID,
 * attestation chain, nonce and this wallet's own application identity, with a proof of possession); its exact field
 * names are not published. The server's answer is stored verbatim in [TwdiwDeviceKeyRecord] so it can be compared on
 * a device. A refused registration never blocks issuance: the dialect then signs with the holder key as before.
 * Only this wallet's own key and identity are used; no official-app key is involved.
 */
class TwdiwDeviceKeys(
    private val storage: Storage,
    private val secureAreas: SecureAreaRepository,
    private val http: HttpClient,
    private val backends: suspend () -> List<TwdiwKeyBackend>,
    private val identity: () -> TwdiwAppIdentity = { TwdiwAppIdentity.DEFAULT },
    /** Base URL of the registration endpoint for an issuer origin; the origin itself by default. */
    private val registrationBase: (origin: String) -> String = { it },
    private val clock: Clock = Clock.System,
) {
    private suspend fun table() = storage.getTable(TABLE)

    suspend fun record(host: String): TwdiwDeviceKeyRecord? =
        table().get(host)?.let { runCatching { DiwJson.decodeFromString(TwdiwDeviceKeyRecord.serializer(), it.decodeToString()) }.getOrNull() }

    suspend fun records(): List<TwdiwDeviceKeyRecord> = table().enumerate().mapNotNull { record(it) }

    private suspend fun save(r: TwdiwDeviceKeyRecord) {
        val t = table()
        val bytes = DiwJson.encodeToString(TwdiwDeviceKeyRecord.serializer(), r).encodeToByteString()
        if (t.get(r.host) == null) t.insert(r.host, bytes) else t.update(r.host, bytes)
    }

    /** Forgets the key and registration for [host]; the next issuance creates and registers a new key. */
    suspend fun reset(host: String) {
        record(host)?.let { r -> runCatching { secureAreas.getImplementation(r.secureArea)?.deleteKey(r.alias) } }
        table().delete(host)
    }

    /**
     * The registered key for the issuer at [origin] (scheme and authority): an earlier registration, or a new key
     * registered now. Null when registration failed; a failed attempt is retried after [RETRY_SECONDS].
     */
    suspend fun signingKey(origin: String): TwdiwDeviceSigningKey? {
        val host = origin.substringAfter("://").substringBefore('/').substringBefore(':').lowercase()
        var r = record(host)
        val now = clock.now().epochSeconds
        val area = r?.let { secureAreas.getImplementation(it.secureArea) }
        val info = area?.let { a -> runCatching { a.getKeyInfo(r!!.alias) }.getOrNull() }
        if (r != null && area != null && info != null && r.keyId != null) {
            return TwdiwDeviceSigningKey(r.keyId, AsymmetricKey.AnonymousSecureAreaBased(alias = r.alias, secureArea = area, keyInfo = info, algorithm = Algorithm.ES256))
        }
        if (r != null && r.lastAttemptAt != null && now - r.lastAttemptAt < RETRY_SECONDS && info != null) return null

        val nonce = nonce(origin)
        // A key that disappeared (cleared keystore) or never existed is created again, bound to this nonce.
        val (useArea, useInfo, record) = if (area != null && info != null && r != null) Triple(area, info, r) else {
            val challenge = (nonce ?: DocCryptoUtil.hex(PlatformCrypto.randomBytes(16))).encodeToByteString()
            var created: Triple<SecureArea, org.multipaz.securearea.KeyInfo, TwdiwDeviceKeyRecord>? = null
            var failure: Throwable? = null
            for (b in backends()) {
                val made = runCatching { b.secureArea.createKey(null, b.settings(challenge)) }
                made.exceptionOrNull()?.let { failure = it }
                val ki = made.getOrNull() ?: continue
                val did = DidKeys.didKeyJwkJcs(ki.publicKey)
                created = Triple(b.secureArea, ki, TwdiwDeviceKeyRecord(
                    host = host, secureArea = b.secureArea.identifier, alias = ki.alias, protection = b.protection,
                    keyPrefix = keyPrefix(b.protection), did = did,
                ))
                break
            }
            created ?: run {
                failure?.let { r?.let { old -> save(old.copy(lastAttemptAt = now, lastError = "無法建立裝置金鑰：" + it.message)) } }
                return null
            }
        }
        val rec = record
        val attestation = useInfo.attestation.certChain?.certificates?.map { Base64.Default.encode(it.encoded.toByteArray()) }.orEmpty()
        val signing = AsymmetricKey.AnonymousSecureAreaBased(alias = useInfo.alias, secureArea = useArea, keyInfo = useInfo, algorithm = Algorithm.ES256)
        val id = identity()
        val jwk = useInfo.publicKey.toJwk()
        val proof = nonce?.let {
            signJws(
                buildJsonObject { put("typ", "JWT"); put("alg", "ES256"); put("kid", rec.did) },
                buildJsonObject { put("iss", rec.did); put("nonce", it); put("iat", now) },
                signing,
            )
        }
        val body = buildJsonObject {
            put("did", rec.did)
            put("keyType", rec.keyType)
            put("keyPrefix", rec.keyPrefix)
            put("publicKey", jwk)
            putJsonArray("attestation") { attestation.forEach { add(JsonPrimitive(it)) } }
            nonce?.let { put("nonce", it) }
            proof?.let { put("proof", it) }
            put("appHash", DocCryptoUtil.hex(PlatformCrypto.sha256(id.appId.encodeToByteArray())))
            put("appPlatform", id.appPlatform)
            put("appVersion", id.appVersion)
        }
        val result = runCatching {
            val resp = http.post(registrationBase(origin).trimEnd('/') + REGISTRATION_PATH) {
                contentType(ContentType.Application.Json)
                header(HttpHeaders.Accept, "application/json")
                setBody(body.toString())
            }
            resp.status.value to resp.bodyAsText()
        }
        val (status, text) = result.getOrElse {
            save(rec.copy(lastAttemptAt = now, lastError = "註冊請求失敗：" + it.message))
            return null
        }
        val parsed = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull()
        val data = parsed?.obj("data") ?: parsed
        val keyId = data?.str("keyId") ?: data?.str("key_id") ?: data?.str("kid")
        val accepted = status in 200..299 && keyId != null && (parsed?.str("code")?.let { it == "0" } ?: true)
        val updated = rec.copy(
            keyId = if (accepted) keyId else null,
            status = data?.str("status") ?: (data?.get("status") as? JsonPrimitive)?.content,
            registeredAt = if (accepted) now else null,
            lastAttemptAt = now,
            lastHttpStatus = status,
            lastResponse = text.take(4000),
            lastError = if (accepted) null else "伺服器沒有接受註冊（HTTP $status）",
        )
        save(updated)
        return if (accepted) TwdiwDeviceSigningKey(keyId!!, signing) else null
    }

    /** A fresh ecosystem nonce from the issuer origin, or null when the endpoint does not answer with one. */
    private suspend fun nonce(origin: String): String? = runCatching {
        val resp = http.get(origin.trimEnd('/') + TwdiwDialect.ECOSYSTEM_NONCE_PATH) { header(HttpHeaders.Accept, "application/json") }
        if (!resp.status.isSuccess()) return null
        val o = DiwJson.parseToJsonElement(resp.bodyAsText()) as? JsonObject ?: return null
        (o.obj("data") ?: o).str("nonce")?.takeIf { it.isNotBlank() }
    }.getOrNull()

    companion object {
        const val REGISTRATION_PATH = "/api/did/"
        const val RETRY_SECONDS = 600L
        private val TABLE = StorageTableSpec("DiwTwdiwDeviceKeys", supportPartitions = false, supportExpiration = false)

        /** The key URI prefix the official app uses for hardware keys; software keys are named as such. */
        fun keyPrefix(protection: String): String = if (protection.equals("software", true)) "software://" else "android-keystore://"
    }
}

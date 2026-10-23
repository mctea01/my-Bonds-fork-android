package diw.wallet.core.zk

import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.zktls.ZkTlsProfile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.EcPublicKey
import kotlin.time.Instant

/**
 * Page templates published as data with each GitHub Release, so a new verification page or document layout needs no
 * app update: zkTLS verification page profiles and zkPDF document templates. The pack is a compact JWS (typ
 * [TYP], ES256) signed by the project's release key, whose public half is pinned in [TRUSTED_KEYS]; [version] only
 * grows, and a wallet never installs a pack older than one it has seen. A template never changes a circuit: the
 * verifier still accepts only the circuits pinned in the app.
 */
data class ZkTemplatePack(
    val version: Long,
    val issuedAt: Instant,
    val zktls: List<ZkTlsProfile>,
    /** zkPDF templates as published; read by the zkPDF code against its own schema. */
    val zkpdf: List<JsonObject>,
) {
    fun payload(): JsonObject = buildJsonObject {
        put("v", 1)
        put("version", version)
        put("iat", issuedAt.epochSeconds)
        putJsonArray("zktls") { zktls.forEach { add(DiwJson.encodeToJsonElement(ZkTlsProfile.serializer(), it)) } }
        putJsonArray("zkpdf") { zkpdf.forEach { add(it) } }
    }

    companion object {
        const val TYP = "zk-templates+jwt"

        /**
         * The release asset name. Every push to main replaces the "nightly" pre-release, which carries the pack;
         * GitHub's releases/latest skips pre-releases, so the tag is named.
         */
        const val FILE = "zk-templates.jwt"
        const val RELEASE_URL = "https://github.com/mctea01/my-Bonds-fork-android/releases/download/nightly/$FILE"

        /**
         * A release the maintainer fills by hand: a pack signed locally with the same key and uploaded to the
         * "zk-templates" release, for when the nightly one is missing or broken (templates/README.md).
         */
        const val MANUAL_URL = "https://github.com/mctea01/my-Bonds-fork-android/releases/download/zk-templates/$FILE"

        /** Where the wallet looks, with the name it shows; the newest valid pack of all of them is installed. */
        val SOURCES: List<Pair<String, String>> = listOf("nightly" to RELEASE_URL, "手動發布" to MANUAL_URL)

        /**
         * PEM public keys (P-256) allowed to sign packs. The private key is the repository's GitHub Actions secret
         * ZK_TEMPLATES_KEY; a key is replaced by adding the new one here first and removing the old one later.
         */
        val TRUSTED_KEYS: List<String> = listOf(
            // Release key added 2026-10-23, SHA-256 of the DER SubjectPublicKeyInfo 3191665f25525309b0658b742639852d233014cf6a5c84612cf0a2518613285f.
            """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/NAlkL/o7vVQIR7TNiKnk+hA+ssI
            nEDL2Z8g3pnWuoVi1WL/5r9ymib+sTI5wt1zWpzqiP3xdOIN7PXnQBsoqg==
            -----END PUBLIC KEY-----
            """.trimIndent(),
        )

        fun trustedKeys(): List<EcPublicKey> = TRUSTED_KEYS.map { EcPublicKey.fromPem(it) }

        suspend fun sign(pack: ZkTemplatePack, key: AsymmetricKey): String =
            signJws(buildJsonObject { put("alg", "ES256"); put("typ", TYP) }, pack.payload(), key)

        /**
         * Verifies [jws] with one of [keys] and reads it; a pack older than [minimumVersion] is refused, so a stale
         * copy cannot bring back a template that was withdrawn.
         */
        suspend fun verify(jws: String, keys: List<EcPublicKey>, minimumVersion: Long = 0): ZkTemplatePack {
            if (keys.isEmpty()) throw ProtocolException("unavailable", "這個版本尚未設定版型簽章金鑰")
            val parsed = Jws.parse(jws.trim())
            if (parsed.typ != TYP || parsed.alg != "ES256") throw ProtocolException("invalid_templates", "Not a template pack")
            if (keys.none { k -> runCatching { parsed.verify(VerificationKey.Ec(k)) }.isSuccess }) {
                throw ProtocolException("invalid_templates", "版型包的簽章不是本專案的發布金鑰")
            }
            val pack = read(parsed.payload)
            if (pack.version < minimumVersion) throw ProtocolException("stale_templates", "版型包比已安裝的版本舊")
            return pack
        }

        fun read(o: JsonObject): ZkTemplatePack {
            fun bad(what: String): Nothing = throw ProtocolException("invalid_templates", "Malformed template pack: $what")
            if ((o["v"] as? JsonPrimitive)?.content != "1") bad("v")
            val version = (o["version"] as? JsonPrimitive)?.content?.toLongOrNull()?.takeIf { it > 0 } ?: bad("version")
            val iat = (o["iat"] as? JsonPrimitive)?.content?.toLongOrNull() ?: bad("iat")
            val zktls = (o["zktls"] as? JsonArray ?: JsonArray(emptyList())).map { (it as? JsonObject)?.let(ZkTlsProfile::parse) ?: bad("zktls") }
            if (zktls.map { it.id }.toSet().size != zktls.size) bad("repeated zktls id")
            val zkpdf = (o["zkpdf"] as? JsonArray ?: JsonArray(emptyList())).map { it as? JsonObject ?: bad("zkpdf") }
            if (zkpdf.any { it.str("id") == null }) bad("zkpdf id")
            return ZkTemplatePack(version, Instant.fromEpochSeconds(iat), zktls, zkpdf)
        }
    }
}

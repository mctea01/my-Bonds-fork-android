package diw.wallet.core.did

import diw.wallet.core.jose.publicJwk
import diw.wallet.core.util.Jcs
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.EcPublicKeyOkp
import org.multipaz.util.toBase64Url

/** Holder identifiers derived from a public key: did:jwk, did:key (multicodec p256-pub, ed25519-pub, jwk_jcs-pub). */
object DidKeys {
    /** JWK with only the members that identify the key, in RFC 8785 order. */
    fun canonicalJwk(jwk: JsonObject): JsonObject {
        val p = publicJwk(jwk)
        return when (p.str("kty")) {
            "EC" -> buildJsonObject { put("crv", p.str("crv")); put("kty", "EC"); put("x", p.str("x")); put("y", p.str("y")) }
            "OKP" -> buildJsonObject { put("crv", p.str("crv")); put("kty", "OKP"); put("x", p.str("x")) }
            "RSA" -> buildJsonObject { put("e", p.str("e")); put("kty", "RSA"); put("n", p.str("n")) }
            else -> throw ProtocolException("invalid_key", "Unsupported kty for DID")
        }
    }

    suspend fun didJwk(key: EcPublicKey): String = "did:jwk:" + Jcs.canonicalBytes(canonicalJwk(key.toJwk())).toBase64Url()

    /** did:key with multicodec 0xEB51 (jwk_jcs-pub): the JCS form of the JWK, as TWDIW uses. */
    suspend fun didKeyJwkJcs(key: EcPublicKey): String =
        "did:key:z" + Base58.encode(varint(0xeb51) + Jcs.canonicalBytes(canonicalJwk(key.toJwk())))

    /** did:key with the curve's own multicodec (p256-pub 0x1200, p384-pub 0x1201, ed25519-pub 0xed). */
    fun didKey(key: EcPublicKey): String = when (key) {
        is EcPublicKeyDoubleCoordinate -> {
            val codec = when (key.curve) {
                EcCurve.P256 -> 0x1200
                EcCurve.P384 -> 0x1201
                EcCurve.P521 -> 0x1202
                else -> throw ProtocolException("invalid_key", "No did:key multicodec for ${key.curve}")
            }
            val prefix = if (key.y.last().toInt() and 1 == 0) 0x02.toByte() else 0x03.toByte()
            "did:key:z" + Base58.encode(varint(codec) + byteArrayOf(prefix) + key.x)
        }
        is EcPublicKeyOkp -> {
            if (key.curve != EcCurve.ED25519) throw ProtocolException("invalid_key", "No did:key multicodec for ${key.curve}")
            "did:key:z" + Base58.encode(varint(0xed) + key.x)
        }
        else -> throw ProtocolException("invalid_key", "Unsupported key type")
    }

    /** Verification method id of a single-key DID (did:jwk uses #0, did:key repeats the multibase value). */
    fun verificationMethod(did: String): String = when {
        did.startsWith("did:jwk:") -> "$did#0"
        did.startsWith("did:key:") -> did + "#" + did.removePrefix("did:key:")
        else -> did
    }

    internal fun varint(value: Int): ByteArray {
        val out = mutableListOf<Byte>()
        var v = value
        while (true) {
            val b = v and 0x7f
            v = v ushr 7
            if (v == 0) { out += b.toByte(); break }
            out += (b or 0x80).toByte()
        }
        return out.toByteArray()
    }
}

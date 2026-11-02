package diw.wallet.app

import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.profile.twdiw.TwdiwApplicationKey
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TwdiwBuildKeyTest {
    @Test
    fun buildPairImportsIntoRuntimeAndSigns() = runBlocking<Unit> {
        val key = TwdiwApplicationKey.fromPem(
            "-----BEGIN PRIVATE KEY-----\n${BuiltInTwdiwApplicationKey.privateKeyPkcs8Base64}\n-----END PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----\n${BuiltInTwdiwApplicationKey.publicKeySpkiBase64}\n-----END PUBLIC KEY-----",
        )
        assertEquals(DocCryptoUtil.hex(PlatformCrypto.sha256(BuiltInTwdiwApplicationKey.publicKeySpkiBase64.encodeToByteArray())), key.keyId)
        assertTrue(BuiltInTwdiwApplicationKey.source in setOf("generated", "provided"))
        val jwt = signJws(buildJsonObject { put("alg", "ES256"); put("typ", "JWT") },
            buildJsonObject { put("test", true) }, key.signingKey)
        Jws.parse(jwt).verify(VerificationKey.Ec(key.publicKey))
    }
}

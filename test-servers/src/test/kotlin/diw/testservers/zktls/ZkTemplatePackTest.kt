package diw.testservers.zktls

import diw.testservers.tools.TemplatePackTool
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zk.ZkTemplatePack
import diw.wallet.core.zktls.ZkTlsProfile
import kotlinx.coroutines.runBlocking
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.multipaz.crypto.EcPublicKey
import java.io.File
import java.io.StringWriter
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The release template pack: built from a folder, signed with the release key, refused when stale or foreign. */
class ZkTemplatePackTest {
    private fun keys(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun pem(o: Any): String = StringWriter().also { w -> JcaPEMWriter(w).use { it.writeObject(o) } }.toString()

    private fun folder(): File {
        val dir = Files.createTempDirectory("zk-templates").toFile()
        File(dir, "zktls").mkdirs()
        File(dir, "zkpdf").mkdirs()
        val profile = DiwJson.encodeToJsonElement(ZkTlsProfile.serializer(), ZkTlsRecordPage.profile(443, "record.example"))
        File(dir, "zktls/record.json").writeText(profile.toString())
        File(dir, "zkpdf/sample.json").writeText("""{"id":"example.student-status/1","note":"layout only"}""")
        return dir
    }

    @Test
    fun signedPackRoundTrip() = runBlocking {
        val pair = keys()
        val pack = TemplatePackTool.build(folder(), version = 1_800_000_000)
        val jws = TemplatePackTool.sign(pack, TemplatePackTool.privateKey(pem(pair.private)))
        val trusted = listOf(EcPublicKey.fromPem(pem(pair.public)))
        val read = ZkTemplatePack.verify(jws, trusted)
        assertEquals(1_800_000_000, read.version)
        assertEquals(listOf(ZkTlsRecordPage.PROFILE_ID), read.zktls.map { it.id })
        assertEquals(1, read.zkpdf.size)
        // A pack older than the installed one is refused; another key is refused.
        assertFailsWith<ProtocolException> { ZkTemplatePack.verify(jws, trusted, minimumVersion = 1_800_000_001) }
        assertFailsWith<ProtocolException> { ZkTemplatePack.verify(jws, listOf(EcPublicKey.fromPem(pem(keys().public)))) }
        assertFailsWith<ProtocolException> { ZkTemplatePack.verify(jws, emptyList()) }
    }

    @Test
    fun releaseKeyIsPinned() {
        val keys = ZkTemplatePack.trustedKeys()
        assertTrue(keys.isNotEmpty())
        assertTrue(keys.all { it.curve == org.multipaz.crypto.EcCurve.P256 })
    }

    @Test
    fun malformedTemplateStopsTheBuild() {
        val dir = folder()
        File(dir, "zktls/bad.json").writeText("""{"id":"Bad Id","title":"x","host":"x","request":{"path":"/"},"status":{"reveal":"a","success":"a"},"fields":[]}""")
        val e = assertFailsWith<IllegalArgumentException> { TemplatePackTool.build(dir) }
        assertTrue(e.message!!.startsWith("bad.json"))
    }

    @Test
    fun repositoryTemplatesBuild() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "templates").isDirectory }
        TemplatePackTool.build(File(root, "templates"))
    }
}

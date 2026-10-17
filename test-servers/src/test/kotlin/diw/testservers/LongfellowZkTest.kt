package diw.testservers

import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.zk.LongfellowZk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.Simple
import org.multipaz.cbor.buildCborMap
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.Tstr
import org.multipaz.mdoc.zkp.ZkDocument
import kotlinx.io.bytestring.ByteString
import org.multipaz.util.toBase64Url
import kotlin.time.Duration.Companion.minutes
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.util.fromBase64Url
import kotlin.test.*

class LongfellowZkTest {
    @Test
    fun dcqlAgeProofContainsNoMso() = runBlocking<Unit> {
        val zk = LongfellowZk(System.getProperty("os.name"))
        org.junit.jupiter.api.Assumptions.assumeTrue(zk.unavailableReason == null)
        val servers = TestServers("http://localhost:8080", TestPki.create()).init()
        val wallet = WalletFixture(zkSystemRepository = zk.repository).init(servers.pki)
        try {
            wallet.issueMdl(servers.pki)
            val origin = "https://verifier.example"
            val (session, protocol, data) = servers.verifier.createDcApi(origin, signed = false, encrypted = false, dcql = zk.ageOver18Query())
            val request = wallet.holder.resolveDcApi(protocol, data, origin)
            val outcome = wallet.holder.respondDefault(wallet.holder.prepare(request))
            assertTrue(outcome is PresentationOutcome.DcApi)
            val encoded = outcome.data.getValue("vp_token").jsonObject.getValue("age").jsonArray.single().jsonPrimitive.content.fromBase64Url()
            val item = Cbor.decode(encoded)
            assertFalse(item.hasKey("documents"))
            val document = DeviceResponse.fromDataItem(item).zkDocuments.single()
            assertEquals(setOf("age_over_18"), document.documentData.issuerSigned.getValue("org.iso.18013.5.1").keys)
            assertTrue(document.documentData.issuerSigned.getValue("org.iso.18013.5.1").getValue("age_over_18").asBoolean)
            val result = servers.verifier.receiveDcApi(session.id, outcome.data, origin)
            assertNull(result.error)
            assertTrue(result.passed, result.credentials.flatMap { it.checks }.joinToString { "${it.name}:${it.status}" })
            assertEquals("mso_mdoc_zk", result.credentials.single().format)
            assertTrue(result.testEnvironmentOnly)
            // Parse the disclosed structure, not a byte substring that could occur randomly in a proof.
            val publicKeys = document.documentData.toDataItem().asMap.keys.map { it.asTstr }.toSet()
            assertFalse("issuerAuth" in publicKeys || "mso" in publicKeys || "deviceKeyInfo" in publicKeys)
            assertTrue(document.documentData.deviceSigned.isEmpty())
            suspend fun rejects(changed: ZkDocument) {
                val response = buildCborMap {
                    item.asMap.forEach { (key, value) ->
                        put(key, if (key == Tstr("zkDocuments")) buildCborArray { add(changed.toDataItem()) } else value)
                    }
                }
                val changedOutcome = buildJsonObject {
                    put("vp_token", buildJsonObject { putJsonArray("age") { add(Cbor.encode(response).toBase64Url()) } })
                }
                assertFalse(servers.verifier.receiveDcApi(session.id, changedOutcome, origin).passed)
            }
            val bytes = document.proof.toByteArray().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            rejects(document.copy(proof = ByteString(bytes)))
            rejects(document.copy(documentData = document.documentData.copy(issuerSigned = mapOf(
                "org.iso.18013.5.1" to mapOf("age_over_18" to Simple.FALSE)))))
            rejects(document.copy(documentData = document.documentData.copy(docType = "wrong.type")))
            rejects(document.copy(documentData = document.documentData.copy(timestamp = document.documentData.timestamp - 10.minutes)))
            rejects(document.copy(documentData = document.documentData.copy(zkSystemSpecId = "unknown")))
            rejects(document.copy(documentData = document.documentData.copy(deviceSigned = mapOf("extra" to mapOf("unproven" to Simple.TRUE)))))
            assertFalse(servers.presentationVerifier.verifyDcApi(outcome.data, session.session.copy(nonce = "different-nonce"), origin).passed)

        } finally {
            wallet.httpClient.close(); servers.httpClient.close()
        }
    }

    @Test
    fun encryptedDirectPostAgeProof() = runBlocking<Unit> {
        org.junit.jupiter.api.Assumptions.assumeFalse(System.getProperty("os.name").startsWith("Windows", ignoreCase = true))
        val port = java.net.ServerSocket(0).use { it.localPort }
        val servers = TestServers("http://localhost:$port", TestPki.create()).init()
        val server = servers.start(port, wait = false)
        val wallet = WalletFixture(zkSystemRepository = servers.longfellow.repository).init(servers.pki)
        try {
            wallet.issueMdl(servers.pki)
            val (session, uri) = servers.verifier.create(VerifierSessionRequest(dcql = servers.longfellow.ageOver18Query()))
            val prepared = wallet.holder.prepare(wallet.holder.resolveUri(uri))
            assertTrue(wallet.holder.respondDefault(prepared) is PresentationOutcome.Posted)
            val result = assertNotNull(session.result)
            assertTrue(result.passed)
            assertEquals("mso_mdoc_zk", result.credentials.single().format)
        } finally {
            server.stop(100, 500); wallet.httpClient.close(); servers.httpClient.close()
        }
    }

    @Test
    fun circuitParametersArePinnedAndDefensivelyCopied() = runBlocking<Unit> {
        val zk = LongfellowZk(System.getProperty("os.name"))
        org.junit.jupiter.api.Assumptions.assumeTrue(zk.unavailableReason == null)
        val spec = zk.specs(1).first()
        val system = assertNotNull(zk.repository?.lookup(spec.system))
        val claims = listOf(org.multipaz.request.MdocRequestedClaim(
            docType = "org.iso.18013.5.1.mDL", namespaceName = "org.iso.18013.5.1",
            dataElementName = "age_over_18", intentToRetain = false))
        assertNotNull(system.getMatchingSystemSpec(listOf(spec), claims))
        spec.addParam("block_enc_sig", 1L)
        assertNull(system.getMatchingSystemSpec(listOf(spec), claims))
        assertNotNull(system.getMatchingSystemSpec(zk.specs(1), claims))
        assertNull(system.getMatchingSystemSpec(zk.specs(1), emptyList()))
    }

    @Test
    fun windowsHasAnExplicitUnavailableReason() = runBlocking<Unit> {
        val zk = LongfellowZk("Windows 11 (JVM)")
        assertNotNull(zk.unavailableReason)
        assertNull(zk.repository)
        assertTrue(zk.specs(1).isEmpty())
        assertFailsWith<IllegalStateException> { zk.ageOver18Query() }
    }

    @Test
    fun missingNativeLibraryDisablesLongfellow() = runBlocking<Unit> {
        // multipaz-longfellow has no library for, e.g., macOS x86_64 or Linux arm64; loading fails with an Error.
        val zk = LongfellowZk("Linux 6.0 (JVM 21)") { "no native library" }
        assertEquals("no native library", zk.unavailableReason)
        assertNull(zk.repository)
        assertTrue(zk.specs(1).isEmpty())
        assertFailsWith<IllegalStateException> { zk.ageOver18Query() }
    }
}

package diw.testservers.zkpassport

import diw.wallet.core.zk.ZkResult
import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.nativeInfo
import diw.wallet.core.zk.native.bindings.zkpassportFacematchCircuits
import diw.wallet.core.zk.native.bindings.zkpassportFacematchStatement
import diw.wallet.core.zkpassport.KeyAttestationInfo
import diw.wallet.core.zkpassport.ZkPassport
import diw.wallet.core.zkpassport.ZkPassportFaceMatchApp
import diw.wallet.core.zkpassport.ZkPassportFaceMatchAttestation
import diw.wallet.core.zkpassport.ZkPassportFaceMatchEvidence
import diw.wallet.core.zkpassport.ZkPassportFaceMatchKind
import diw.wallet.core.zkpassport.ZkPassportFaceMatchRequest
import diw.wallet.core.zkpassport.ZkPassportProver
import diw.wallet.core.zkpassport.ZkPassportRequest
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.Date
import java.util.zip.GZIPInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * FaceMatch with this project's circuits (docs/design/zkpassport.md 5.6). The request and policy forms need no
 * native library. The proofs are made for real on a synthetic document: with the zkPDF assets (their CRS) for the
 * self-declared circuit built into the library, and with `DIW_FACEMATCH_CIRCUITS` (a folder of packaged circuits
 * from `keyattest.py package`) for a key attestation chain of throwaway keys.
 */
class ZkPassportFaceMatchTest {
    private val bc = BouncyCastleProvider()
    private val b64 = Base64.getEncoder()

    private fun tlv(tag: Int, value: ByteArray): ByteArray {
        val length = when {
            value.size < 128 -> byteArrayOf(value.size.toByte())
            value.size < 256 -> byteArrayOf(0x81.toByte(), value.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (value.size shr 8).toByte(), value.size.toByte())
        }
        return byteArrayOf(tag.toByte()) + length + value
    }

    // A fictional passport: a zone of made-up values, a photo file of filler bytes, signed by a throwaway key.
    private val dg1 = byteArrayOf(0x61, 0x5B, 0x5F, 0x1F, 0x58) +
        ("P<UTOSPECIMEN<<FACE<MATCH".padEnd(44, '<') + "L898902C36UTO7408122F3001017ZE184226B<<<<<10").encodeToByteArray()
    private val dg2 = tlv(0x75, ByteArray(300) { (it * 7).toByte() })

    private fun sod(): ByteArray {
        val signer = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val name = X500Name("C=UT,O=Test Ministry,CN=Test DSC")
        val certificate = JcaX509v3CertificateBuilder(name, BigInteger.TWO, Date(System.currentTimeMillis() - 86_400_000), Date(System.currentTimeMillis() + 86_400_000_00L), name, signer.public)
            .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signer.private))
        val hashes = ASN1EncodableVector()
        for ((n, file) in listOf(1 to dg1, 2 to dg2)) {
            hashes.add(DERSequence(arrayOf(ASN1Integer(n.toLong()), DEROctetString(MessageDigest.getInstance("SHA-256").digest(file)))))
        }
        val lso = DERSequence(arrayOf(ASN1Integer(0), AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), DERSequence(hashes))).encoded
        val generator = CMSSignedDataGenerator()
        generator.addSignerInfoGenerator(JcaSignerInfoGeneratorBuilder(JcaDigestCalculatorProviderBuilder().setProvider(bc).build())
            .build(JcaContentSignerBuilder("SHA256withRSA").setProvider(bc).build(signer.private), certificate))
        generator.addCertificates(JcaCertStore(listOf(certificate)))
        return tlv(0x77, generator.generate(CMSProcessableByteArray(ASN1ObjectIdentifier("2.23.136.1.1.1"), lso), true).encoded)
    }

    private val job = ZkPassportProver.Job(
        query = buildJsonObject { putJsonObject("facematch") { put("mode", "regular") } },
        domain = "verifier.example", scope = "door", nowSeconds = 1_788_000_000,
    )

    /** The answer of a session before FaceMatch: one document proof and the query result. */
    private val before = ZkPassportProver.Proved(
        proofs = listOf(ZkPassportProver.Proof("disclose_bytes", "00", "", "0x01", "0.22.0", null)),
        messages = listOf(
            "accept" to JsonObject(emptyMap()),
            "proof" to buildJsonObject { put("proof", "00"); put("name", "disclose_bytes"); put("index", 0); put("total", 1) },
            "done" to buildJsonObject { putJsonObject("age") { put("passed", true) } },
        ),
        queryResult = buildJsonObject { putJsonObject("age") { put("passed", true) } },
    )

    private fun crs(): File {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        assertTrue(ZkNative.load(Files.createTempDirectory("diw-facematch").toFile()) is ZkResult.Ok<*>)
        assumeTrue("zkpdf" in nativeInfo().features, "zkPDF backend not built")
        val assets = System.getenv("ZKPDF_ASSETS_DIR")
        assumeTrue(!assets.isNullOrEmpty() && File(assets, "bn254_g1.dat").isFile, "zkPDF assets not installed")
        return File(assets!!)
    }

    private fun prover(crs: File, circuits: File? = null) = ZkPassportProver(
        HttpClient(MockEngine { error("No network expected") }), Files.createTempDirectory("diw-facematch-cache").toFile(), { crs }, { true },
        faceMatchCircuit = circuits?.let { dir -> { name -> GZIPInputStream(File(dir, "$name.json.gz").inputStream()).use { it.readBytes().decodeToString() } } },
    )

    /** The public values of a proof message's hex: 32 bytes each, before the proof itself. */
    private fun public(proof: String, index: Int) = BigInteger(proof.substring(index * 64, index * 64 + 64), 16)

    private fun checkAdded(proved: ZkPassportProver.Proved, name: String) {
        assertEquals(listOf("disclose_bytes", name), proved.proofs.map { it.name })
        assertEquals(listOf("accept", "proof", "proof", "done"), proved.messages.map { it.first })
        val sent = proved.messages.filter { it.first == "proof" }.map { it.second.jsonObject }
        assertEquals(listOf(0, 1), sent.map { it["index"]!!.jsonPrimitive.content.toInt() })
        assertTrue(sent.all { it["total"]!!.jsonPrimitive.content == "2" })
        val pinned = Json.parseToJsonElement(zkpassportFacematchCircuits()).jsonObject["circuits"]!!.jsonObject
        assertEquals(pinned[name], sent[1]["vkeyHash"])
        assertTrue(sent[1]["vkey"]!!.jsonPrimitive.content.isNotEmpty())
        for (result in listOf(proved.queryResult, proved.messages.last().second)) {
            assertEquals("regular", result.jsonObject["facematch"]!!.jsonObject["mode"]!!.jsonPrimitive.content)
            assertTrue("age" in result.jsonObject)
        }
        // The date and scope of the session, and no identifier: the private nullifier stays hidden.
        val proof = proved.proofs.last().proof
        assertEquals(BigInteger.valueOf(job.nowSeconds), public(proof, 1))
        assertEquals(BigInteger.ZERO, public(proof, 6))
    }

    @Test fun requestsNameTheKindsTheyAccept() {
        val app = ZkPassportFaceMatchApp("diw.wallet.app", listOf("AB".repeat(32)))
        val face = ZkPassportFaceMatchRequest(strict = true, keyAttestation = true, selfDeclared = true, apps = listOf(app))
        val request = ZkPassportRequest(domain = "verifier.example", name = "Door", purpose = "Entry", faceMatch = face)
        val query = ZkPassport.query(request)
        assertEquals("strict", query["facematch"]!!.jsonObject["mode"]!!.jsonPrimitive.content)
        assertEquals(listOf("keyattest", "self"), query["facematch"]!!.jsonObject["diw"]!!.jsonArray.map { it.jsonPrimitive.content })

        val incoming = ZkPassport.parseLink(ZkPassport.url(request, "02" + "11".repeat(32), 1_788_000_000))!!
        assertEquals("strict", incoming.faceMatchMode)
        assertEquals(listOf(ZkPassportFaceMatchKind.KEY_ATTESTATION, ZkPassportFaceMatchKind.SELF), incoming.faceMatchKinds)

        // zkPassport's SDK names no kind of this project, and a request without FaceMatch asks for none.
        val official = ZkPassport.parseLink(ZkPassport.url(request.copy(faceMatch = ZkPassportFaceMatchRequest()), "02" + "11".repeat(32), 1_788_000_000))!!
        assertEquals("regular", official.faceMatchMode)
        assertTrue(official.faceMatchKinds.isEmpty())
        assertNull(ZkPassport.query(request.copy(faceMatch = null))["facematch"])
        assertNull(ZkPassport.parseLink(ZkPassport.url(request.copy(faceMatch = null), "02" + "11".repeat(32), 1_788_000_000))!!.faceMatchMode)

        val policy = ZkPassport.faceMatchPolicy(face)
        assertEquals(listOf("official", "keyattest", "self"), policy["accept"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals("ab".repeat(32), policy["apps"]!!.jsonArray[0].jsonObject["signers"]!!.jsonArray[0].jsonPrimitive.content)
        assertEquals(listOf("official"), ZkPassport.faceMatchPolicy(ZkPassportFaceMatchRequest())["accept"]!!.jsonArray.map { it.jsonPrimitive.content })

        val report = """{"verified":true,"errors":[],"facematch":{"kind":"keyattest","mode":"regular","environment":"self_signed","appId":"diw.wallet.app","signerDigest":"ab"}}"""
        val read = ZkPassport.result(report).faceMatch!!
        assertEquals(ZkPassportFaceMatchKind.KEY_ATTESTATION, read.kind)
        assertEquals("self_signed", read.environment)
        assertEquals("diw.wallet.app", read.appId)
        assertNull(ZkPassport.result("""{"verified":true,"errors":[],"facematch":null}""").faceMatch)
    }

    /** The wallet reads the app and the key's level from an attestation the way the circuits do. */
    @Test fun anAttestationNamesItsAppAndKeyLevel() {
        val fixtures = Json.parseToJsonElement(File("../native/diw-zk-ffi/tests/data/keyattest-chains.json").readText()).jsonArray
        for (fixture in fixtures.map { it.jsonObject }) {
            val chain = fixture["chain"]!!.jsonArray.map { Base64.getDecoder().decode(it.jsonPrimitive.content) }
            val stated = assertNotNull(KeyAttestationInfo.read(chain.first()))
            assertEquals(fixture["app_id"]!!.jsonPrimitive.content, stated.packageName)
            assertEquals(fixture["signer_digest"]!!.jsonPrimitive.content, stated.signerDigest)
            assertTrue(stated.provable)
            // A certificate without the extension (an intermediate) is not an attestation.
            assertNull(KeyAttestationInfo.read(chain[1]))
        }
        assertNull(KeyAttestationInfo.read(byteArrayOf(0x30, 0x00)))
    }

    @Test fun aSelfDeclaredProofJoinsTheAnswer() = runBlocking<Unit> {
        val crs = crs()
        val chip = ZkPassportProver.Chip(sod(), dg1, dg2)
        val face = ZkPassportFaceMatchEvidence(strict = false, appId = "diw.wallet.app", attestation = null)
        val proved = prover(crs).faceMatch(before, face, chip, ZkPassportProver.salt(), job, "0.22.0", crs.absolutePath)
        checkAdded(proved, "diw_facematch_self")
        val committed = proved.proofs.last().committedInputs!!.jsonObject["facematch"]!!.jsonObject
        assertEquals("diw.wallet.app", committed["appId"]!!.jsonPrimitive.content)
        assertEquals("regular", committed["mode"]!!.jsonPrimitive.content)

        // Another photo than the one the document's security object lists is refused before any proof.
        val other = ZkPassportProver.Chip(chip.sod, dg1, dg2 + byteArrayOf(1))
        assertEquals(
            "facematch:dg2_mismatch",
            assertFailsWith<ZkPassportProver.Failure> { prover(crs).faceMatch(before, face, other, ZkPassportProver.salt(), job, "0.22.0", crs.absolutePath) }.code,
        )
    }

    @Test fun aKeyAttestedProofJoinsTheAnswer() = runBlocking<Unit> {
        val crs = crs()
        val circuits = System.getenv("DIW_FACEMATCH_CIRCUITS")?.let(::File)
        assumeTrue(circuits?.isDirectory == true, "Set DIW_FACEMATCH_CIRCUITS to the packaged circuits")
        val fixture = Json.parseToJsonElement(File("../native/diw-zk-ffi/tests/data/keyattest-chains.json").readText()).jsonArray[0].jsonObject
        val name = fixture["name"]!!.jsonPrimitive.content
        assumeTrue(File(circuits, "$name.json.gz").isFile, "$name is not packaged")
        val decoder = Base64.getDecoder()
        val chip = ZkPassportProver.Chip(sod(), dg1, dg2)

        // The statement of a comparison on this document, signed by the fixture's keystore key.
        val statement = Json.parseToJsonElement(zkpassportFacematchStatement(buildJsonObject {
            put("sod", b64.encodeToString(diw.wallet.core.document.mrtd.BerToDer.sod(chip.sod)))
            put("dg2", b64.encodeToString(dg2))
            put("app_version", "1.0")
            put("mode", "regular")
            putJsonArray("embedding") { repeat(128) { add(JsonPrimitive(it / 128f)) } }
            put("cosine", 81_000_000)
            put("threshold", 60_000_000)
        }.toString())).jsonObject
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(decoder.decode(fixture["credential_key"]!!.jsonPrimitive.content)))
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(key)
            update(decoder.decode(statement["toSign"]!!.jsonPrimitive.content))
        }.sign()
        val attestation = ZkPassportFaceMatchAttestation(
            clientData = decoder.decode(statement["clientData"]!!.jsonPrimitive.content),
            chain = fixture["chain"]!!.jsonArray.map { decoder.decode(it.jsonPrimitive.content) },
            signature = signature,
            signerDigest = fixture["signer_digest"]!!.jsonPrimitive.content,
        )
        val face = ZkPassportFaceMatchEvidence(strict = false, appId = fixture["app_id"]!!.jsonPrimitive.content, attestation = attestation)
        val proved = prover(crs, circuits).faceMatch(before, face, chip, ZkPassportProver.salt(), job, "0.22.0", crs.absolutePath)
        checkAdded(proved, name)
        val committed = proved.proofs.last().committedInputs!!.jsonObject["facematch"]!!.jsonObject
        // The fixture's device is locked with a verified system.
        assertEquals("production", committed["environment"]!!.jsonPrimitive.content)
        assertEquals(attestation.signerDigest, committed["signerDigest"]!!.jsonPrimitive.content)
        assertTrue(committed["rootKeyLeaf"]!!.jsonPrimitive.content.startsWith("0x"))

        // A statement the key did not sign has no valid witness.
        val forged = ZkPassportFaceMatchEvidence(false, face.appId, ZkPassportFaceMatchAttestation(attestation.clientData.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }, attestation.chain, signature, attestation.signerDigest))
        val code = assertFailsWith<ZkPassportProver.Failure> { prover(crs, circuits).faceMatch(before, forged, chip, ZkPassportProver.salt(), job, "0.22.0", crs.absolutePath) }.code
        assertTrue(code.startsWith("proof:$name"), code)
    }
}

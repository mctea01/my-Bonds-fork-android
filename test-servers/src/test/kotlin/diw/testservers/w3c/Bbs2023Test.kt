package diw.testservers.w3c

import diw.wallet.core.did.DidResolver
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.w3c.bbs.Bbs
import diw.wallet.core.w3c.bbs.Bbs2023
import diw.wallet.core.w3c.bbs.BbsBaseProof
import diw.wallet.core.w3c.bbs.BbsDerivedProof
import diw.wallet.core.w3c.bbs.BbsFeature
import diw.wallet.core.w3c.bbs.BbsHolderSecrets
import diw.wallet.core.w3c.ld.JsonLd
import diw.wallet.core.w3c.ld.LdContextLoader
import diw.wallet.core.w3c.sd.SdPrimitives
import diw.wallet.core.zk.native.ZkNative
import io.ktor.client.HttpClient
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.int
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Instant

/** bbs-2023 against the W3C Data Integrity BBS Cryptosuites test vectors (resources/bbs-2023, see its README). */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Bbs2023Test {
    private val jsonLd = JsonLd(LdContextLoader.Offline)
    private val suite = Bbs2023(jsonLd)

    private fun text(path: String) = Bbs2023Test::class.java.getResourceAsStream("/bbs-2023/$path")!!.use { it.readBytes().decodeToString() }
    private fun json(path: String): JsonElement = Json.parseToJsonElement(text(path))
    private fun obj(path: String) = json(path).jsonObject
    private fun strings(path: String) = json(path).jsonArray.map { it.jsonPrimitive.content }
    private fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun hexOf(path: String, key: String) = hex(obj(path)[key]!!.jsonPrimitive.content)

    private val keys by lazy { obj("BBSKeyMaterial.json") }
    private val sk by lazy { hex(keys["privateKeyHex"]!!.jsonPrimitive.content) }
    private val pk by lazy { hex(keys["publicKeyHex"]!!.jsonPrimitive.content) }
    private val hmacKey by lazy { hex(keys["hmacKeyString"]!!.jsonPrimitive.content) }
    private val ph by lazy { hexOf("BBSDeriveMaterial.json", "presentationHeaderHex") }
    private val domain by lazy { obj("FeatureInputs/verifierInfo.json")["verifierId"]!!.jsonPrimitive.content }
    private val holderSecret by lazy { hexOf("FeatureInputs/holderSecret.json", "holderSecretHex") }
    private val proverNym by lazy { hexOf("FeatureInputs/proverNym.json", "proverNymHex") }
    private val entropy by lazy { hexOf("FeatureInputs/signerNymEntropy.json", "signerNymEntropyHex") }

    @BeforeAll fun loadNative() {
        val packaged = ZkNative::class.java.getResource("/zk/native") != null
        assumeTrue(packaged || System.getProperty("diw.zkNative") == "require", "ZK native library not built")
        ZkNative.load(Files.createTempDirectory("diw-bbs").toFile())
        assertTrue(Bbs.available())
    }

    private fun proofOptions(dir: String): Pair<String, Instant> {
        val config = obj("${dir}addProofConfig.json")
        return config["verificationMethod"]!!.jsonPrimitive.content to Instant.parse(config["created"]!!.jsonPrimitive.content)
    }

    private fun proofValue(doc: JsonObject) = doc["proof"]!!.jsonObject["proofValue"]!!.jsonPrimitive.content

    private fun labelMap(disclosure: JsonObject): Map<String, String> =
        disclosure["labelMap"]!!.jsonObject["value"]!!.jsonArray.associate { it.jsonArray[0].jsonPrimitive.content to it.jsonArray[1].jsonPrimitive.content }

    private fun ints(e: JsonElement?) = e!!.jsonArray.map { it.jsonPrimitive.int }

    private fun withoutProof(doc: JsonObject) = JsonObject(doc - "proof")

    @Test fun didKeyResolvesBlsMultikey() = runBlocking<Unit> {
        val vm = obj("addSignedSDBase.json")["proof"]!!.jsonObject["verificationMethod"]!!.jsonPrimitive.content
        val key = DidResolver(HttpClient()).resolveKey(vm.substringBefore('#'), vm).key
        assertIs<VerificationKey.Bls12381G2>(key)
        assertContentEquals(pk, key.publicKey)
    }

    @Test fun canonicalizationMatchesVectors() = runBlocking<Unit> {
        val doc = obj("windDoc.json")
        assertEquals(strings("addBaseDocCanon.json"), jsonLd.canonicalize(doc).nquads)
        val (_, relabelled) = SdPrimitives.labelReplacementCanonicalize(jsonLd.toRdf(doc), SdPrimitives.shuffledIdLabelMapFunction(hmacKey))
        assertEquals(strings("addBaseDocHMACCanon.json"), relabelled)
        assertEquals(text("addProofConfigCanon.txt").trimEnd('\n') + "\n", jsonLd.canonicalize(obj("addProofConfig.json")).text())
    }

    /** [document] is signed as the vectors' base document (prCredUnsigned.json differs from the one signed in prc/). */
    private fun baseline(dir: String, mandatory: String, selective: String) = runBlocking<Unit> {
        val (vm, created) = proofOptions(dir)
        val expected = obj("${dir}addSignedSDBase.json")
        val signed = suite.sign(withoutProof(expected), sk, pk, vm, strings(mandatory), created = created, hmacKey = hmacKey)
        assertEquals(proofValue(expected), proofValue(signed))
        suite.verifyBase(signed, pk)
        suite.verifyBase(expected, pk)

        val reveal = obj("${dir}derivedRevealDocument.json")
        val verified = suite.verifyDerived(reveal, pk)
        assertEquals(BbsFeature.BASELINE, verified.feature)
        assertEquals(withoutProof(reveal), verified.document)

        val derived = suite.derive(signed, strings(selective), ph)
        assertEquals(withoutProof(reveal), withoutProof(derived))
        val disclosure = obj("${dir}derivedDisclosureData.json")
        val parsed = BbsDerivedProof.parse(proofValue(derived))
        assertEquals(labelMap(disclosure), parsed.labelMap)
        assertEquals(ints(disclosure["mandatoryIndexes"]), parsed.mandatoryIndexes)
        assertEquals(ints(disclosure["adjSelectiveIndexes"]), parsed.selectiveIndexes)
        assertContentEquals(ph, parsed.presentationHeader)
        suite.verifyDerived(derived, pk)
        // A fresh derivation is unlinkable: same disclosure, different proof bytes.
        assertNotEquals(proofValue(derived), proofValue(suite.derive(signed, strings(selective), ph)))
        assertFailsWith<ProtocolException> { suite.verifyDerived(tamper(derived), pk) }
        assertFailsWith<ProtocolException> { suite.verifyDerived(derived, Bbs.generateKeyPair(ByteArray(32) { 7 }).publicKey) }
    }

    /** Changes the first string value found under credentialSubject. */
    private fun tamper(doc: JsonObject): JsonObject {
        fun change(e: JsonElement): Pair<JsonElement, Boolean> = when (e) {
            is JsonObject -> {
                var done = false
                JsonObject(e.mapValues { (k, v) -> if (done || k == "id" || k == "type") v else change(v).also { done = it.second }.first }) to done
            }
            is JsonArray -> {
                var done = false
                JsonArray(e.map { v -> if (done) v else change(v).also { done = it.second }.first }) to done
            }
            is JsonPrimitive -> if (e.isString) JsonPrimitive(e.content + "x") to true else e to false
        }
        val subject = doc["credentialSubject"]!!
        return JsonObject(doc + ("credentialSubject" to change(subject).first))
    }

    @Test fun windsurfBaseline() = baseline("", "windMandatory.json", "windSelective.json")

    @Test fun permanentResidentCardBaseline() = baseline("prc/", "prCredMandatory.json", "prCredSelective.json")

    @Test fun anonymousHolderBinding() = runBlocking<Unit> {
        val (vm, created) = proofOptions("HolderBinding/")
        val commitment = obj("HolderBinding/commitmentInfo.json")
        val signed = suite.sign(
            obj("FeatureInputs/license.json"), sk, pk, vm, strings("FeatureInputs/licenseMandatory.json"), BbsFeature.ANONYMOUS_HOLDER_BINDING,
            commitmentWithProof = hex(commitment["commitmentWithProof"]!!.jsonPrimitive.content), created = created, hmacKey = hmacKey,
        )
        assertEquals(proofValue(obj("HolderBinding/addSignedSDBase.json")), proofValue(signed))
        val secrets = BbsHolderSecrets(BbsFeature.ANONYMOUS_HOLDER_BINDING, hex(commitment["secretProverBlind"]!!.jsonPrimitive.content), holderSecret)
        suite.verifyBase(signed, pk, secrets)
        assertFailsWith<ProtocolException> { suite.verifyBase(signed, pk, BbsHolderSecrets(BbsFeature.ANONYMOUS_HOLDER_BINDING, secrets.secretProverBlind, ByteArray(32) { 1 })) }
        assertFailsWith<ProtocolException> { suite.verifyBase(signed, pk) }

        val reveal = obj("HolderBinding/derivedRevealDocument.json")
        assertEquals(BbsFeature.ANONYMOUS_HOLDER_BINDING, suite.verifyDerived(reveal, pk).feature)
        val derived = suite.derive(signed, strings("FeatureInputs/licenseSelective.json"), ph, secrets)
        assertEquals(withoutProof(reveal), withoutProof(derived))
        val disclosure = obj("HolderBinding/derivedDisclosureData.json")
        val parsed = BbsDerivedProof.parse(proofValue(derived))
        assertEquals(labelMap(disclosure), parsed.labelMap)
        assertEquals(disclosure["lengthBBSMessages"]!!.jsonPrimitive.int, parsed.signerMessageCount)
        suite.verifyDerived(derived, pk)
        assertFailsWith<ProtocolException> { suite.derive(signed, strings("FeatureInputs/licenseSelective.json"), ph) }
    }

    @Test fun pseudonymVectors() = runBlocking<Unit> {
        val (vm, created) = proofOptions("HolderBinding/")
        for ((dir, feature) in listOf("Pseudonym/" to BbsFeature.PSEUDONYM, "PseudonymHB/" to BbsFeature.HOLDER_BINDING_PSEUDONYM)) {
            val commitment = obj("${dir}commitmentInfo.json")
            val signed = suite.sign(
                obj("FeatureInputs/license.json"), sk, pk, vm, strings("FeatureInputs/licenseMandatory.json"), feature,
                commitmentWithProof = hex(commitment["commitmentWithProof"]!!.jsonPrimitive.content), signerNymEntropy = entropy,
                created = created, hmacKey = hmacKey,
            )
            val vectorBase = BbsBaseProof.parse(proofValue(obj("${dir}addSignedSDBase.json")))
            val ours = BbsBaseProof.parse(proofValue(signed))
            assertContentEquals(vectorBase.signature, ours.signature)
            assertContentEquals(vectorBase.header, ours.header)
            assertContentEquals(entropy, ours.signerNymEntropy)

            val secrets = BbsHolderSecrets(feature, hex(commitment["secretProverBlind"]!!.jsonPrimitive.content),
                if (feature.holderBound) holderSecret else null, proverNym)
            val finalized = suite.verifyBase(signed, pk, secrets).second!!
            val expectedNym = obj("${dir}nymSecret.json")["nymSecretHex"]!!.jsonPrimitive.content.padStart(64, '0')
            assertContentEquals(hex(expectedNym), finalized.nymSecret)

            // The vectors' derived proofs omit nym_domain, so the verifier supplies its own.
            val reveal = obj("${dir}derivedRevealDocument.json")
            val vectorVerified = suite.verifyDerived(reveal, pk, domain)
            val disclosure = obj("${dir}derivedDisclosureData.json")
            assertContentEquals(hex(disclosure["pseudonym"]!!.jsonPrimitive.content), vectorVerified.pseudonym)
            assertFailsWith<ProtocolException> { suite.verifyDerived(reveal, pk, "https://other.example/") }

            val derived = suite.derive(signed, strings("FeatureInputs/licenseSelective.json"), ph, finalized, domain)
            assertEquals(withoutProof(reveal), withoutProof(derived))
            val parsed = BbsDerivedProof.parse(proofValue(derived))
            assertEquals(domain, parsed.nymDomain)
            assertContentEquals(vectorVerified.pseudonym, parsed.pseudonym)
            val verified = suite.verifyDerived(derived, pk, domain)
            assertEquals(feature, verified.feature)
            assertFailsWith<ProtocolException> { suite.verifyDerived(derived, pk, "https://other.example/") }
            assertFailsWith<ProtocolException> { suite.derive(signed, strings("FeatureInputs/licenseSelective.json"), ph, finalized) }
        }
    }

    @Test fun freshKeysAllFeatures() = runBlocking<Unit> {
        val issuer = Bbs.generateKeyPair(Bbs.randomScalar() + Bbs.randomScalar())
        val did = "did:example:issuer#key-1"
        val doc = obj("windDoc.json")
        for (feature in BbsFeature.entries) {
            val (secrets, commitment) = if (feature == BbsFeature.BASELINE) null to null else BbsHolderSecrets.create(feature)
            val signed = suite.sign(doc, issuer.secretKey, issuer.publicKey, did, strings("windMandatory.json"), feature, commitment)
            val (_, finalized) = suite.verifyBase(signed, issuer.publicKey, secrets)
            val a = suite.derive(signed, strings("windSelective.json"), ByteArray(0), finalized, if (feature.pseudonymous) "https://a.example" else null)
            val b = suite.derive(signed, strings("windSelective.json"), ByteArray(0), finalized, if (feature.pseudonymous) "https://a.example" else null)
            val va = suite.verifyDerived(a, issuer.publicKey, "https://a.example")
            val vb = suite.verifyDerived(b, issuer.publicKey, "https://a.example")
            assertEquals(feature, va.feature)
            assertNotEquals(proofValue(a), proofValue(b))
            if (feature.pseudonymous) {
                // Same verifier, same pseudonym; another verifier sees an unrelated one.
                assertContentEquals(va.pseudonym, vb.pseudonym)
                val c = suite.derive(signed, strings("windSelective.json"), ByteArray(0), finalized, "https://b.example")
                val vc = suite.verifyDerived(c, issuer.publicKey, "https://b.example")
                assertFalse(va.pseudonym!!.contentEquals(vc.pseudonym!!))
            }
        }
    }


    /**
     * A holder cannot relabel a derived proof as another feature (e.g. a plain pseudonym as holder bound): the number
     * of hidden messages in the BBS proof decides the feature, not the header.
     */
    @Test fun featureHeaderCannotBeRelabelled() = runBlocking<Unit> {
        val issuer = Bbs.generateKeyPair(Bbs.randomScalar() + Bbs.randomScalar())
        val doc = obj("windDoc.json")
        val relabel = mapOf(
            BbsFeature.PSEUDONYM to BbsFeature.HOLDER_BINDING_PSEUDONYM,
            BbsFeature.HOLDER_BINDING_PSEUDONYM to BbsFeature.PSEUDONYM,
            BbsFeature.BASELINE to BbsFeature.ANONYMOUS_HOLDER_BINDING,
            BbsFeature.ANONYMOUS_HOLDER_BINDING to BbsFeature.PSEUDONYM,
        )
        for ((feature, claimed) in relabel) {
            val (secrets, commitment) = if (feature == BbsFeature.BASELINE) null to null else BbsHolderSecrets.create(feature)
            val signed = suite.sign(doc, issuer.secretKey, issuer.publicKey, "did:example:issuer#key-1", strings("windMandatory.json"), feature, commitment)
            val (_, finalized) = suite.verifyBase(signed, issuer.publicKey, secrets)
            val derived = suite.derive(signed, strings("windSelective.json"), ByteArray(0), finalized, "https://a.example")
            val d = BbsDerivedProof.parse(proofValue(derived))
            val forged = BbsDerivedProof(
                claimed, d.bbsProof, d.labelMap, d.mandatoryIndexes, d.selectiveIndexes, d.presentationHeader,
                nymDomain = if (claimed.pseudonymous) "https://a.example" else null,
                pseudonym = d.pseudonym ?: ByteArray(48).also { it[0] = 0xc0.toByte() },
                signerMessageCount = d.signerMessageCount ?: (d.selectiveIndexes.size + (d.bbsProof.size - 272) / 32),
            ).encode()
            val proof = derived["proof"] as JsonObject
            val tampered = JsonObject(derived + ("proof" to JsonObject(proof + ("proofValue" to JsonPrimitive(forged)))))
            // Either the proof fails, or it is read as what it really is (the vectors' 0x09 label on plain pseudonyms).
            val read = runCatching { suite.verifyDerived(tampered, issuer.publicKey, "https://a.example").feature }.getOrNull()
            assertTrue(read == null || read == feature, "$feature relabelled as $claimed was accepted as $read")
        }
    }

    /**
     * Members the contexts do not define would be left out of the signed RDF but still read from the JSON: a derived
     * credential that adds one (through a context mapping it to null, or with no definition) must not verify.
     */
    @Test fun undefinedMembersAreRejected() = runBlocking<Unit> {
        val reveal = obj("HolderBinding/derivedRevealDocument.json")
        suite.verifyDerived(reveal, pk)
        fun withSubjectMember(doc: JsonObject, context: JsonElement): JsonObject {
            val subject = doc["credentialSubject"]!!.jsonObject
            return JsonObject(doc + ("@context" to context) + ("credentialSubject" to JsonObject(subject + ("isAdult" to JsonPrimitive(true)))))
        }
        val nulled = JsonArray(reveal["@context"]!!.jsonArray + Json.parseToJsonElement("{\"isAdult\": null}"))
        assertFailsWith<ProtocolException> { suite.verifyDerived(withSubjectMember(reveal, nulled), pk) }
        val v1 = Json.parseToJsonElement("{\"@context\": [\"https://www.w3.org/2018/credentials/v1\"], \"type\": [\"VerifiableCredential\"], " +
            "\"credentialSubject\": {\"isAdult\": true}}").jsonObject
        assertFailsWith<ProtocolException> { jsonLd.toRdf(v1) }
    }

    /** Byte strings wrapped in CBOR tag 64 (RFC 8746 uint8 typed array) read the same as plain ones. */
    @Test fun tag64ByteStringsAreRead() {
        val base = BbsBaseProof.parse(proofValue(obj("addSignedSDBase.json")))
        fun head(major: Int, n: Int): ByteArray = when {
            n < 24 -> byteArrayOf(((major shl 5) or n).toByte())
            n < 256 -> byteArrayOf(((major shl 5) or 24).toByte(), n.toByte())
            else -> byteArrayOf(((major shl 5) or 25).toByte(), (n shr 8).toByte(), n.toByte())
        }
        fun tagged(b: ByteArray) = byteArrayOf(0xd8.toByte(), 0x40) + head(2, b.size) + b
        val pointers = base.mandatoryPointers.fold(head(4, base.mandatoryPointers.size)) { acc, p -> acc + head(3, p.encodeToByteArray().size) + p.encodeToByteArray() }
        val cbor = byteArrayOf(0xd9.toByte(), 0x5d, 0x02) + head(4, 5) + tagged(base.signature) + tagged(base.header) + tagged(base.publicKey) + tagged(base.hmacKey) + pointers
        val parsed = BbsBaseProof.parse("u" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(cbor))
        assertContentEquals(base.signature, parsed.signature)
        assertContentEquals(base.hmacKey, parsed.hmacKey)
        assertEquals(base.mandatoryPointers, parsed.mandatoryPointers)
    }
}

package diw.wallet.core.w3c.bbs

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.w3c.W3cVc
import diw.wallet.core.w3c.ld.JsonLd
import diw.wallet.core.w3c.ld.Rdfc10
import diw.wallet.core.w3c.sd.SdPrimitives
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * The holder's secrets for an optional-feature credential. [holderSecret] is the committed holder secret (anonymous
 * holder binding), [proverNym] the holder's share of the pseudonym secret; [secretProverBlind] comes from the
 * commitment. [nymSecret] is computed when the base proof is verified.
 */
class BbsHolderSecrets(
    val feature: BbsFeature,
    val secretProverBlind: ByteArray,
    val holderSecret: ByteArray? = null,
    val proverNym: ByteArray? = null,
    val nymSecret: ByteArray? = null,
) {
    val committed: List<ByteArray> get() = if (feature.holderBound) listOf(holderSecret ?: throw ProtocolException("invalid_request", "Holder secret missing")) else emptyList()

    fun withNymSecret(secret: ByteArray) = BbsHolderSecrets(feature, secretProverBlind, holderSecret, proverNym, secret)

    companion object {
        /** New secrets and the commitment the issuer signs over (sent in the credential request). */
        fun create(feature: BbsFeature): Pair<BbsHolderSecrets, ByteArray> {
            require(feature != BbsFeature.BASELINE)
            val holderSecret = if (feature.holderBound) Bbs.randomScalar() else null
            val committed = listOfNotNull(holderSecret)
            return if (feature.pseudonymous) {
                val proverNym = Bbs.randomScalar()
                val c = Bbs.nymCommit(committed, proverNym)
                BbsHolderSecrets(feature, c.secretProverBlind, holderSecret, proverNym) to c.commitmentWithProof
            } else {
                val c = Bbs.commit(committed)
                BbsHolderSecrets(feature, c.secretProverBlind, holderSecret) to c.commitmentWithProof
            }
        }
    }
}

/** The result of verifying a derived (presented) bbs-2023 proof. */
class BbsVerified(
    val document: JsonObject,
    val feature: BbsFeature,
    val verificationMethod: String,
    val pseudonym: ByteArray?,
    val nymDomain: String?,
    val created: Instant?,
)

/**
 * W3C Data Integrity BBS Cryptosuites v1.0, bbs-2023: issuing base proofs, deriving selectively disclosed proofs and
 * verifying them, for all four feature options. Keys are BLS12-381 G2 (Multikey 0xeb01).
 */
class Bbs2023(private val jsonLd: JsonLd = JsonLd.Default) {

    /** 3.3.1 and 3.3.2: adds a base proof to [unsecured]. */
    suspend fun sign(
        unsecured: JsonObject,
        secretKey: ByteArray,
        publicKey: ByteArray,
        verificationMethod: String,
        mandatoryPointers: List<String>,
        feature: BbsFeature = BbsFeature.BASELINE,
        commitmentWithProof: ByteArray? = null,
        signerNymEntropy: ByteArray? = null,
        created: Instant? = Clock.System.now(),
        proofPurpose: String = "assertionMethod",
        hmacKey: ByteArray = PlatformCrypto.randomBytes(32),
    ): JsonObject {
        if (feature != BbsFeature.BASELINE && commitmentWithProof == null) throw ProtocolException("invalid_request", "${feature.id} needs commitment_with_proof")
        val options = buildJsonObject {
            put("type", "DataIntegrityProof")
            put("cryptosuite", SUITE)
            created?.let { put("created", Instant.fromEpochSeconds(it.epochSeconds).toString()) }
            put("verificationMethod", verificationMethod)
            put("proofPurpose", proofPurpose)
        }
        val proofHash = proofHash(options, unsecured)
        val groups = SdPrimitives.canonicalizeAndGroup(unsecured, SdPrimitives.shuffledIdLabelMapFunction(hmacKey), mapOf("mandatory" to mandatoryPointers), jsonLd)
        val mandatory = groups.groups.getValue("mandatory")
        val header = proofHash + SdPrimitives.hashMandatory(mandatory.matching.values)
        val messages = mandatory.nonMatching.values.map { it.encodeToByteArray() }
        val entropy = if (feature.pseudonymous) signerNymEntropy ?: Bbs.randomScalar() else null
        val signature = when (feature) {
            BbsFeature.BASELINE -> Bbs.sign(secretKey, publicKey, header, messages)
            BbsFeature.ANONYMOUS_HOLDER_BINDING -> Bbs.blindSign(secretKey, publicKey, commitmentWithProof!!, header, messages)
            else -> Bbs.nymSign(secretKey, publicKey, commitmentWithProof!!, header, entropy!!, messages)
        }
        val proofValue = BbsBaseProof(feature, signature, header, publicKey, hmacKey, mandatoryPointers, entropy).encode()
        return JsonObject(unsecured + ("proof" to JsonObject(options + ("proofValue" to JsonPrimitive(proofValue)))))
    }

    /**
     * Checks a received base proof with the issuer key [publicKey] (resolved from its verificationMethod): the header
     * must match the document and the signature must verify. Returns the secrets with nym_secret filled in.
     */
    suspend fun verifyBase(secured: JsonObject, publicKey: ByteArray, secrets: BbsHolderSecrets? = null): Pair<BbsBaseProof, BbsHolderSecrets?> {
        val proof = singleProof(secured)
        val base = BbsBaseProof.parse(proof.str("proofValue") ?: throw ProtocolException("invalid_proof", "Proof without proofValue"))
        if (!base.publicKey.contentEquals(publicKey)) throw ProtocolException("invalid_proof", "bbs-2023 public key does not match the verification method")
        val unsecured = JsonObject(secured - "proof")
        val proofHash = proofHash(JsonObject(proof - "proofValue"), unsecured)
        val groups = SdPrimitives.canonicalizeAndGroup(unsecured, SdPrimitives.shuffledIdLabelMapFunction(base.hmacKey), mapOf("mandatory" to base.mandatoryPointers), jsonLd)
        val mandatory = groups.groups.getValue("mandatory")
        val header = proofHash + SdPrimitives.hashMandatory(mandatory.matching.values)
        if (!header.contentEquals(base.header)) throw ProtocolException("invalid_proof", "bbs-2023 base proof does not match the document")
        val messages = mandatory.nonMatching.values.map { it.encodeToByteArray() }
        if (base.feature != BbsFeature.BASELINE && (secrets == null || secrets.feature != base.feature)) {
            throw ProtocolException("invalid_proof", "bbs-2023 ${base.feature.id} credential without the holder secrets")
        }
        val updated = when (base.feature) {
            BbsFeature.BASELINE -> { if (!Bbs.verify(publicKey, base.signature, header, messages)) throw invalid(); secrets }
            BbsFeature.ANONYMOUS_HOLDER_BINDING -> {
                if (!Bbs.blindVerify(publicKey, base.signature, header, messages, secrets!!.committed, secrets.secretProverBlind)) throw invalid()
                secrets
            }
            else -> {
                val s = secrets!!
                val nym = try {
                    Bbs.nymFinalize(publicKey, base.signature, header, messages, s.committed, s.proverNym ?: throw invalid(), base.signerNymEntropy!!, s.secretProverBlind)
                } catch (_: BbsFailure) { throw invalid() }
                s.withNymSecret(nym)
            }
        }
        return base to updated
    }

    /**
     * 3.3.3 and 3.3.4: the selectively disclosed document with a derived proof. [selectivePointers] are added to the
     * issuer's mandatory pointers; [nymDomain] is required for the pseudonym features (the verifier's identifier).
     */
    suspend fun derive(
        secured: JsonObject,
        selectivePointers: List<String>,
        presentationHeader: ByteArray = ByteArray(0),
        secrets: BbsHolderSecrets? = null,
        nymDomain: String? = null,
    ): JsonObject {
        val proof = singleProof(secured)
        val base = BbsBaseProof.parse(proof.str("proofValue") ?: throw ProtocolException("invalid_proof", "Proof without proofValue"))
        val document = JsonObject(secured - "proof")
        val combined = base.mandatoryPointers + selectivePointers
        val groups = SdPrimitives.canonicalizeAndGroup(
            document,
            SdPrimitives.shuffledIdLabelMapFunction(base.hmacKey),
            mapOf("mandatory" to base.mandatoryPointers, "selective" to selectivePointers, "combined" to combined),
            jsonLd,
        )
        val mandatory = groups.groups.getValue("mandatory")
        val selective = groups.groups.getValue("selective")
        val combinedGroup = groups.groups.getValue("combined")
        val mandatoryIndexes = combinedGroup.matching.keys.mapIndexedNotNull { relative, absolute -> relative.takeIf { absolute in mandatory.matching } }
        val selectiveIndexes = mandatory.nonMatching.keys.mapIndexedNotNull { relative, absolute -> relative.takeIf { absolute in selective.matching } }
        val reveal = SdPrimitives.selectJsonLd(combined, document) ?: throw ProtocolException("invalid_request", "Nothing selected to disclose")
        val canonicalIdMap = Rdfc10.canonicalize(combinedGroup.deskolemized).issued
        val verifierLabelMap = canonicalIdMap.entries.associate { (input, verifierLabel) ->
            verifierLabel to (groups.labelMap[input] ?: throw ProtocolException("invalid_proof", "Disclosure label map is incomplete"))
        }
        val messages = mandatory.nonMatching.values.map { it.encodeToByteArray() }
        val count = messages.size
        val derived = when (base.feature) {
            BbsFeature.BASELINE -> BbsDerivedProof(
                base.feature, Bbs.proofGen(base.publicKey, base.signature, base.header, presentationHeader, messages, selectiveIndexes),
                verifierLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader,
            )
            BbsFeature.ANONYMOUS_HOLDER_BINDING -> {
                val s = needSecrets(secrets, base.feature)
                BbsDerivedProof(
                    base.feature,
                    Bbs.blindProofGen(base.publicKey, base.signature, base.header, presentationHeader, messages, s.committed, selectiveIndexes, s.secretProverBlind),
                    verifierLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader, signerMessageCount = count,
                )
            }
            else -> {
                val s = needSecrets(secrets, base.feature)
                val domain = nymDomain ?: throw ProtocolException("invalid_request", "A pseudonym presentation needs the verifier's nym_domain")
                val nymSecret = s.nymSecret ?: Bbs.nymFinalize(base.publicKey, base.signature, base.header, messages, s.committed, s.proverNym ?: throw invalid(), base.signerNymEntropy!!, s.secretProverBlind)
                val p = Bbs.nymProofGen(base.publicKey, base.signature, base.header, presentationHeader, nymSecret, domain.encodeToByteArray(), messages, s.committed, selectiveIndexes, s.secretProverBlind)
                BbsDerivedProof(base.feature, p.proof, verifierLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader, domain, p.pseudonym, count)
            }
        }
        val newProof = JsonObject(proof + ("proofValue" to JsonPrimitive(derived.encode())))
        return JsonObject(reveal + ("proof" to newProof))
    }

    /**
     * 3.3.5: verifies a derived proof with the issuer key [publicKey]. For pseudonym proofs [expectedNymDomain] is the
     * verifier's own identifier; a proof that names another domain fails.
     */
    suspend fun verifyDerived(secured: JsonObject, publicKey: ByteArray, expectedNymDomain: String? = null): BbsVerified {
        val proof = singleProof(secured)
        val derived = BbsDerivedProof.parse(proof.str("proofValue") ?: throw ProtocolException("invalid_proof", "Proof without proofValue"))
        val unsecured = JsonObject(secured - "proof")
        val proofHash = proofHash(JsonObject(proof - "proofValue"), unsecured)
        val (_, nquads) = SdPrimitives.labelReplacementCanonicalize(jsonLd.toRdf(unsecured), SdPrimitives.labelMapFunction(derived.labelMap))
        if (derived.mandatoryIndexes.any { it >= nquads.size } || derived.mandatoryIndexes.toSet().size != derived.mandatoryIndexes.size) throw invalid()
        val mandatorySet = derived.mandatoryIndexes.toSet()
        val mandatory = nquads.filterIndexed { i, _ -> i in mandatorySet }
        val nonMandatory = nquads.filterIndexed { i, _ -> i !in mandatorySet }
        if (nonMandatory.size != derived.selectiveIndexes.size) throw invalid()
        // The feature label is the holder's to write: the proof must hide exactly the messages that feature commits to,
        // so a plain pseudonym cannot pass as holder bound (both verify through the same pseudonym check).
        val feature = if (derived.feature == BbsFeature.BASELINE) BbsFeature.BASELINE else {
            val signerCount = derived.signerMessageCount!!
            val hidden = (derived.bbsProof.size - PROOF_FIXED_BYTES).takeIf { it >= 0 && it % 32 == 0 }?.div(32) ?: throw invalid()
            if (signerCount < nonMandatory.size) throw invalid()
            val committed = hidden - (signerCount - nonMandatory.size)
            when {
                committed == derived.feature.committedMessages -> derived.feature
                // The published pseudonym vectors label plain pseudonym proofs with the holder bound header (0x09).
                derived.feature == BbsFeature.HOLDER_BINDING_PSEUDONYM && committed == BbsFeature.PSEUDONYM.committedMessages -> BbsFeature.PSEUDONYM
                else -> throw invalid()
            }
        }
        val header = proofHash + SdPrimitives.hashMandatory(mandatory)
        val disclosed = nonMandatory.map { it.encodeToByteArray() }
        val ok = when (feature) {
            BbsFeature.BASELINE -> Bbs.proofVerify(publicKey, derived.bbsProof, header, derived.presentationHeader, disclosed, derived.selectiveIndexes)
            BbsFeature.ANONYMOUS_HOLDER_BINDING ->
                Bbs.blindProofVerify(publicKey, derived.bbsProof, header, derived.presentationHeader, derived.signerMessageCount!!, disclosed, derived.selectiveIndexes)
            else -> {
                val domain = when {
                    derived.nymDomain != null && expectedNymDomain != null && derived.nymDomain != expectedNymDomain ->
                        throw ProtocolException("invalid_proof", "Pseudonym was made for another verifier")
                    else -> derived.nymDomain ?: expectedNymDomain ?: throw ProtocolException("invalid_proof", "Pseudonym proof without a nym_domain")
                }
                Bbs.nymProofVerify(publicKey, derived.bbsProof, header, derived.presentationHeader, derived.pseudonym!!, domain.encodeToByteArray(),
                    derived.signerMessageCount!!, disclosed, derived.selectiveIndexes)
            }
        }
        if (!ok) throw invalid()
        return BbsVerified(
            unsecured, feature, proof.str("verificationMethod") ?: "", derived.pseudonym,
            if (feature.pseudonymous) derived.nymDomain ?: expectedNymDomain else null, W3cVc.date(proof.str("created")),
        )
    }

    /** RDFC-1.0 of the proof configuration (the proof options with the document's @context), SHA-256. */
    private suspend fun proofHash(options: JsonObject, unsecured: JsonObject): ByteArray {
        if (options.str("type") != "DataIntegrityProof" || options.str("cryptosuite") != SUITE) throw ProtocolException("invalid_proof", "Not a bbs-2023 proof")
        options.str("created")?.let { W3cVc.date(it) ?: throw ProtocolException("invalid_proof", "Invalid proof created date") }
        val config = unsecured["@context"]?.let { JsonObject(options + ("@context" to it)) } ?: throw ProtocolException("invalid_proof", "Document has no @context")
        return PlatformCrypto.sha256(jsonLd.canonicalize(config).text().encodeToByteArray())
    }

    private fun singleProof(secured: JsonObject): JsonObject = when (val p = secured["proof"]) {
        is JsonObject -> p
        is JsonArray -> p.filterIsInstance<JsonObject>().singleOrNull { it.str("cryptosuite") == SUITE }
            ?: throw ProtocolException("invalid_proof", "Expected one bbs-2023 proof")
        else -> throw ProtocolException("invalid_proof", "Document has no proof")
    }

    private fun needSecrets(secrets: BbsHolderSecrets?, feature: BbsFeature): BbsHolderSecrets =
        secrets?.takeIf { it.feature == feature } ?: throw ProtocolException("invalid_request", "The ${feature.id} credential's holder secrets are missing")

    private fun invalid() = ProtocolException("invalid_proof", "bbs-2023 proof is invalid")

    companion object {
        const val SUITE = "bbs-2023"

        /** A BBS proof without its hidden message responses: Abar, Bbar, D (G1) and e^, r1^, r3^, challenge (scalars). */
        private const val PROOF_FIXED_BYTES = 3 * 48 + 4 * 32

        /** True when [proof] is a bbs-2023 proof object. */
        fun isBbs(proof: JsonElement?): Boolean = (proof as? JsonObject)?.str("cryptosuite") == SUITE ||
            (proof as? JsonArray)?.any { (it as? JsonObject)?.str("cryptosuite") == SUITE } == true
    }
}

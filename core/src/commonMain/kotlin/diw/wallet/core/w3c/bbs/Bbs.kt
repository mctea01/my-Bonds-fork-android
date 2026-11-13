package diw.wallet.core.w3c.bbs

/**
 * BBS signatures over BLS12-381 with SHA-256 (draft-irtf-cfrg-bbs-signatures, Blind BBS, BBS per-verifier linkability)
 * as bbs-2023 uses them. The platform implementation is the zkryptium build in the ZK native library; [available] is
 * false when that library is not packaged, and every other call then throws [BbsUnavailable].
 *
 * Messages are the UTF-8 non-mandatory N-Quads; indexes are 0-based positions in the signer's messages. Verification
 * calls return false for any malformed input instead of throwing.
 */
expect object Bbs {
    fun available(): Boolean
    fun generateKeyPair(keyMaterial: ByteArray, keyInfo: ByteArray = ByteArray(0)): BbsKeys
    fun publicKey(secretKey: ByteArray): ByteArray
    fun randomScalar(): ByteArray

    fun sign(secretKey: ByteArray, publicKey: ByteArray, header: ByteArray, messages: List<ByteArray>): ByteArray
    fun verify(publicKey: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>): Boolean
    fun proofGen(publicKey: ByteArray, signature: ByteArray, header: ByteArray, presentationHeader: ByteArray, messages: List<ByteArray>, disclosed: List<Int>): ByteArray
    fun proofVerify(publicKey: ByteArray, proof: ByteArray, header: ByteArray, presentationHeader: ByteArray, disclosedMessages: List<ByteArray>, disclosed: List<Int>): Boolean

    /** Blind BBS: the holder commits to [committed] (the holder secret). */
    fun commit(committed: List<ByteArray>): BbsCommitment
    fun blindSign(secretKey: ByteArray, publicKey: ByteArray, commitmentWithProof: ByteArray, header: ByteArray, messages: List<ByteArray>): ByteArray
    fun blindVerify(publicKey: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, secretProverBlind: ByteArray): Boolean
    fun blindProofGen(publicKey: ByteArray, signature: ByteArray, header: ByteArray, presentationHeader: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, disclosed: List<Int>, secretProverBlind: ByteArray): ByteArray
    fun blindProofVerify(publicKey: ByteArray, proof: ByteArray, header: ByteArray, presentationHeader: ByteArray, signerMessageCount: Int, disclosedMessages: List<ByteArray>, disclosed: List<Int>): Boolean

    /** Pseudonyms: the holder commits to [committed] and its prover_nym; the issuer adds signer_nym_entropy. */
    fun nymCommit(committed: List<ByteArray>, proverNym: ByteArray): BbsCommitment
    fun nymSign(secretKey: ByteArray, publicKey: ByteArray, commitmentWithProof: ByteArray, header: ByteArray, signerNymEntropy: ByteArray, messages: List<ByteArray>): ByteArray
    /** Verifies the signature and returns nym_secret. */
    fun nymFinalize(publicKey: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, proverNym: ByteArray, signerNymEntropy: ByteArray, secretProverBlind: ByteArray): ByteArray
    fun nymProofGen(publicKey: ByteArray, signature: ByteArray, header: ByteArray, presentationHeader: ByteArray, nymSecret: ByteArray, nymDomain: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, disclosed: List<Int>, secretProverBlind: ByteArray): BbsNymProof
    fun nymProofVerify(publicKey: ByteArray, proof: ByteArray, header: ByteArray, presentationHeader: ByteArray, pseudonym: ByteArray, nymDomain: ByteArray, signerMessageCount: Int, disclosedMessages: List<ByteArray>, disclosed: List<Int>): Boolean
}

class BbsKeys(val secretKey: ByteArray, val publicKey: ByteArray)

class BbsCommitment(val commitmentWithProof: ByteArray, val secretProverBlind: ByteArray)

class BbsNymProof(val proof: ByteArray, val pseudonym: ByteArray)

/** The BBS library is not part of this build, or rejected its input. */
class BbsUnavailable(message: String) : Exception(message)

class BbsFailure(val reason: String) : Exception("BBS operation failed: $reason")

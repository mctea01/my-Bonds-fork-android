package diw.wallet.core.w3c.bbs

import diw.wallet.core.zk.native.ZkNative
import diw.wallet.core.zk.native.bindings.ZkException
import diw.wallet.core.zk.native.bindings.bbsBlindProofGen
import diw.wallet.core.zk.native.bindings.bbsBlindProofVerify
import diw.wallet.core.zk.native.bindings.bbsBlindSign
import diw.wallet.core.zk.native.bindings.bbsBlindVerify
import diw.wallet.core.zk.native.bindings.bbsCommit
import diw.wallet.core.zk.native.bindings.bbsGenerateKeyPair
import diw.wallet.core.zk.native.bindings.bbsNymCommit
import diw.wallet.core.zk.native.bindings.bbsNymFinalize
import diw.wallet.core.zk.native.bindings.bbsNymProofGen
import diw.wallet.core.zk.native.bindings.bbsNymProofVerify
import diw.wallet.core.zk.native.bindings.bbsNymSign
import diw.wallet.core.zk.native.bindings.bbsProofGen
import diw.wallet.core.zk.native.bindings.bbsProofVerify
import diw.wallet.core.zk.native.bindings.bbsPublicKey
import diw.wallet.core.zk.native.bindings.bbsRandomScalar
import diw.wallet.core.zk.native.bindings.bbsSign
import diw.wallet.core.zk.native.bindings.bbsVerify
import diw.wallet.core.zk.native.bindings.nativeInfo

/** The zkryptium BBS exports of the diw_zk native library (see native/diw-zk-ffi/src/bbs.rs). */
actual object Bbs {
    @Volatile
    private var state: Boolean? = null

    actual fun available(): Boolean = state ?: synchronized(this) {
        state ?: runCatching {
            val dalvik = System.getProperty("java.vm.name", "").orEmpty().contains("Dalvik", ignoreCase = true)
            (dalvik || ZkNative.ensureLoaded()) && "bbs" in nativeInfo().features
        }.getOrElse { false }.also { state = it }
    }

    private fun <T> call(block: () -> T): T {
        if (!available()) throw BbsUnavailable("BBS signatures are not available in this build")
        return try {
            block()
        } catch (_: ZkException.Unsupported) {
            throw BbsUnavailable("BBS signatures are not available in this build")
        } catch (e: ZkException) {
            throw BbsFailure(e.message ?: "native error")
        }
    }

    private fun check(block: () -> Boolean): Boolean = available() && runCatching(block).getOrElse { false }

    private fun idx(list: List<Int>): List<ULong> = list.map { require(it >= 0); it.toULong() }

    actual fun generateKeyPair(keyMaterial: ByteArray, keyInfo: ByteArray): BbsKeys = call {
        bbsGenerateKeyPair(keyMaterial, keyInfo).let { BbsKeys(it.secretKey, it.publicKey) }
    }

    actual fun publicKey(secretKey: ByteArray): ByteArray = call { bbsPublicKey(secretKey) }

    actual fun randomScalar(): ByteArray = call { bbsRandomScalar() }

    actual fun sign(secretKey: ByteArray, publicKey: ByteArray, header: ByteArray, messages: List<ByteArray>): ByteArray =
        call { bbsSign(secretKey, publicKey, header, messages) }

    actual fun verify(publicKey: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>): Boolean =
        check { bbsVerify(publicKey, signature, header, messages) }

    actual fun proofGen(publicKey: ByteArray, signature: ByteArray, header: ByteArray, presentationHeader: ByteArray, messages: List<ByteArray>, disclosed: List<Int>): ByteArray =
        call { bbsProofGen(publicKey, signature, header, presentationHeader, messages, idx(disclosed)) }

    actual fun proofVerify(publicKey: ByteArray, proof: ByteArray, header: ByteArray, presentationHeader: ByteArray, disclosedMessages: List<ByteArray>, disclosed: List<Int>): Boolean =
        check { bbsProofVerify(publicKey, proof, header, presentationHeader, disclosedMessages, idx(disclosed)) }

    actual fun commit(committed: List<ByteArray>): BbsCommitment = call {
        bbsCommit(committed).let { BbsCommitment(it.commitmentWithProof, it.secretProverBlind) }
    }

    actual fun blindSign(secretKey: ByteArray, publicKey: ByteArray, commitmentWithProof: ByteArray, header: ByteArray, messages: List<ByteArray>): ByteArray =
        call { bbsBlindSign(secretKey, publicKey, commitmentWithProof, header, messages) }

    actual fun blindVerify(publicKey: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, secretProverBlind: ByteArray): Boolean =
        check { bbsBlindVerify(publicKey, signature, header, messages, committed, secretProverBlind) }

    actual fun blindProofGen(publicKey: ByteArray, signature: ByteArray, header: ByteArray, presentationHeader: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, disclosed: List<Int>, secretProverBlind: ByteArray): ByteArray =
        call { bbsBlindProofGen(publicKey, signature, header, presentationHeader, messages, committed, idx(disclosed), secretProverBlind) }

    actual fun blindProofVerify(publicKey: ByteArray, proof: ByteArray, header: ByteArray, presentationHeader: ByteArray, signerMessageCount: Int, disclosedMessages: List<ByteArray>, disclosed: List<Int>): Boolean =
        check { bbsBlindProofVerify(publicKey, proof, header, presentationHeader, signerMessageCount.toULong(), disclosedMessages, idx(disclosed)) }

    actual fun nymCommit(committed: List<ByteArray>, proverNym: ByteArray): BbsCommitment = call {
        bbsNymCommit(committed, proverNym).let { BbsCommitment(it.commitmentWithProof, it.secretProverBlind) }
    }

    actual fun nymSign(secretKey: ByteArray, publicKey: ByteArray, commitmentWithProof: ByteArray, header: ByteArray, signerNymEntropy: ByteArray, messages: List<ByteArray>): ByteArray =
        call { bbsNymSign(secretKey, publicKey, commitmentWithProof, header, signerNymEntropy, messages) }

    actual fun nymFinalize(publicKey: ByteArray, signature: ByteArray, header: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, proverNym: ByteArray, signerNymEntropy: ByteArray, secretProverBlind: ByteArray): ByteArray =
        call { bbsNymFinalize(publicKey, signature, header, messages, committed, proverNym, signerNymEntropy, secretProverBlind) }

    actual fun nymProofGen(publicKey: ByteArray, signature: ByteArray, header: ByteArray, presentationHeader: ByteArray, nymSecret: ByteArray, nymDomain: ByteArray, messages: List<ByteArray>, committed: List<ByteArray>, disclosed: List<Int>, secretProverBlind: ByteArray): BbsNymProof =
        call { bbsNymProofGen(publicKey, signature, header, presentationHeader, nymSecret, nymDomain, messages, committed, idx(disclosed), secretProverBlind).let { BbsNymProof(it.proof, it.pseudonym) } }

    actual fun nymProofVerify(publicKey: ByteArray, proof: ByteArray, header: ByteArray, presentationHeader: ByteArray, pseudonym: ByteArray, nymDomain: ByteArray, signerMessageCount: Int, disclosedMessages: List<ByteArray>, disclosed: List<Int>): Boolean =
        check { bbsNymProofVerify(publicKey, proof, header, presentationHeader, pseudonym, nymDomain, signerMessageCount.toULong(), disclosedMessages, idx(disclosed)) }
}

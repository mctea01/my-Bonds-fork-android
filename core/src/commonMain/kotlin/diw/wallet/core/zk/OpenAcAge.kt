package diw.wallet.core.zk

/**
 * One OpenAC age proof: the card's SD-JWT and issuer key, the verifier's nonce, the holder's signature over it and the
 * cutoff date. The private inputs stay on the device; only the two proofs leave it.
 */
class OpenAcAgeInput(
    val sdJwt: String,
    val issuerKeyX: String,
    val issuerKeyY: String,
    val nonce: String,
    /** base64url r||s ES256 signature of the holder's cnf key over the nonce's UTF-8 bytes. */
    val deviceSignature: String,
    /** The circuit literal of the cutoff for the card's birth date format (2 ISO, 3 ROC). */
    val cutoff: (claimFormat: Int) -> Long,
)

/** Linked Prepare and Show proofs, re-randomised and verified on this device before they are returned. */
class OpenAcAgeProof(
    val claimName: String,
    val claimFormat: Int,
    val prepareProof: ByteArray,
    val showProof: ByteArray,
    val prepareMs: Long,
    val showMs: Long,
)

interface OpenAcAgeProver {
    /** Runs on the caller's coroutine; cancelling it stops the native work. [step] names the current stage. */
    suspend fun prove(input: OpenAcAgeInput, step: (String) -> Unit): ZkResult<OpenAcAgeProof>
}

package diw.wallet.app

/**
 * A live face compared with a document's photo on this device and found to match. [embedding] is the photo's face
 * embedding; [cosine] and [threshold] are the similarity score and the pass mark, both times 10^8.
 */
class FaceComparison(val embedding: FloatArray, val cosine: Long, val threshold: Long)

/**
 * A fresh hardware key's attestation [chain] (DER, the key's certificate first, the root last), its [signature]
 * (SHA256withECDSA, DER) over a statement, and the signing certificate digest the attestation states for this app.
 */
class FaceKeyAttestation(val chain: List<ByteArray>, val signature: ByteArray, val signerDigest: String)

/**
 * Why a comparison did not pass: `cancelled` (the holder closed the camera), `photo` (no usable face in the
 * document's photo), `no_match` (the face or the liveness check did not pass) or `unavailable` (no camera screen).
 */
class FaceMatchFailure(val code: String) : Exception(code)

/**
 * Face comparison for zkPassport FaceMatch answers (docs/design/zkpassport.md 5.6). Everything stays on this device:
 * the camera frames are compared with the photo read from the document's chip and are not kept.
 */
interface FaceMatchService {
    /** This app's package name, which a FaceMatch proof commits to. */
    val appId: String

    /** This app's version, written into the statement a hardware key signs. */
    val appVersion: String

    /**
     * SHA-256 (hex) of this app's signing certificate as a key attestation states it, for a verifier that wants to
     * accept proofs of this very build; null when it cannot be read.
     */
    val ownSigner: String? get() = null

    /**
     * Shows the camera and compares the holder's face with [portrait] (JPEG or JPEG 2000) together with a passive
     * liveness check; [strict] adds a head turn challenge. Throws [FaceMatchFailure] unless the face matched.
     */
    suspend fun compare(portrait: ByteArray, strict: Boolean): FaceComparison

    /**
     * Signs [toSign] with a new attested hardware key; null where the device gives no hardware key attestation the
     * circuits take (a software keystore, or an attestation without this app's signing certificate).
     */
    suspend fun attest(toSign: ByteArray): FaceKeyAttestation?
}

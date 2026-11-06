package diw.wallet.core.zk

import diw.wallet.core.document.zkpdf.ZkPdfTextRecord

/**
 * The public statement of a zkPDF proof (native/circuits/PUBLIC_SPEC.md): the holder builds it from the signed PDF,
 * the verifier rebuilds it from the masked file, the template and its own policy. Window input states are in
 * layout order (content first); slots are the circuit slot numbers 0..11.
 */
class ZkPdfStatement(
    /** zkpdf-v1-phone or zkpdf-v1-desktop; picks the segment circuits and their verification keys. */
    val composition: String,
    /** β: SHA-256 of the derived credential's cnf.jwk thumbprint. */
    val binding: ByteArray,
    val windows: List<Window>,
    val anchors: List<Anchor>,
    val slots: List<Slot>,
    val digitTables: List<DigitTable>,
    val predicates: List<Predicate>,
) {
    init {
        require(composition in COMPOSITIONS) { "Unknown zkPDF composition" }
        require(binding.size == 32) { "Invalid zkPDF binding" }
    }

    class Window(val role: String, val midIn: ByteArray, val blocks: Int, val head: ByteArray, val tail: ByteArray, val keyStream: ByteArray?)
    class Anchor(val record: ZkPdfTextRecord, val ordinal: Int, val total: Int)
    class Slot(val slot: Int, val beforeAnchor: Int, val afterAnchor: Int)
    class DigitTable(val font: ByteArray, val width: Int, val codes: IntArray)
    /** [kind] 0 DATE_LE, 1 DATE_GE; [format] 0 is year, month, day. */
    class Predicate(val kind: Int, val slot: Int, val format: Int, val cutoff: Int)

    companion object {
        const val PHONE = "zkpdf-v1-phone"
        const val DESKTOP = "zkpdf-v1-desktop"
        val COMPOSITIONS = setOf(PHONE, DESKTOP)
    }
}

/** The private part: the raw stream data of each window (layout order) and a fresh 16-byte salt per slot. */
class ZkPdfWitness(val privateData: List<ByteArray>, val salts: List<ByteArray>)

/** One segment proof of a bundle, as the native verifier reads it. */
class ZkPdfSegment(val kind: String, val index: Int, val proof: ByteArray, val publicInputs: ByteArray)

/** Size of a proof before it is made. */
class ZkPdfCost(val segments: Int, val estimatedProofBytes: Long)

class ZkPdfProofOutput(
    val segments: List<ZkPdfSegment>,
    /** SHA-256 state after each window, layout order. */
    val midOuts: List<ByteArray>,
    /** v2 record bytes of each of the 12 slots (empty when unused): the zkOpen source. */
    val claimRecords: List<ByteArray>,
    /** SHA-256 field commitment of each of the 12 slots (zeros when unused). */
    val claimDigests: List<ByteArray>,
    val proveMs: Long,
)

/** What a verified bundle attests besides the statement itself. */
class ZkPdfVerifiedOutput(val midOuts: List<ByteArray>, val claimDigests: List<ByteArray>)

/**
 * The zkPDF segment prover and verifier over the hash-pinned circuit assets. Errors never carry document content.
 */
interface ZkPdfEngine {
    /** Segment count and proof size for this input, without proving; fails when it is outside the circuit limits. */
    suspend fun check(statement: ZkPdfStatement, witness: ZkPdfWitness): ZkResult<ZkPdfCost>

    /**
     * Proves every segment and verifies the bundle before returning it. Runs on the caller's coroutine; cancelling it
     * stops the native work. [progress] reports the segment kind, the number of finished segments and the total.
     */
    suspend fun prove(statement: ZkPdfStatement, witness: ZkPdfWitness, progress: (String, Int, Int) -> Unit): ZkResult<ZkPdfProofOutput>

    /** Ok with the attested outputs when every segment verifies against [statement]; Ok(null) when it is rejected. */
    suspend fun verify(statement: ZkPdfStatement, segments: List<ZkPdfSegment>): ZkResult<ZkPdfVerifiedOutput?>

    /** Whether the assets that [composition] needs (or only its verification keys) are installed. */
    fun ready(composition: String, prover: Boolean): Boolean
}

/** Asset identifiers of the zkPDF compositions, as native/assets.json lists them. */
object ZkPdfAssets {
    private val SHARED = listOf("pdf_sha_content_v1", "pdf_sha_opaque_v1", "pdf_claim_v1", "pdf_pred_v1")
    private val TIERED = listOf("pdf_inflate_seg0_v1", "pdf_inflate_seg_v1", "pdf_lex_seg_v1")
    val CRS = listOf("bn254_g1.dat", "bn254_g2.dat")

    fun required(composition: String, prover: Boolean): List<String> {
        require(composition in ZkPdfStatement.COMPOSITIONS)
        val suffix = if (composition == ZkPdfStatement.DESKTOP) "_desktop" else ""
        val circuits = SHARED + TIERED.map { it + suffix }
        val extensions = if (prover) listOf(".json", ".vk") else listOf(".vk")
        return CRS + circuits.flatMap { c -> extensions.map { c + it } }
    }
}

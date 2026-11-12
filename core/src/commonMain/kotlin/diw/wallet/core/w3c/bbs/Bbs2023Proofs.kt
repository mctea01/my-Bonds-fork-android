package diw.wallet.core.w3c.bbs

import diw.wallet.core.util.ProtocolException
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url

/** bbs-2023 feature options and their base and derived proof header bytes (0xd9 0x5d xx). */
enum class BbsFeature(val id: String, val baseHeader: Int, val derivedHeader: Int) {
    BASELINE("baseline", 0x02, 0x03),
    ANONYMOUS_HOLDER_BINDING("anonymous_holder_binding", 0x04, 0x05),
    PSEUDONYM("pseudonym", 0x06, 0x07),
    HOLDER_BINDING_PSEUDONYM("holder_binding_pseudonym", 0x08, 0x09);

    val holderBound: Boolean get() = this == ANONYMOUS_HOLDER_BINDING || this == HOLDER_BINDING_PSEUDONYM
    val pseudonymous: Boolean get() = this == PSEUDONYM || this == HOLDER_BINDING_PSEUDONYM

    /**
     * Messages a derived proof hides beyond the signer's: the holder secret and secret_prover_blind (anonymous holder
     * binding), secret_prover_blind and nym_secret (pseudonym), or all three (holder bound pseudonym).
     */
    val committedMessages: Int get() = when (this) {
        BASELINE -> 0
        ANONYMOUS_HOLDER_BINDING, PSEUDONYM -> 2
        HOLDER_BINDING_PSEUDONYM -> 3
    }

    companion object {
        fun of(id: String): BbsFeature? = entries.firstOrNull { it.id == id }
    }
}

/** A parsed bbs-2023 base proof value (bbs-2023 3.2.1 and 3.2.2). */
class BbsBaseProof(
    val feature: BbsFeature,
    val signature: ByteArray,
    val header: ByteArray,
    val publicKey: ByteArray,
    val hmacKey: ByteArray,
    val mandatoryPointers: List<String>,
    val signerNymEntropy: ByteArray? = null,
) {
    fun encode(): String {
        val items = mutableListOf<Any>(signature, header, publicKey, hmacKey, mandatoryPointers)
        if (feature.pseudonymous) items += signerNymEntropy ?: throw ProtocolException("invalid_proof", "Pseudonym base proof needs signer_nym_entropy")
        return "u" + (byteArrayOf(0xd9.toByte(), 0x5d, feature.baseHeader.toByte()) + MiniCbor.encode(items)).toBase64Url()
    }

    companion object {
        fun parse(proofValue: String): BbsBaseProof {
            val (headerByte, items) = MiniCbor.decodeProof(proofValue)
            val feature = BbsFeature.entries.firstOrNull { it.baseHeader == headerByte }
                ?: throw ProtocolException("invalid_proof", "Not a bbs-2023 base proof")
            val expected = if (feature.pseudonymous) 6 else 5
            if (items.size != expected) throw ProtocolException("invalid_proof", "bbs-2023 base proof has ${items.size} components")
            return BbsBaseProof(
                feature = feature,
                signature = MiniCbor.bytes(items[0]),
                header = MiniCbor.bytes(items[1]),
                publicKey = MiniCbor.bytes(items[2]),
                hmacKey = MiniCbor.bytes(items[3]),
                mandatoryPointers = MiniCbor.list(items[4]).map { it as? String ?: throw ProtocolException("invalid_proof", "Mandatory pointer is not text") },
                signerNymEntropy = if (feature.pseudonymous) MiniCbor.scalar(items[5]) else null,
            )
        }

        fun isBase(proofValue: String): Boolean = runCatching { proofValue.startsWith("u") && proofValue.substring(1).fromBase64Url().let { it.size > 3 && it[0] == 0xd9.toByte() && it[1] == 0x5d.toByte() && it[2].toInt() in setOf(2, 4, 6, 8) } }.getOrDefault(false)
    }
}

/**
 * A parsed bbs-2023 derived proof value (bbs-2023 3.2.3 and 3.2.4). [labelMap] is the decompressed verifier label map
 * (c14nN to bM). Pseudonym proofs are written with nym_domain as the normative text lists it; the 7-component form of
 * the published test vectors (without nym_domain) is also read, and then [nymDomain] is null.
 */
class BbsDerivedProof(
    val feature: BbsFeature,
    val bbsProof: ByteArray,
    val labelMap: Map<String, String>,
    val mandatoryIndexes: List<Int>,
    val selectiveIndexes: List<Int>,
    val presentationHeader: ByteArray,
    val nymDomain: String? = null,
    val pseudonym: ByteArray? = null,
    val signerMessageCount: Int? = null,
) {
    fun encode(): String {
        val compressed = labelMap.entries.map { (k, v) -> label(k, "c14n") to label(v, "b") }.sortedBy { it.first }
        val items = mutableListOf<Any>(bbsProof, MiniCbor.IntMap(compressed), mandatoryIndexes, selectiveIndexes, presentationHeader)
        if (feature.pseudonymous) {
            items += nymDomain ?: throw ProtocolException("invalid_proof", "Pseudonym proof needs nym_domain")
            items += pseudonym ?: throw ProtocolException("invalid_proof", "Pseudonym proof needs the pseudonym")
        }
        if (feature != BbsFeature.BASELINE) items += signerMessageCount ?: throw ProtocolException("invalid_proof", "Proof needs lengthBBSMessages")
        return "u" + (byteArrayOf(0xd9.toByte(), 0x5d, feature.derivedHeader.toByte()) + MiniCbor.encode(items)).toBase64Url()
    }

    companion object {
        private fun label(s: String, prefix: String): Int =
            s.removePrefix(prefix).takeIf { s.startsWith(prefix) }?.toIntOrNull() ?: throw ProtocolException("invalid_proof", "Bad blank node label $s")

        fun parse(proofValue: String): BbsDerivedProof {
            val (headerByte, items) = MiniCbor.decodeProof(proofValue)
            val feature = BbsFeature.entries.firstOrNull { it.derivedHeader == headerByte }
                ?: throw ProtocolException("invalid_proof", "Not a bbs-2023 derived proof")
            if (items.size !in 5..8) throw ProtocolException("invalid_proof", "bbs-2023 derived proof has ${items.size} components")
            fun ints(x: Any?) = MiniCbor.list(x).map { (it as? Long)?.toInt()?.takeIf { v -> v >= 0 } ?: throw ProtocolException("invalid_proof", "Index is not an unsigned integer") }
            val labelMap = (items[1] as? MiniCbor.IntMap ?: throw ProtocolException("invalid_proof", "Label map is not a map"))
                .entries.associate { (k, v) -> "c14n$k" to "b$v" }
            var nymDomain: String? = null
            var pseudonym: ByteArray? = null
            var count: Int? = null
            when (feature) {
                BbsFeature.BASELINE -> if (items.size != 5) throw ProtocolException("invalid_proof", "Baseline derived proof must have 5 components")
                BbsFeature.ANONYMOUS_HOLDER_BINDING -> {
                    if (items.size != 6) throw ProtocolException("invalid_proof", "Holder binding derived proof must have 6 components")
                    count = (items[5] as? Long)?.toInt()
                }
                else -> when (items.size) {
                    7 -> { pseudonym = MiniCbor.bytes(items[5]); count = (items[6] as? Long)?.toInt() }
                    8 -> {
                        nymDomain = when (val d = items[5]) { is String -> d; is ByteArray -> d.decodeToString(); else -> throw ProtocolException("invalid_proof", "nym_domain is not text") }
                        pseudonym = MiniCbor.bytes(items[6]); count = (items[7] as? Long)?.toInt()
                    }
                    else -> throw ProtocolException("invalid_proof", "Pseudonym derived proof must have 7 or 8 components")
                }
            }
            if (feature != BbsFeature.BASELINE && (count == null || count < 0)) throw ProtocolException("invalid_proof", "lengthBBSMessages missing")
            return BbsDerivedProof(feature, MiniCbor.bytes(items[0]), labelMap, ints(items[2]), ints(items[3]), MiniCbor.bytes(items[4]), nymDomain, pseudonym, count)
        }
    }
}

/** The CBOR subset bbs-2023 proof values use (no tags, no floats): byte and text strings, unsigned ints, arrays, int maps. */
internal object MiniCbor {
    class IntMap(val entries: List<Pair<Int, Int>>)

    /** A tag 2 (positive bignum) value: the published pseudonym vectors encode signer_nym_entropy this way. */
    class Bignum(val magnitude: ByteArray)

    fun encode(value: Any): ByteArray {
        val out = ArrayList<Byte>()
        write(out, value)
        return out.toByteArray()
    }

    private fun head(out: MutableList<Byte>, major: Int, n: Long) {
        val m = major shl 5
        when {
            n < 24 -> out += (m or n.toInt()).toByte()
            n < 0x100 -> { out += (m or 24).toByte(); out += n.toByte() }
            n < 0x10000 -> { out += (m or 25).toByte(); for (s in 8 downTo 0 step 8) out += (n shr s).toByte() }
            n < 0x100000000L -> { out += (m or 26).toByte(); for (s in 24 downTo 0 step 8) out += (n shr s).toByte() }
            else -> { out += (m or 27).toByte(); for (s in 56 downTo 0 step 8) out += (n shr s).toByte() }
        }
    }

    private fun write(out: MutableList<Byte>, v: Any) {
        when (v) {
            is ByteArray -> { head(out, 2, v.size.toLong()); v.forEach { out += it } }
            is String -> { val b = v.encodeToByteArray(); head(out, 3, b.size.toLong()); b.forEach { out += it } }
            is Int -> { require(v >= 0); head(out, 0, v.toLong()) }
            is Long -> { require(v >= 0); head(out, 0, v) }
            is List<*> -> { head(out, 4, v.size.toLong()); v.forEach { write(out, it!!) } }
            is IntMap -> { head(out, 5, v.entries.size.toLong()); v.entries.forEach { (k, x) -> write(out, k); write(out, x) } }
            else -> error("unsupported CBOR value")
        }
    }

    fun decodeProof(proofValue: String): Pair<Int, List<Any?>> {
        if (!proofValue.startsWith("u")) throw ProtocolException("invalid_proof", "bbs-2023 proofValue must be multibase base64url")
        val raw = runCatching { proofValue.substring(1).fromBase64Url() }.getOrNull()
            ?: throw ProtocolException("invalid_proof", "bbs-2023 proofValue is not base64url")
        if (raw.size < 4 || raw[0] != 0xd9.toByte() || raw[1] != 0x5d.toByte()) throw ProtocolException("invalid_proof", "Not a bbs-2023 proof value")
        val r = Reader(raw, 3)
        val items = r.read() as? List<*> ?: throw ProtocolException("invalid_proof", "bbs-2023 proof components are not an array")
        if (r.pos != raw.size) throw ProtocolException("invalid_proof", "Trailing bytes after bbs-2023 proof")
        return raw[2].toInt() to items
    }

    fun bytes(v: Any?): ByteArray = v as? ByteArray ?: throw ProtocolException("invalid_proof", "Expected a byte string in the proof")

    /** A 32-byte scalar written as a byte string, or (leniently) as a bignum. */
    fun scalar(v: Any?): ByteArray = when (v) {
        is ByteArray -> v
        is Bignum -> if (v.magnitude.size <= 32) ByteArray(32 - v.magnitude.size) + v.magnitude else throw ProtocolException("invalid_proof", "Scalar too large")
        else -> throw ProtocolException("invalid_proof", "Expected a byte string in the proof")
    }
    fun list(v: Any?): List<Any?> = v as? List<*> ?: throw ProtocolException("invalid_proof", "Expected an array in the proof")

    private class Reader(val b: ByteArray, var pos: Int) {
        var depth = 0
        fun byte(): Int = if (pos < b.size) b[pos++].toInt() and 0xff else fail()
        fun arg(ai: Int): Long = when {
            ai < 24 -> ai.toLong()
            ai in 24..27 -> { var n = 0L; repeat(1 shl (ai - 24)) { n = (n shl 8) or byte().toLong() }; if (n < 0) fail(); n }
            else -> fail()
        }
        fun take(n: Long): ByteArray {
            if (n > b.size - pos) fail()
            return b.copyOfRange(pos, pos + n.toInt()).also { pos += n.toInt() }
        }
        fun read(): Any? {
            if (++depth > 8) fail()
            val ib = byte()
            val major = ib shr 5
            val n = arg(ib and 31)
            val v: Any? = when (major) {
                0 -> n
                2 -> take(n)
                3 -> take(n).decodeToString()
                4 -> { if (n > b.size) fail(); (0 until n.toInt()).map { read() } }
                5 -> {
                    if (n > b.size) fail()
                    IntMap((0 until n.toInt()).map {
                        val k = read() as? Long ?: fail()
                        val x = read() as? Long ?: fail()
                        if (k > Int.MAX_VALUE || x > Int.MAX_VALUE) fail()
                        k.toInt() to x.toInt()
                    })
                }
                6 -> when (n) {
                    2L -> Bignum(read() as? ByteArray ?: fail())
                    // RFC 8746 uint8 typed array around a byte string, as some encoders (and Digital Bazaar's reader) use.
                    64L -> read() as? ByteArray ?: fail()
                    else -> fail()
                }
                else -> fail()
            }
            depth--
            return v
        }
        fun fail(): Nothing = throw ProtocolException("invalid_proof", "Malformed CBOR in bbs-2023 proof")
    }
}

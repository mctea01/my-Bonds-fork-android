package diw.wallet.core.zkpassport

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.security.MessageDigest

/**
 * The checks of zkPassport's integrity circuits (data_check_integrity_sa_X_dg_Y, circuits lib data-check/integrity),
 * repeated on their inputs when proving fails, so the failure names the check. The result is a fixed code without
 * any document data: the circuits' own failure gives only "witness unsatisfied".
 */
object ZkPassportIntegrity {
    private val NAME = Regex("^data_check_integrity_sa_(sha\\d+)_dg_(sha\\d+)$")
    private val DG2_HASH_DER = byteArrayOf(0x02, 0x01, 0x02, 0x04)
    private const val DG1_LENGTH = 95
    private const val PASSPORT_DG1_LENGTH = 93

    /** The first check [inputs] fail for the circuit [name]; null when they pass or [name] is not an integrity circuit. */
    fun diagnose(name: String, inputs: JsonObject): String? {
        val match = NAME.find(name) ?: return null
        val sa = algorithm(match.groupValues[1]) ?: return null
        val dg = algorithm(match.groupValues[2]) ?: return null
        val dg1 = bytes((inputs["salted_dg1"] as? JsonObject)?.get("value")) ?: return "dg1_input"
        val eContent = bytes(inputs["e_content"]) ?: return "e_content_input"
        val signedAttributes = bytes(inputs["signed_attributes"]) ?: return "signed_attributes_input"
        if (dg1.size != DG1_LENGTH) return "dg1_length"
        // An ID card fills all 95 bytes, a passport 93 and zero padding (is_id_card, get_checked_dg1_size).
        val idCard = dg1[93] != 0.toByte() && dg1[94] != 0.toByte()
        if (!idCard && (dg1[93] != 0.toByte() || dg1[94] != 0.toByte())) return "dg1_padding"
        val eSize = tlvLength(eContent) ?: return "e_content_length"
        if (eSize > eContent.size) return "e_content_length"
        if ((eSize until eContent.size).any { eContent[it] != 0.toByte() }) return "e_content_padding"
        val content = eContent.copyOf(eSize)
        val dg1Hash = MessageDigest.getInstance(dg).digest(dg1.copyOf(if (idCard) DG1_LENGTH else PASSPORT_DG1_LENGTH))
        if (indexOf(content, dg1Hash) < 0) return "dg1_hash"
        if (indexOf(signedAttributes, MessageDigest.getInstance(sa).digest(content)) < 0) return "e_content_hash"
        // DG2's hash is found by the DER that precedes it: SEQUENCE { INTEGER 2, OCTET STRING hash }.
        val size = dg1Hash.size
        val at = indexOf(eContent, DG2_HASH_DER)
        if (at < 2 || at + DG2_HASH_DER.size >= eContent.size || eContent[at - 2] != 0x30.toByte() || eContent[at - 1] != (5 + size).toByte() ||
            eContent[at + DG2_HASH_DER.size] != size.toByte() || at + DG2_HASH_DER.size + 1 + size > eSize
        ) return "dg2_hash"
        return null
    }

    private fun algorithm(name: String) = when (name) {
        "sha1" -> "SHA-1"
        "sha224" -> "SHA-224"
        "sha256" -> "SHA-256"
        "sha384" -> "SHA-384"
        "sha512" -> "SHA-512"
        else -> null
    }

    private fun bytes(element: JsonElement?): ByteArray? {
        val array = element as? JsonArray ?: return null
        val out = ByteArray(array.size)
        for ((i, e) in array.withIndex()) {
            val text = (e as? JsonPrimitive)?.contentOrNull ?: return null
            val value = (if (text.startsWith("0x")) text.drop(2).toIntOrNull(16) else text.toIntOrNull()) ?: return null
            if (value !in 0..255) return null
            out[i] = value.toByte()
        }
        return out
    }

    /** The whole length of the DER element at the start of [der] (unsafe_get_asn1_element_length). */
    private fun tlvLength(der: ByteArray): Int? {
        if (der.size < 2 || (der[0].toInt() and 0x1F) == 0x1F) return null
        val first = der[1].toInt() and 0xFF
        if (first == 0x80) return null
        if (first < 0x80) return 2 + first
        val n = first and 0x7F
        if (n > 4 || der.size < 2 + n) return null
        var length = 0L
        for (i in 0 until n) length = (length shl 8) or (der[2 + i].toLong() and 0xFF)
        return (2 + n + length).takeIf { it <= Int.MAX_VALUE }?.toInt()
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
}

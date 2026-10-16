package diw.wallet.core.oid4vp

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.arr
import diw.wallet.core.util.int
import diw.wallet.core.util.str
import kotlinx.serialization.json.JsonObject
import org.multipaz.documenttype.TransactionType
import org.multipaz.util.fromBase64Url

/**
 * The CSC transaction data a remote signing service sends with its OpenID4VP request when the holder approves
 * signatures (type https://cloudsignatureconsortium.org/2025/qes-approval, also the earlier qes_authorization).
 * The wallet shows what is approved and binds the presentation to it through transaction_data_hashes.
 */
class QesApprovalTransaction(identifier: String) : TransactionType<JsonObject>(
    displayName = "遠端簽章授權",
    identifier = identifier,
) {
    override fun parseOpenId4VpRequest(jsonString: String): JsonObject =
        DiwJson.parseToJsonElement(jsonString) as? JsonObject ?: throw IllegalArgumentException("transaction_data is not an object")

    companion object {
        const val CSC_2025 = "https://cloudsignatureconsortium.org/2025/qes-approval"
        const val QES_AUTHORIZATION = "qes_authorization"
        val types: List<QesApprovalTransaction> = listOf(QesApprovalTransaction(CSC_2025), QesApprovalTransaction(QES_AUTHORIZATION))

        /**
         * What the holder approves, one line per transaction_data entry of these types: the number of documents and
         * their labels or digests; null for entries of other types.
         */
        fun describe(encoded: String): String? {
            val o = runCatching { DiwJson.parseToJsonElement(encoded.fromBase64Url().decodeToString()) as JsonObject }.getOrNull() ?: return null
            if (o.str("type") !in setOf(CSC_2025, QES_AUTHORIZATION)) return null
            val digests = (o.arr("documentDigests") ?: o.arr("documentDigest")).orEmpty().mapNotNull { it as? JsonObject }
            val labels = digests.map { d -> d.str("label")?.takeIf { it.isNotBlank() } ?: ("摘要 " + (d.str("hash") ?: "").take(16)) }
            val count = o.int("numSignatures") ?: digests.size
            return "遠端簽章授權：簽署 $count 份" + if (labels.isEmpty()) "" else "（" + labels.joinToString("、") + "）"
        }
    }
}

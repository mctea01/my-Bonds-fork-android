package diw.wallet.core.profile.twdiw

import diw.wallet.core.util.DiwJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Identity assurance level of a TWDIW card. TWDIW issuers write it in the credential display description as a JSON
 * string, {"ial":"IAL 2"}, and the official wallet shows it on the card and orders cards by it when presenting.
 */
object TwdiwAssurance {
    /** The level the issuer chose ("IAL 2" gives 2, an empty choice gives ""), or null when the description has none. */
    fun level(description: String?): String? {
        val text = description?.trim()?.takeIf { it.startsWith("{") } ?: return null
        val obj = runCatching { DiwJson.parseToJsonElement(text) as? JsonObject }.getOrNull() ?: return null
        val raw = (obj["ial"] as? JsonPrimitive)?.content ?: return null
        return raw.trim().removePrefix("IAL").removePrefix("ial").trim()
    }

    /** Numeric level for ordering, 0 when unknown or not chosen. */
    fun rank(description: String?): Int = level(description)?.toIntOrNull() ?: 0
}

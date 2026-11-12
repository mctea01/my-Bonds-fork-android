package diw.wallet.core.document.derived

import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.profile.bonds.MyDataText

/**
 * Whether another document names the same travel document (docs/design/zkpassport.md 5.4 item 5): an entry and exit
 * certificate, a mainland China entry and exit record or any other text that carries the passport number. The match
 * is local and by number; the holder's name in Latin letters makes it stronger. A zero-knowledge link between a
 * zkPassport commitment and a zkPDF field commitment is later work.
 */
object TravelDocumentLinks {
    /** A match of the passport in a text: [number] always, [sameName] when the zone's surname appears too. */
    data class Mention(val number: String, val sameName: Boolean)

    private fun compact(text: String): String = MyDataText.halfWidth(text).uppercase().replace(Regex("\\s+"), "")

    /** The passport [mrz] in [text], or null when its number is not there as a whole token. */
    fun mention(mrz: Mrz, text: String): Mention? {
        val number = mrz.documentNumber.trim('<', ' ').uppercase()
        if (number.length < 6) return null
        val spaced = MyDataText.halfWidth(text).uppercase()
        val token = Regex("(?<![A-Z0-9])" + Regex.escape(number) + "(?![A-Z0-9])")
        // Text layers sometimes put spaces between characters, so the number is also looked for with spaces removed.
        val found = token.containsMatchIn(spaced) || token.containsMatchIn(compact(text))
        if (!found) return null
        val surname = mrz.primaryIdentifier.trim().uppercase()
        val sameName = surname.length >= 2 && Regex("(?<![A-Z])" + Regex.escape(surname) + "(?![A-Z])").containsMatchIn(spaced)
        return Mention(number, sameName)
    }
}

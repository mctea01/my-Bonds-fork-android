package diw.wallet.core.oid4vp

/**
 * What a verifier says about a request beyond the claims it asks for, shown on the consent screen: who receives the
 * data, the occasion, the purpose and a page with the terms the holder agrees to. Presentation Exchange carries the
 * purpose in presentation_definition.purpose; profiles (TWDIW) pack more into it.
 */
data class ConsentTerms(
    /** Organisation that receives the data, when the request names it apart from the verifier identity. */
    val recipient: String? = null,
    /** The occasion of the request (TWDIW "scenario"); the terms page is titled after it. */
    val scenario: String? = null,
    val purpose: String? = null,
    /** https page with the terms (TWDIW 知情同意書); other schemes are dropped. */
    val termsUri: String? = null,
) {
    val isEmpty: Boolean get() = recipient == null && scenario == null && purpose == null && termsUri == null

    companion object {
        /** [uri] when it is an https URL, else null. */
        fun httpsOnly(uri: String?): String? = uri?.trim()?.takeIf { it.startsWith("https://", ignoreCase = true) && it.length > 8 }
    }
}

package diw.wallet.core.document.zkpdf

import diw.wallet.core.zk.ZkTemplatePack

/**
 * The zkPDF document templates the wallet knows: those of the installed signed pack ([ZkTemplatePack.zkpdf]), and in
 * the test environment unsigned templates imported for testing (always marked [ZkPdfProfile.test]). Both the holder
 * (which template fits a PDF) and the verifier (V1, the pinned template a bundle names) read them here. A pack entry
 * that does not parse, or that is marked as a test template, is skipped.
 */
object ZkPdfProfiles {
    @Volatile
    private var packVersion: Long? = null

    @Volatile
    private var signed: List<ZkPdfProfile> = emptyList()

    @Volatile
    private var test: List<ZkPdfProfile> = emptyList()

    /** Templates of the installed pack. */
    val installed: List<ZkPdfProfile> get() = signed

    /** Templates imported for testing. */
    val testProfiles: List<ZkPdfProfile> get() = test

    fun install(pack: ZkTemplatePack) {
        val current = packVersion
        if (current != null && pack.version < current) return
        packVersion = pack.version
        signed = pack.zkpdf.mapNotNull { o -> runCatching { ZkPdfProfile.parse(o) }.getOrNull()?.takeIf { !it.test } }
            .distinctBy { it.id }
    }

    /** Replaces the test templates; each is marked as a test template and none may reuse a signed identifier. */
    fun installTest(profiles: List<ZkPdfProfile>) {
        val ids = signed.map { it.id }.toSet()
        test = profiles.filter { it.id !in ids }.map { it.asTest() }.distinctBy { it.id }
    }

    /** Every template usable here: the signed ones, plus the test ones when [testEnvironment]. */
    fun available(testEnvironment: Boolean): List<ZkPdfProfile> = if (testEnvironment) signed + test else signed

    /** The template named [id], a test template only when [testEnvironment]. */
    fun find(id: String, testEnvironment: Boolean): ZkPdfProfile? = available(testEnvironment).firstOrNull { it.id == id }

    private fun ZkPdfProfile.asTest(): ZkPdfProfile = if (test) this else ZkPdfProfile(id, title, opaqueImages, fields, true)
}

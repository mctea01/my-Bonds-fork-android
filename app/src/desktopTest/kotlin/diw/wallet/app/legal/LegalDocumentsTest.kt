package diw.wallet.app.legal

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * docs/legal holds the published form of every legal text (the privacy policy URL for app stores). The files are
 * generated from LegalTexts; run the tests with DIW_UPDATE_LEGAL=1 to write them after changing a text.
 */
class LegalDocumentsTest {
    private val dir: File = generateSequence(File("").absoluteFile) { it.parentFile }
        .first { File(it, "settings.gradle.kts").exists() }
        .resolve("docs/legal")

    @Test
    fun publishedTextsMatchTheApp() {
        val update = System.getenv("DIW_UPDATE_LEGAL") == "1"
        for (doc in LegalTexts.all) {
            val file = File(dir, doc.id + ".md")
            val expected = doc.toMarkdown()
            if (update) {
                file.parentFile.mkdirs()
                file.writeText(expected, Charsets.UTF_8)
            }
            assertTrue(file.exists(), "${file.path} is missing; run the tests with DIW_UPDATE_LEGAL=1")
            assertEquals(expected, file.readText(Charsets.UTF_8), "${file.path} differs from LegalTexts; run the tests with DIW_UPDATE_LEGAL=1")
        }
    }

    @Test
    fun everyIntegrationHasOneStatement() {
        assertEquals(Integration.entries.toSet(), LegalTexts.statements.map { it.integration }.toSet())
        assertEquals(LegalTexts.all.size, LegalTexts.all.map { it.id }.toSet().size, "document ids are unique")
        LegalTexts.all.forEach { d -> assertTrue(d.version >= 1 && d.sections.isNotEmpty() && d.summary.isNotEmpty(), d.id) }
    }
}

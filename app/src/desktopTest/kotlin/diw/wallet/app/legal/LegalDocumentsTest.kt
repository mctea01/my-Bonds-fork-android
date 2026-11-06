package diw.wallet.app.legal

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * docs/legal holds the published form of every legal text (the privacy policy URL for app stores): the Chinese
 * original at the top and the English translation in docs/legal/en. The files are generated from LegalTexts; run the
 * tests with DIW_UPDATE_LEGAL=1 to write them after changing a text.
 */
class LegalDocumentsTest {
    private val dir: File = generateSequence(File("").absoluteFile) { it.parentFile }
        .first { File(it, "settings.gradle.kts").exists() }
        .resolve("docs/legal")

    private val han = Regex("[\\u3400-\\u9fff\\uff00-\\uffef\\u3000-\\u303f]")

    @Test
    fun publishedTextsMatchTheApp() {
        val update = System.getenv("DIW_UPDATE_LEGAL") == "1"
        for (doc in LegalTexts.published) {
            val file = File(dir, doc.path)
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
        for (language in LegalTexts.LANGUAGES) {
            val set = LegalTexts.texts(language)
            assertEquals(Integration.entries.toSet(), set.statements.map { it.integration }.toSet(), language)
            assertEquals(set.all.size, set.all.map { it.id }.toSet().size, "document ids are unique in $language")
            set.all.forEach { d ->
                assertTrue(d.version >= 1 && d.sections.isNotEmpty() && d.summary.isNotEmpty(), d.id)
                assertEquals(language, d.language, d.id)
            }
        }
    }

    /** A translation has the same documents, versions and structure as the original, so section references and consents hold. */
    @Test
    fun translationsFollowTheOriginal() {
        val zh = LegalTexts.texts("zh").all
        for (language in LegalTexts.LANGUAGES.drop(1)) {
            val other = LegalTexts.texts(language).all
            assertEquals(zh.map { it.id }, other.map { it.id }, language)
            zh.zip(other).forEach { (a, b) ->
                assertEquals(a.version, b.version, b.path)
                assertEquals(a.effectiveDate, b.effectiveDate, b.path)
                assertEquals(a.summary.size, b.summary.size, "summary of ${b.path}")
                assertEquals(a.sections.size, b.sections.size, "sections of ${b.path}")
                a.sections.zip(b.sections).forEachIndexed { i, (s, t) ->
                    assertEquals(s.blocks.map { it::class }, t.blocks.map { it::class }, "${b.path} section ${i + 1}")
                    s.blocks.zip(t.blocks).forEach { (x, y) ->
                        if (x is LegalBlock.Bullets && y is LegalBlock.Bullets) assertEquals(x.items.size, y.items.size, "${b.path} section ${i + 1}")
                    }
                }
            }
        }
    }

    @Test
    fun englishTextsHaveNoChinese() {
        val set = LegalTexts.texts("en")
        assertFalse(han.containsMatchIn(set.developer))
        set.statements.forEach { assertFalse(han.containsMatchIn(it.name + it.operator), it.name) }
        set.all.forEach { d -> assertFalse(han.containsMatchIn(d.toMarkdown()), d.path + ": " + han.find(d.toMarkdown())?.let { m -> d.toMarkdown().substring(maxOf(0, m.range.first - 40), m.range.first + 10) }) }
    }
}

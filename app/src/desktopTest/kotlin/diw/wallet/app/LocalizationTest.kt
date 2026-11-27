package diw.wallet.app

import diw.wallet.app.res.Res
import diw.wallet.app.res.action_cancel
import diw.wallet.app.res.flow_added_count
import diw.wallet.app.res.legal_version_line
import diw.wallet.app.res.screen_settings
import diw.wallet.app.res.sep_comma
import diw.wallet.app.res.settings_history_count
import diw.wallet.app.res.web_proof_government
import diw.wallet.core.i18n.CoreStrings
import diw.wallet.core.i18n.ct
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The interface strings (composeResources values, values-zh, values-zh-rCN and any other translation file) and the
 * language the app reads them in.
 */
class LocalizationTest {
    private val res = File("src/commonMain/composeResources")
    private val han = Regex("[\\u3400-\\u9fff\\uff00-\\uffef\\u3000-\\u303f]")

    private fun strings(dir: String): Map<String, String> =
        Regex("<string name=\"([^\"]+)\">(.*?)</string>", RegexOption.DOT_MATCHES_ALL)
            .findAll(File(res, "$dir/strings.xml").readText())
            .associate { it.groupValues[1] to it.groupValues[2] }

    private fun placeholders(text: String) = Regex("%(\\d+)\\$[sd]").findAll(text).map { it.groupValues[1] }.toSortedSet()

    // Common characters that exist only in Traditional Chinese; Simplified Chinese text has none of them.
    private val traditionalOnly = Regex("[與為會個這們說證資設檔還時動體實點關開發單機錄號碼簽鑰線網認讀選擇輸頁顯從]")

    @Test
    fun bothLanguagesHaveTheSameStrings() {
        val en = strings("values")
        val zh = strings("values-zh")
        assertEquals(en.keys, zh.keys, "keys only in one language")
        en.forEach { (k, v) ->
            assertTrue(!han.containsMatchIn(v), "Chinese text in the English string $k: $v")
            val z = zh.getValue(k)
            if (z.isNotEmpty()) assertEquals(placeholders(z), placeholders(v), "placeholders of $k")
        }
    }

    @Test
    fun simplifiedChineseHasEveryString() {
        val zh = strings("values-zh")
        val hans = strings("values-zh-rCN")
        assertEquals(zh.keys, hans.keys, "keys only in Traditional or Simplified Chinese (python3 tools/i18n/i18n.py hans)")
        hans.forEach { (k, v) ->
            assertEquals(placeholders(zh.getValue(k)), placeholders(v), "placeholders of $k")
            assertTrue(!traditionalOnly.containsMatchIn(v), "Traditional characters in the Simplified Chinese string $k: $v")
        }
    }

    @Test
    fun everyTranslationFitsTheDefaultFile() {
        val en = strings("values")
        val dirs = res.listFiles().orEmpty().filter { it.name.startsWith("values-") && File(it, "strings.xml").exists() }
        assertTrue(dirs.map { it.name }.containsAll(listOf("values-zh", "values-zh-rCN")))
        // Other languages may be partly translated (strings they lack show in English), but every key must exist in
        // the default file and keep its placeholders.
        for (dir in dirs) {
            strings(dir.name).forEach { (k, v) ->
                assertTrue(k in en, "${dir.name}: $k is not in values/strings.xml")
                if (v.isNotEmpty()) assertEquals(placeholders(en.getValue(k)), placeholders(v), "${dir.name}: placeholders of $k")
            }
        }
    }

    /** The Google Play store listing (distribution/play/listing) fits Play's limits in every language. */
    @Test
    fun playListingFitsPlayLimits() {
        val listing = File("../distribution/play/listing")
        val dirs = listing.listFiles().orEmpty().filter { it.isDirectory }
        assertTrue(dirs.map { it.name }.containsAll(listOf("zh-TW", "en-US", "zh-CN")), "languages in $listing")
        val limits = mapOf("title.txt" to 30, "short_description.txt" to 80, "full_description.txt" to 4000)
        val notes = mapOf("release_notes_header.txt" to "{version}", "release_notes_more.txt" to "{count}", "release_notes_footer.txt" to "{url}")
        for (dir in dirs) {
            limits.forEach { (name, limit) ->
                val text = File(dir, name).readText().trim()
                assertTrue(text.isNotEmpty() && text.codePointCount(0, text.length) <= limit, "${dir.name}/$name: at most $limit characters")
            }
            notes.forEach { (name, placeholder) ->
                assertTrue(placeholder in File(dir, name).readText(), "${dir.name}/$name must contain $placeholder")
            }
        }
        listing.resolve("zh-CN").listFiles().orEmpty().forEach {
            assertTrue(!traditionalOnly.containsMatchIn(it.readText()), "Traditional characters in zh-CN/${it.name} (python3 tools/i18n/i18n.py play-hans)")
        }
    }

    @Test
    fun stringsFollowTheLanguage() = runBlocking<Unit> {
        val en = MemoryLanguageStore("en")
        assertEquals("Settings", en.text(Res.string.screen_settings))
        // Spaces at either end are kept: fragments are joined to other text.
        assertEquals(", ", en.text(Res.string.sep_comma))
        assertEquals(" (government website)", en.text(Res.string.web_proof_government))
        assertEquals("Version 3 · effective 2026-11-05", en.text(Res.string.legal_version_line, 3, "2026-11-05"))
        assertEquals("12 records", en.text(Res.string.settings_history_count, 12))
        assertEquals("Settings", MemoryLanguageStore("ja").text(Res.string.screen_settings))
        for (tag in listOf("zh-TW", "zh-HK", "zh-Hant-TW", "zh")) {
            assertEquals("設定", MemoryLanguageStore(tag).text(Res.string.screen_settings), tag)
        }
        for (tag in listOf("zh-CN", "zh-Hans-CN")) {
            assertEquals("设置", MemoryLanguageStore(tag).text(Res.string.screen_settings), tag)
        }
        assertEquals("版本 3・生效日期 2026-11-05", MemoryLanguageStore("zh-TW").text(Res.string.legal_version_line, 3, "2026-11-05"))
        // Following the system reads the current locale.
        val saved = Locale.getDefault()
        try {
            Locale.setDefault(Locale.TRADITIONAL_CHINESE)
            assertEquals("設定", MemoryLanguageStore().text(Res.string.screen_settings))
            Locale.setDefault(Locale.SIMPLIFIED_CHINESE)
            assertEquals("设置", MemoryLanguageStore().text(Res.string.screen_settings))
            Locale.setDefault(Locale.US)
            assertEquals("Settings", MemoryLanguageStore().text(Res.string.screen_settings))
        } finally {
            Locale.setDefault(saved)
        }
    }

    @Test
    fun languageChoiceIsKept() {
        val store = MemoryLanguageStore()
        assertEquals(null, store.tag.value)
        // The languages come from the translation files, named in themselves.
        assertEquals(listOf("en" to "English", "zh-TW" to "繁體中文", "zh-CN" to "简体中文"), AppLanguage.all.map { it.tag to it.name })
        val english = AppLanguage.of("en")
        store.set(english)
        assertEquals("en", store.tag.value)
        assertEquals(english, AppLanguage.of(store.tag.value))
        assertEquals(english, AppLanguage.of("en-GB"))
        store.set(AppLanguage.SYSTEM)
        assertEquals(null, store.tag.value)
        assertEquals("zh-TW", AppLanguage.of("zh-Hant-TW").tag)
        assertEquals("zh-TW", AppLanguage.of("zh_TW").tag)
        assertEquals("zh-TW", AppLanguage.of("zh-HK").tag)
        assertEquals("zh-CN", AppLanguage.of("zh-Hans-CN").tag)
        assertEquals("zh-CN", AppLanguage.of("zh_CN").tag)
        assertEquals(AppLanguage.SYSTEM, AppLanguage.of("ja"))
    }

    @Test
    fun modelStringsFollowTheLoadedLanguage() = runBlocking<Unit> {
        try {
            AppText.load("en")
            assertEquals("Cancel", tr(Res.string.action_cancel))
            assertEquals("3 credentials added", tr(Res.string.flow_added_count, 3))
            AppText.load("zh-TW")
            assertEquals("取消", tr(Res.string.action_cancel))
            assertEquals("已加入 3 張證件", tr(Res.string.flow_added_count, 3))
            AppText.load("zh-CN")
            assertEquals("已加入 3 张证件", tr(Res.string.flow_added_count, 3))
        } finally {
            AppText.load(null)
        }
    }

    @Test
    fun coreMessagesHaveBothLanguages() {
        val zh = strings("values-zh").filterKeys { it.startsWith("core_") }
        assertEquals(zh.keys, CoreStrings.ZH.keys, "core_ keys of values-zh and CoreStrings (tools/i18n/i18n.py writes both)")
    }

    @Test
    fun coreMessagesAndLegalTextsFollowTheLoadedLanguage() = runBlocking<Unit> {
        try {
            AppText.load("en")
            assertEquals("Signature 2", ct("core_signature_n", 2))
            assertEquals("en", diw.wallet.app.legal.LegalTexts.terms.language)
            assertEquals("LIN, CHE-CHUAN", diw.wallet.app.legal.LegalTexts.DEVELOPER)
            AppText.load("zh-TW")
            assertEquals("簽章 2", ct("core_signature_n", 2))
            assertEquals("zh", diw.wallet.app.legal.LegalTexts.terms.language)
            // Simplified Chinese shows the Traditional Chinese original of the legal documents.
            AppText.load("zh-CN")
            assertEquals("签章 2", ct("core_signature_n", 2))
            assertEquals("zh", diw.wallet.app.legal.LegalTexts.terms.language)
        } finally {
            AppText.load(null)
        }
    }
}

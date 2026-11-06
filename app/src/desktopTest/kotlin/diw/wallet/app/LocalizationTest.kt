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

/** The interface strings (composeResources values and values-zh) and the language the app reads them in. */
class LocalizationTest {
    private val res = File("src/commonMain/composeResources")
    private val han = Regex("[\\u3400-\\u9fff\\uff00-\\uffef\\u3000-\\u303f]")

    private fun strings(dir: String): Map<String, String> =
        Regex("<string name=\"([^\"]+)\">(.*?)</string>", RegexOption.DOT_MATCHES_ALL)
            .findAll(File(res, "$dir/strings.xml").readText())
            .associate { it.groupValues[1] to it.groupValues[2] }

    private fun placeholders(text: String) = Regex("%(\\d+)\\$[sd]").findAll(text).map { it.groupValues[1] }.toSortedSet()

    @Test
    fun bothLanguagesHaveTheSameStrings() {
        val en = strings("values")
        val zh = strings("values-zh")
        assertEquals(en.keys, zh.keys, "keys only in one language")
        en.forEach { (k, v) ->
            if (k != "language_zh_hant") assertTrue(!han.containsMatchIn(v), "Chinese text in the English string $k: $v")
            val z = zh.getValue(k)
            if (z.isNotEmpty()) assertEquals(placeholders(z), placeholders(v), "placeholders of $k")
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
        for (tag in listOf("zh-TW", "zh-HK", "zh-CN", "zh-Hant-TW")) {
            assertEquals("設定", MemoryLanguageStore(tag).text(Res.string.screen_settings), tag)
        }
        assertEquals("版本 3・生效日期 2026-11-05", MemoryLanguageStore("zh-TW").text(Res.string.legal_version_line, 3, "2026-11-05"))
        // Following the system reads the current locale.
        val saved = Locale.getDefault()
        try {
            Locale.setDefault(Locale.TRADITIONAL_CHINESE)
            assertEquals("設定", MemoryLanguageStore().text(Res.string.screen_settings))
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
        store.set(AppLanguage.ENGLISH)
        assertEquals("en", store.tag.value)
        assertEquals(AppLanguage.ENGLISH, AppLanguage.of(store.tag.value))
        store.set(AppLanguage.SYSTEM)
        assertEquals(null, store.tag.value)
        assertEquals(AppLanguage.TRADITIONAL_CHINESE, AppLanguage.of("zh-Hant-TW"))
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
        } finally {
            AppText.load(null)
        }
    }
}

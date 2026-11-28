package diw.wallet.app

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The third-party list the build generates for the desktop (app/third-party.gradle.kts) and how the app reads it. */
class ThirdPartyTest {
    private val catalog: ThirdPartyCatalog = runBlocking { assertNotNull(ThirdParty.catalog(), "files/third-party.json is missing") }

    @Test
    fun listsTheDesktopRuntimeClassPath() {
        assertEquals("desktop", catalog.platform)
        val coordinates = catalog.components.mapNotNull { it.coordinates }.toSet()
        for (c in listOf("org.bouncycastle:bcprov-jdk18on", "org.multipaz:multipaz-jvm", "org.apache.pdfbox:pdfbox", "org.xerial:sqlite-jdbc", "io.ktor:ktor-client-java-jvm")) {
            assertTrue(c in coordinates, "$c is not listed")
        }
        // Android-only libraries and components stay out of the desktop list.
        assertTrue(coordinates.none { it.startsWith("androidx.camera:") })
        assertTrue(catalog.component("component:mobilefacenet") == null)
        assertNotNull(catalog.component("component:temurin"))
        assertNotNull(catalog.component("component:musl"))
    }

    @Test
    fun everyLicenseHasItsFullText() {
        val ids = catalog.licenses.map { it.id }.toSet()
        for (c in catalog.components) {
            assertTrue(c.licenses.isNotEmpty(), "${c.id} has no license")
            c.licenses.forEach { assertTrue(it in ids, "${c.id}: $it is not in the license list") }
            c.texts.forEach { assertTrue(catalog.texts[it]?.isNotBlank() == true, "${c.id}: text $it is missing") }
        }
        for (l in catalog.licenses) {
            assertTrue((catalog.texts[l.text]?.length ?: 0) > 100, "${l.id} has no full text")
            assertTrue(catalog.usersOf(l.id).isNotEmpty(), "${l.id} is listed but unused")
        }
        assertTrue(catalog.license("Apache-2.0")!!.let { catalog.texts.getValue(it.text) }.contains("Apache License"))
    }

    @Test
    fun searchAndGroups() {
        val bc = catalog.search("bouncy", null, "en")
        assertTrue(bc.isNotEmpty() && bc.all { "LicenseRef-BouncyCastle" in it.licenses || it.name.contains("Bouncy", ignoreCase = true) })
        assertTrue(catalog.search("", ThirdPartyKind.LIBRARY, "en").all { it.kind == "library" })
        assertTrue(catalog.components.all { ThirdPartyKind.of(it.kind) != null }, "unknown kind")
        val temurin = catalog.component("component:temurin")!!
        assertTrue(temurin.description("zh")!!.contains("執行環境"))
        assertTrue(temurin.description("ja") == temurin.description("en"))
    }

    @Test
    fun packagesNoticeAndLicense() = runBlocking<Unit> {
        assertTrue(ThirdParty.document("NOTICE")!!.startsWith("DIW MY WALLET"))
        assertTrue(ThirdParty.document("LICENSE")!!.contains("Apache License"))
    }
}

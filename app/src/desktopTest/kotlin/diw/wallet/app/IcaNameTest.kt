package diw.wallet.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The holder's name an identity claims aggregation lists for a held credential. */
class IcaNameTest {
    private fun c(path: String, value: String, label: String? = null) = Triple(path.split('.'), label, value)

    @Test
    fun wholeNameClaimComesFirst() {
        assertEquals("王小明", FilesModel.holderName(listOf(c("given_name", "小明"), c("family_name", "王"), c("name", " 王小明 "))))
        assertEquals("陳大文", FilesModel.holderName(listOf(c("credentialSubject.xm", "陳大文", "姓名"))))
    }

    @Test
    fun familyAndGivenNamesAreJoinedByScript() {
        assertEquals("王小明", FilesModel.holderName(listOf(c("org.iso.18013.5.1.given_name", "小明"), c("org.iso.18013.5.1.family_name", "王"))))
        assertEquals("Alice Smith", FilesModel.holderName(listOf(c("family_name", "Smith"), c("given_name", "Alice"))))
        assertEquals("Smith", FilesModel.holderName(listOf(c("family_name", "Smith"))))
    }

    @Test
    fun noNameClaimGivesNull() {
        assertNull(FilesModel.holderName(listOf(c("birth_date", "1990-01-01"), c("name", " "))))
    }
}

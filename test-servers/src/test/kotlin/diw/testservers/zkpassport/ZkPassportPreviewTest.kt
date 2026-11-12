package diw.testservers.zkpassport

import diw.wallet.core.zkpassport.ZkPassport
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ZkPassportPreviewTest {
    // A fictional passport zone (ICAO 9303 specimen layout, made-up holder).
    private val line1 = "P<UTOERIKSSON<<TAI<MING".padEnd(44, '<')
    private val line2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
    private val mrz = line1 + line2

    @Test fun theFirstNameIsTheFirstGivenNameComponentAsZkPassportSendsIt() {
        val query = Json.parseToJsonElement(
            """{"age":{"gte":18},"firstname":{"disclose":true},"fullname":{"disclose":true},"nationality":{"disclose":true},"document_type":{"disclose":true},"gender":{"eq":"F"}}""",
        ).jsonObject
        assertEquals(
            listOf("firstname" to "TAI", "fullname" to "TAI MING ERIKSSON", "nationality" to "UTO", "document_type" to "passport"),
            ZkPassport.disclosedPreview(mrz, query),
        )
        assertTrue(ZkPassport.firstNameDropsParts(mrz))
        assertFalse(ZkPassport.firstNameDropsParts("P<UTOERIKSSON<<ANNA".padEnd(44, '<') + line2))
        assertEquals(emptyList(), ZkPassport.disclosedPreview("short", query))
    }
}

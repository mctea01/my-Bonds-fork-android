package diw.testservers

import diw.wallet.core.credential.ClaimLabels
import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.util.DiwJson
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

class ClaimLabelsTest {
    private fun config(id: String, json: String) = CredentialConfiguration.parse(id, DiwJson.parseToJsonElement(json).jsonObject)

    private val withNames = config("a", """{"format":"dc+sd-jwt","vct":"urn:a","credential_metadata":{"claims":[
        {"path":["member_no"],"display":[{"name":"會員編號","locale":"zh-TW"},{"name":"Member number","locale":"en"}]},
        {"path":["given_name"],"display":[{"name":"Given name","locale":"en"}]}]}}""")
    private val draft13 = config("b", """{"format":"vc+sd-jwt","credential_definition":{"type":["VerifiableCredential","X"],
        "credentialSubject":{"level":{"display":[{"name":"等級","locale":"zh-TW"}]}}}}""")

    @Test
    fun issuerNamesKeepEveryLanguage() {
        assertEquals(
            mapOf("zh-tw|member_no" to "會員編號", "en|member_no" to "Member number", "en|given_name" to "Given name"),
            ClaimLabels.issuerNames(withNames),
        )
        assertEquals(mapOf("zh-tw|level" to "等級"), ClaimLabels.issuerNames(draft13))
    }

    @Test
    fun fallbackOrder() {
        val labels = ClaimLabels(listOf("zh-TW", "en"))
        val names = ClaimLabels.issuerNames(withNames)
        assertEquals("會員編號", labels.label(listOf("member_no"), names))
        // English-only issuer name loses to the built-in Chinese name; an English user gets the issuer's name.
        assertEquals("名字", labels.label(listOf("given_name"), names))
        assertEquals("Given name", ClaimLabels(listOf("en-US")).label(listOf("given_name"), names))
        assertEquals("Member number", ClaimLabels(listOf("en-GB")).label(listOf("member_no"), names))
        assertEquals("地址 / 城市", labels.label(listOf("address", "locality"), emptyMap()))
        assertEquals("名字", labels.label(listOf("org.iso.18013.5.1", "given_name"), emptyMap()))
        // Learned from one issuer, used for another that gives no names.
        assertEquals("Member no", labels.label(listOf("member_no"), emptyMap()))
        labels.learn(listOf(withNames, draft13))
        assertEquals("會員編號", labels.label(listOf("member_no"), emptyMap()))
        assertEquals("等級", labels.label(listOf("level"), emptyMap()))
        // The same cache serves another region of the language and, after a language change, other languages.
        assertEquals("會員編號", ClaimLabels(listOf("zh-HK"), labels.learned).label(listOf("member_no"), emptyMap()))
        assertEquals("Member number", ClaimLabels(listOf("en"), labels.learned).label(listOf("member_no"), emptyMap()))
        // A name without a locale is used when nothing in the user's language exists.
        val noLocale = config("c", """{"format":"dc+sd-jwt","vct":"urn:c","credential_metadata":{"claims":[
            {"path":["given_name"],"display":[{"name":"First name"}]},{"path":["tier"],"display":[{"name":"Tier"}]}]}}""")
        assertEquals("名字", labels.label(listOf("given_name"), ClaimLabels.issuerNames(noLocale)))
        assertEquals("Tier", labels.label(listOf("tier"), ClaimLabels.issuerNames(noLocale)))
        // Unknown claims: the credential type's name, else the claim name made readable.
        assertEquals("Driving privileges x", labels.label(listOf("driving_privileges_x"), emptyMap()))
        assertEquals("Card number", ClaimLabels(listOf("en")).label(listOf("cardNumber"), emptyMap()))
        assertEquals("Family Name", ClaimLabels(listOf("en")).label(listOf("family_name"), emptyMap(), "Family Name"))
    }
}

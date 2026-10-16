package diw.wallet.core.credential

import diw.wallet.core.oid4vci.CredentialConfiguration
import diw.wallet.core.oid4vci.DisplayInfo
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Claim names in the user's language. Order: names the credential's issuer gave, names learned from other
 * issuers' metadata, built-in names for common claims, an issuer name without a language, the credential type's
 * own name, then the claim name made readable. Issuer and learned names are keyed "locale|claim" for every
 * language the issuer gave, so a later change of the device language still finds them; [learned] is persisted
 * by the caller.
 */
class ClaimLabels(locales: List<String>, val learned: MutableMap<String, String> = mutableMapOf()) {
    private val tag = (locales.firstOrNull() ?: "en").lowercase()
    private val language = tag.substringBefore('-')

    fun label(path: List<String>, issuerNames: Map<String, String>, typeName: String? = null): String {
        val key = path.joinToString(".")
        val name = path.lastOrNull() ?: return key
        find(issuerNames, key)?.let { return it }
        find(learned, key)?.let { return it }
        find(learned, name)?.let { return it }
        BUILT_IN[language]?.get(name)?.let { return withParent(path, it) }
        issuerNames["|$key"]?.let { return it }
        if (typeName != null && typeName != name) return typeName
        return humanize(name)
    }

    /** Remembers the names every configuration of an issuer gives, in all its languages. */
    fun learn(configurations: Collection<CredentialConfiguration>): Boolean {
        var changed = false
        for (c in configurations) {
            for ((k, name) in issuerNames(c)) {
                val locale = k.substringBefore('|')
                if (locale.isEmpty()) continue
                val path = k.substringAfter('|')
                if (learned.put(k, name) != name) changed = true
                if (learned.put("$locale|${path.substringAfterLast('.')}", name) != name) changed = true
            }
        }
        return changed
    }

    /** The user's locale first, then the same language in another region (zh-TW, then zh-HK or zh). */
    private fun find(names: Map<String, String>, key: String): String? =
        names["$tag|$key"] ?: names.entries.firstOrNull { (k, _) ->
            k.substringAfter('|') == key && k.substringBefore('|').substringBefore('-') == language
        }?.value

    private fun withParent(path: List<String>, name: String): String {
        if (path.size < 2) return name
        val parent = BUILT_IN[language]?.get(path[path.size - 2]) ?: return name
        return "$parent / $name"
    }

    companion object {
        /**
         * Claim names from a configuration's metadata (1.0 claims array, or the draft 13 object form) keyed
         * "locale|claim path" with the locale lowercased; a name without a locale is keyed "|claim path".
         */
        fun issuerNames(config: CredentialConfiguration): Map<String, String> {
            val out = mutableMapOf<String, String>()
            val claims = config.claims
            if (claims != null) {
                for (c in claims.filterIsInstance<JsonObject>()) {
                    val path = (c["path"] as? JsonArray)?.map { (it as? JsonPrimitive)?.content ?: "" } ?: continue
                    names(c["display"], path.joinToString("."), out)
                }
            } else {
                // Draft 13: {"claim": {"display": [...]}} or for mdoc {"namespace": {"element": {...}}}.
                (config.raw["claims"] as? JsonObject)?.let { walk(it, emptyList(), out) }
                ((config.raw["credential_definition"] as? JsonObject)?.get("credentialSubject") as? JsonObject)?.let { walk(it, emptyList(), out) }
            }
            return out
        }

        private fun walk(o: JsonObject, prefix: List<String>, out: MutableMap<String, String>) {
            for ((k, v) in o) {
                if (v !is JsonObject) continue
                val path = prefix + k
                v["display"]?.let { names(it, path.joinToString("."), out) }
                walk(v, path, out)
            }
        }

        private fun names(display: JsonElement?, key: String, out: MutableMap<String, String>) {
            for (d in DisplayInfo.list(display as? JsonArray)) {
                val name = d.name ?: continue
                out.putIfAbsent("${d.locale?.lowercase() ?: ""}|$key", name)
            }
        }

        /** given_name -> Given name, cardNumber -> Card number. */
        fun humanize(name: String): String {
            val words = name.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2").replace('_', ' ').replace('-', ' ').trim()
            return words.lowercase().replaceFirstChar { it.uppercase() }
        }

        /** Common claims of OpenID Connect, SD-JWT VC PID, ISO 18013-5 mDL and W3C credentials. */
        val BUILT_IN: Map<String, Map<String, String>> = mapOf(
            "zh" to mapOf(
                "name" to "姓名", "given_name" to "名字", "family_name" to "姓氏", "middle_name" to "中間名",
                "nickname" to "暱稱", "birthdate" to "出生日期", "birth_date" to "出生日期", "gender" to "性別", "sex" to "性別",
                "email" to "電子郵件", "email_address" to "電子郵件", "phone_number" to "電話號碼", "mobile_phone_number" to "手機號碼",
                "address" to "地址", "formatted" to "完整地址", "street_address" to "街道地址", "locality" to "城市", "region" to "地區",
                "postal_code" to "郵遞區號", "country" to "國家", "house_number" to "門牌號碼", "street" to "街道", "city" to "城市",
                "nationality" to "國籍", "nationalities" to "國籍", "picture" to "照片", "portrait" to "照片",
                "birth_family_name" to "出生時姓氏", "birth_given_name" to "出生時名字", "family_name_birth" to "出生時姓氏",
                "given_name_birth" to "出生時名字", "place_of_birth" to "出生地", "birth_place" to "出生地",
                "age_over_12" to "年滿 12 歲", "age_over_14" to "年滿 14 歲", "age_over_16" to "年滿 16 歲",
                "age_over_18" to "年滿 18 歲", "age_over_21" to "年滿 21 歲", "age_over_65" to "年滿 65 歲",
                "age_equal_or_over" to "年齡門檻", "age_in_years" to "年齡", "age_birth_year" to "出生年份",
                "resident_address" to "居住地址", "resident_country" to "居住國家", "resident_state" to "居住州省",
                "resident_city" to "居住城市", "resident_postal_code" to "居住地郵遞區號", "resident_street" to "居住街道",
                "resident_house_number" to "居住門牌號碼", "issuing_authority" to "發證機關", "issuing_country" to "發證國家",
                "issuing_jurisdiction" to "發證轄區", "issuance_date" to "核發日期", "issue_date" to "核發日期",
                "date_of_issuance" to "核發日期", "expiry_date" to "到期日", "date_of_expiry" to "到期日",
                "document_number" to "證件號碼", "personal_administrative_number" to "個人行政編號",
                "administrative_number" to "行政編號", "driving_privileges" to "駕駛類別", "vehicle_category_code" to "車輛類別",
                "un_distinguishing_sign" to "國際識別代碼", "height" to "身高", "weight" to "體重", "eye_colour" to "眼睛顏色",
                "hair_colour" to "頭髮顏色", "portrait_capture_date" to "照片拍攝日期", "signature_usual_mark" to "簽名",
                "id" to "識別碼", "cardNumber" to "卡號", "idNumber" to "身分證字號", "birthDate" to "出生日期",
                "givenName" to "名字", "familyName" to "姓氏", "phone" to "電話", "title" to "職稱", "organization" to "組織",
                "unifiedNo" to "身分證統一編號", "addressOfHousehold" to "戶籍地址", "over18AtIssuance" to "簽發時年滿 18 歲",
            ),
        )
    }
}

package diw.testservers

import diw.wallet.core.did.DidKeys
import diw.wallet.core.did.DidResolver
import diw.wallet.core.document.derived.DocumentFields
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.jose.Jws
import diw.wallet.core.jose.VerificationKey
import diw.wallet.core.jose.signJws
import diw.wallet.core.oid4vp.Oid4vpHolder
import diw.wallet.core.oid4vp.PreparedDerived
import diw.wallet.core.oid4vp.PresentationOutcome
import diw.wallet.core.profile.bonds.BondsHolderDerived
import diw.wallet.core.profile.bonds.DerivedRule
import diw.wallet.core.profile.bonds.HolderDerivedException
import diw.wallet.core.profile.bonds.HolderDerivedSource
import diw.wallet.core.profile.bonds.HolderDerivedTypes
import diw.wallet.core.profile.bonds.HolderHint
import diw.wallet.core.profile.bonds.MyDataParsers
import diw.wallet.core.profile.bonds.MyDataText
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.obj
import diw.wallet.core.util.str
import diw.wallet.core.util.strList
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.encodeURLParameter
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Instant

/**
 * Bonds holder-derived credentials (twdiw-vp-verifier-lite holderDerived): the verifier asks in DCQL with a
 * bonds_rule, the wallet computes the answer from a vault document and mints a one-time SD-JWT VC whose iss and cnf
 * are one fresh key. The mock verifier checks the response the way verifier-lite does. Document texts are synthetic.
 */
class BondsHolderDerivedTest {
    private val verifierKey = runBlocking { Crypto.createEcPrivateKey(EcCurve.P256) }
    private val verifierDid = runBlocking { DidKeys.didKey(verifierKey.publicKey) }
    private val errors = mutableListOf<String>()
    private val disclosed = mutableListOf<Map<String, String>>()
    private val pending = HashMap<String, Triple<String, List<String>, DerivedRule>>()
    private val resolver = DidResolver(HttpClient(MockEngine { respond("", HttpStatusCode.NotFound) }))

    private fun MockRequestHandleScope.json(o: JsonObject, status: HttpStatusCode = HttpStatusCode.OK) =
        respond(o.toString(), status, headersOf(HttpHeaders.ContentType, "application/json"))

    private suspend fun MockRequestHandleScope.handle(request: HttpRequestData): HttpResponseData {
        if (request.url.host != HOST) return respond("", HttpStatusCode.NotFound)
        val path = request.url.encodedPath
        return when {
            path.startsWith("/request/") -> {
                val id = path.removePrefix("/request/")
                val (vct, claims, rule) = pending[id] ?: return respond("", HttpStatusCode.NotFound)
                respond(requestObject(id, vct, claims, rule), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/oauth-authz-req+jwt"))
            }
            path == "/response" -> {
                val form = parseQueryString(request.body.toByteArray().decodeToString())
                val problem = runCatching { check(form["state"]!!, form["vp_token"]!!) }.exceptionOrNull()
                if (problem != null) {
                    errors += problem.message ?: problem.toString()
                    json(buildJsonObject { put("error", "invalid_request") }, HttpStatusCode.BadRequest)
                } else json(buildJsonObject { put("status", "ok") })
            }
            else -> respond("", HttpStatusCode.NotFound)
        }
    }

    private suspend fun requestObject(id: String, vct: String, claims: List<String>, rule: DerivedRule): String = signJws(
        buildJsonObject { put("alg", "ES256"); put("typ", "oauth-authz-req+jwt"); put("kid", DidKeys.verificationMethod(verifierDid)) },
        buildJsonObject {
            put("client_id", verifierDid); put("iss", verifierDid); put("aud", verifierDid)
            put("response_type", "vp_token"); put("response_mode", "direct_post"); put("response_uri", "$ORIGIN/response")
            put("nonce", "nonce-$id"); put("state", id)
            putJsonObject("client_metadata") {
                putJsonObject("vp_formats_supported") { putJsonObject("dc+sd-jwt") { putJsonArray("sd-jwt_alg_values") { add("ES256") } } }
            }
            putJsonObject("dcql_query") {
                putJsonArray("credentials") {
                    addJsonObject {
                        put("id", "derived"); put("format", "dc+sd-jwt")
                        putJsonObject("meta") { putJsonArray("vct_values") { add(vct) } }
                        putJsonArray("claims") { claims.forEach { c -> addJsonObject { putJsonArray("path") { add(c) } } } }
                    }
                }
            }
            put("bonds_rule", rule.toJson())
        },
        AsymmetricKey.AnonymousExplicit(verifierKey, Algorithm.ES256),
    )

    private fun b64sha(s: String) = MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).toBase64Url()

    /** verifier-lite verifyHolderDerivedPresentation, step by step. */
    private suspend fun check(state: String, vpToken: String) {
        val (vct, _, rule) = pending.getValue(state)
        val presentation = ((DiwJson.parseToJsonElement(vpToken) as JsonObject)["derived"] as JsonArray).single().let { (it as JsonPrimitive).content }
        val parts = presentation.split('~')
        val issuerJwt = Jws.parse(parts.first())
        val kb = Jws.parse(parts.last())
        val disclosures = parts.subList(1, parts.size - 1)
        val payload = issuerJwt.payload
        val iss = payload.str("iss")!!
        require(iss.startsWith("did:key:")) { "iss $iss" }
        val issKey = resolver.resolveKey(iss, null).key
        issuerJwt.verify(issKey)
        val cnf = VerificationKey.fromJwk(payload.obj("cnf")!!.obj("jwk")!!)
        require((cnf as VerificationKey.Ec).key == (issKey as VerificationKey.Ec).key) { "presenter is not the issuer" }
        kb.verify(cnf)
        require(kb.header.str("typ") == "kb+jwt") { "kb typ" }
        require(kb.payload.str("aud") == verifierDid) { "aud ${kb.payload.str("aud")}" }
        require(kb.payload.str("nonce") == "nonce-$state") { "nonce" }
        require(kb.payload.str("sd_hash") == b64sha(presentation.substringBeforeLast('~') + "~")) { "sd_hash" }
        require(payload.str("vct") == vct) { "vct" }
        require(payload.str("vct#integrity") == HolderDerivedTypes.byVct(vct)!!.integrity) { "integrity" }
        require(payload.str("assurance") == "holder-derived") { "assurance" }
        val source = payload.obj("source")!!
        require(source.str("kind") == "mydata-downloaded-document" && Regex("^[0-9a-f]{64}$").matches(source.str("sha256")!!)) { "source $source" }
        require(source.str("document_type") == HolderDerivedTypes.byVct(vct)!!.documentType) { "document type" }
        require(DerivedRule.parse(payload["rule"]) == rule) { "rule ${payload["rule"]}" }
        val digests = payload.strList("_sd").toSet()
        val claims = disclosures.associate { d ->
            require(b64sha(d) in digests) { "undisclosed digest" }
            val a = DiwJson.parseToJsonElement(d.fromBase64Url().decodeToString()) as JsonArray
            (a[1] as JsonPrimitive).content to (a[2] as JsonPrimitive).content
        }
        disclosed += claims
    }

    private fun holder(sources: List<HolderDerivedSource>, hints: List<HolderHint> = emptyList()): Oid4vpHolder {
        val http = HttpClient(MockEngine { request -> handle(request) }) { followRedirects = false }
        val w = runBlocking { WalletFixture(trustVerifierRoot = false, trustIssuer = false, httpClient = http, env = EnvironmentPolicy()).init() }
        return Oid4vpHolder(http, w.trust, w.source, w.env, holderIdentities = w.holderIdentities, derivedSources = { sources }, derivedHolders = { hints })
    }

    private fun uri(id: String, type: String, claims: List<String>, rule: DerivedRule): String {
        pending[id] = Triple(HolderDerivedTypes.byDocumentType(type)!!.vct, claims, rule)
        return "openid4vp://?client_id=${verifierDid.encodeURLParameter()}&request_uri=${"$ORIGIN/request/$id".encodeURLParameter()}"
    }

    private fun source(id: String, type: String?, text: String) = HolderDerivedSource(id, "$id.pdf", type, "ab".repeat(32)) { text }

    @Test
    fun incomeCeilingAnsweredFromTheVault() = runBlocking<Unit> {
        val h = holder(listOf(source("income", HolderDerivedTypes.INCOME, INCOME)))
        val rule = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2024", "ceiling_twd" to "500000"))
        val prepared = h.prepare(h.resolveUri(uri("s1", HolderDerivedTypes.INCOME, listOf("tax_year", "income_within_ceiling"), rule))) as PreparedDerived
        assertEquals("true", prepared.plan.answers["income_within_ceiling"])
        assertEquals("2", prepared.plan.answers["payer_count"])
        assertTrue(h.respond(prepared) is PresentationOutcome.Posted)
        assertTrue(errors.isEmpty(), "verifier errors: $errors")
        // Only the asked claims travel; the payer count stays committed but undisclosed.
        assertEquals(mapOf("tax_year" to "2024", "income_within_ceiling" to "true"), disclosed.single())

        // A ceiling below the total answers false; a rule for another year is refused, not answered.
        val low = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2024", "ceiling_twd" to "400000"))
        val p2 = h.prepare(h.resolveUri(uri("s2", HolderDerivedTypes.INCOME, listOf("income_within_ceiling"), low))) as PreparedDerived
        assertEquals("false", p2.plan.answers["income_within_ceiling"])
        val other = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2023", "ceiling_twd" to "500000"))
        val e = assertFailsWith<ProtocolException> { h.prepare(h.resolveUri(uri("s3", HolderDerivedTypes.INCOME, listOf("income_within_ceiling"), other))) }
        assertEquals("access_denied", e.code)
        // A parameter outside the rule is refused before the vault is opened.
        val smuggled = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2024", "ceiling_twd" to "1", "name" to "x"))
        assertFailsWith<ProtocolException> { h.prepare(h.resolveUri(uri("s4", HolderDerivedTypes.INCOME, listOf("income_within_ceiling"), smuggled))) }
    }

    /** Income records of several years stay side by side; the one of the asked year answers. */
    @Test
    fun incomeOfTheAskedYearAmongSeveralYears() = runBlocking<Unit> {
        val older = INCOME.replace("113", "112")
        assertTrue(older != INCOME)
        val h = holder(listOf(source("income-2024", HolderDerivedTypes.INCOME, INCOME), source("income-2023", HolderDerivedTypes.INCOME, older)))
        val r2023 = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2023", "ceiling_twd" to "500000"))
        val p = h.prepare(h.resolveUri(uri("y1", HolderDerivedTypes.INCOME, listOf("tax_year", "income_within_ceiling"), r2023))) as PreparedDerived
        assertEquals("income-2023", p.plan.source.id)
        assertEquals("2023", p.plan.answers["tax_year"])
        val r2024 = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2024", "ceiling_twd" to "500000"))
        val p2 = h.prepare(h.resolveUri(uri("y2", HolderDerivedTypes.INCOME, listOf("tax_year"), r2024))) as PreparedDerived
        assertEquals("income-2024", p2.plan.source.id)
        val r2020 = DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2020", "ceiling_twd" to "500000"))
        val e = assertFailsWith<ProtocolException> { h.prepare(h.resolveUri(uri("y3", HolderDerivedTypes.INCOME, listOf("tax_year"), r2020))) }
        assertTrue("2023、2024" in e.message!!, e.message)
    }

    @Test
    fun householdPicksTheHoldersOwnRow() = runBlocking<Unit> {
        val now = Instant.parse("2026-10-15T00:00:00Z")
        // Two people on one record: the head moved in 2001, the holder in 2026-08; only the holder's date may answer.
        val parsed = MyDataParsers.household(HOUSEHOLD_BLOCKS, listOf(HolderHint("B223456789", "測試持有人")))
        assertEquals("臺北市", parsed.fields[MyDataParsers.CITY])
        assertEquals("中正區", parsed.fields[MyDataParsers.DISTRICT])
        assertEquals("2", parsed.fields[MyDataParsers.MEMBER_COUNT])
        assertEquals("2026-08-01", parsed.fields[MyDataParsers.REGISTERED_SINCE])
        val rule = DerivedRule(DerivedRule.HOUSEHOLD, mapOf("city" to "台北市", "min_months" to "6"))
        val answers = BondsHolderDerived.derive(HolderDerivedTypes.household, parsed, rule, now)
        assertEquals("true", answers["registered_in_city"])
        assertEquals("false", answers["registered_at_least_months"])
        // Picked by name alone when the record masks the ID number.
        assertEquals("2026-08-01", MyDataParsers.household(HOUSEHOLD_BLOCKS.replace("B223456789", "B22****789"), listOf(HolderHint(null, "測試持有人"))).fields[MyDataParsers.REGISTERED_SINCE])
        // The table layout gives the same rows.
        val table = MyDataParsers.household(HOUSEHOLD_TABLE, listOf(HolderHint("B223456789", null)))
        assertEquals("2026-08-01", table.fields[MyDataParsers.REGISTERED_SINCE])
        // Without knowing who the holder is, the record is refused.
        val e = assertFailsWith<HolderDerivedException> { MyDataParsers.household(HOUSEHOLD_BLOCKS) }
        assertTrue("身分證" in e.message!!, e.message)
        val other = assertFailsWith<HolderDerivedException> { MyDataParsers.household(HOUSEHOLD_BLOCKS, listOf(HolderHint("C123456789", "他人"))) }
        assertTrue("2 位住戶" in other.message!!, other.message)

        // Over OpenID4VP, the hints come from the wallet; the record is found by its own text when untyped.
        val h = holder(listOf(source("household", null, HOUSEHOLD_BLOCKS)), listOf(HolderHint("B223456789", "測試持有人")))
        val p = h.prepare(h.resolveUri(uri("h1", HolderDerivedTypes.HOUSEHOLD, listOf("registered_in_city"), DerivedRule(DerivedRule.HOUSEHOLD, mapOf("city" to "臺北市"))))) as PreparedDerived
        assertTrue(h.respond(p) is PresentationOutcome.Posted)
        assertTrue(errors.isEmpty(), "verifier errors: $errors")
        assertEquals(mapOf("registered_in_city" to "true"), disclosed.single())
    }

    /** A record of one person answers only when that person is the holder; someone else's record is refused. */
    @Test
    fun householdOfOnePersonMustBeTheHolder() = runBlocking<Unit> {
        val single = HOUSEHOLD_BLOCKS.lines().let { lines ->
            lines.subList(0, lines.indexOfFirst { it.trim() == "稱謂：子" }).joinToString("\n")
        }
        assertEquals(1, MyDataParsers.householdMembers(single).size)
        val head = MyDataParsers.householdMembers(single).single()
        assertFailsWith<HolderDerivedException> { MyDataParsers.household(single) }
        val notHolder = assertFailsWith<HolderDerivedException> { MyDataParsers.household(single, listOf(HolderHint("B223456789", "測試持有人"))) }
        assertTrue("不是持有人" in notHolder.message!!, notHolder.message)
        val own = MyDataParsers.household(single, listOf(HolderHint(head.idNumber, head.name)))
        assertEquals("true", own.fields[MyDataParsers.HOLDER_MATCHED])
        // The derived credential offers no personal fields of someone else.
        val fields = assertNotNull(DocumentFields.fromHousehold(single, listOf(HolderHint("B223456789", "測試持有人"))))
        assertNull(fields.claims.firstOrNull { it.name == "姓名" })
        assertTrue("不是你" in fields.notice!!, fields.notice)
    }

    /**
     * A whole-household transcript as MyData prints it: every person has the same labels (姓名, 姓名羅馬拼音,
     * 父姓名, 個人註記, 原住民族別...), empty fields end their line, a print-time footer closes each page and the
     * household header is printed again on the next page. The derived credential and the Bonds answer must both use
     * the holder's own block.
     */
    @Test
    fun householdTranscriptIsReadPerPerson() = runBlocking<Unit> {
        val members = MyDataParsers.householdMembers(TRANSCRIPT)
        assertEquals(listOf("測試戶長", "測試配偶", "測試持有人"), members.map { it.name }, "姓名羅馬拼音 and 父姓名 do not start a person")
        assertEquals(listOf("A123456789", "B200000001", "B223456789"), members.map { it.idNumber })
        assertEquals(listOf("2001-05-01", "2010-03-03", "2026-08-01"), members.map { it.since })

        val hint = listOf(HolderHint("B223456789", "測試持有人"))
        val parsed = MyDataParsers.household(TRANSCRIPT, hint)
        assertEquals("3", parsed.fields[MyDataParsers.MEMBER_COUNT])
        assertEquals("2026-08-01", parsed.fields[MyDataParsers.REGISTERED_SINCE])

        val own = assertNotNull(DocumentFields.fromHousehold(TRANSCRIPT, hint))
        val c = own.claims.associate { it.name to it.value }
        assertEquals("測試持有人", c["姓名"])
        assertEquals("B223456789", c["統一編號"])
        assertEquals("CE-SHIH CHIH-YU-JEN", c["姓名羅馬拼音"])
        assertEquals("測試戶長", c["父姓名"])
        assertEquals("現住人口", c["個人註記"])
        assertNull(c["原住民族別"], "an empty field never takes the page footer")
        assertTrue(own.claims.none { "第" in it.value && "頁" in it.value }, "no footer value: ${own.claims}")
        assertEquals("A0000001", c["戶號"])
        assertEquals("3", c["householdMemberCount"])
        assertTrue("第 3 位" in own.notice!!, own.notice)

        // Without knowing who the holder is, only the household's own fields are offered.
        val unknown = assertNotNull(DocumentFields.fromHousehold(TRANSCRIPT, emptyList()))
        assertNull(unknown.claims.firstOrNull { it.name == "姓名" })
        assertEquals("A0000001", unknown.claims.associate { it.name to it.value }["戶號"])
        assertTrue("3 位住戶" in unknown.notice!!)
        // Any other PDF keeps the general reading.
        assertNull(DocumentFields.fromHousehold("在學證明\n姓名：甲", hint))
    }

    @Test
    fun laborInsuranceOnADate() = runBlocking<Unit> {
        val parsed = MyDataParsers.laborInsurance(LABOR)
        assertEquals(2, parsed.periods.size)
        val rule = { d: String -> DerivedRule(DerivedRule.INSURANCE, mapOf("on_date" to d)) }
        assertEquals("true", BondsHolderDerived.derive(HolderDerivedTypes.laborInsurance, parsed, rule("2026-09-01"))["insured_on_date"])
        assertEquals("false", BondsHolderDerived.derive(HolderDerivedTypes.laborInsurance, parsed, rule("2023-01-01"))["insured_on_date"])
        assertEquals("true", BondsHolderDerived.derive(HolderDerivedTypes.laborInsurance, parsed, rule("2021-06-30"))["insured_on_date"])
        // Without the document the request is refused with what to download.
        val h = holder(emptyList())
        val e = assertFailsWith<ProtocolException> { h.prepare(h.resolveUri(uri("l1", HolderDerivedTypes.LABOR_INSURANCE, listOf("insured_on_date"), rule("2026-09-01")))) }
        assertTrue("被保險人投保資料" in e.message!!, e.message)
    }

    /** The tax office summary puts 給付總額, 扣繳稅額 and 所得額 totals on shared lines; only 給付總額 answers the ceiling. */
    @Test
    fun incomeSummaryLineUsesTheGrossTotal() {
        for (text in listOf(INCOME_SUMMARY, INCOME_SUMMARY.replace("(收入)", "（收入）").replace("2,134", "２，１３４"))) {
            val parsed = MyDataParsers.income(text)
            assertEquals("2134", parsed.fields[MyDataParsers.INCOME_TOTAL], text)
            assertEquals("2025", parsed.fields[MyDataParsers.TAX_YEAR])
            val answers = BondsHolderDerived.derive(
                HolderDerivedTypes.income, parsed, DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2025", "ceiling_twd" to "1000")),
            )
            assertEquals("false", answers["income_within_ceiling"])
            val higher = BondsHolderDerived.derive(
                HolderDerivedTypes.income, parsed, DerivedRule(DerivedRule.INCOME, mapOf("tax_year" to "2025", "ceiling_twd" to "3000")),
            )
            assertEquals("true", higher["income_within_ceiling"])
        }
    }

    /** Without a 遷入日期 field the latest move-in in the person's 記事 is the registration date; none at all refuses. */
    @Test
    fun householdDateFromNotes() {
        assertEquals("2023-03-05", MyDataParsers.sinceFromNotes("記事：民國100年01月02日出生登記。民國112年03月05日由新北市板橋區\n遷入登記。"))
        assertEquals("2011-01-02", MyDataParsers.sinceFromNotes("記事：民國100年01月02日出生登記。"))
        val now = Instant.parse("2026-10-15T00:00:00Z")
        val rule = DerivedRule(DerivedRule.HOUSEHOLD, mapOf("city" to "臺北市", "min_months" to "6"))
        val parsed = MyDataParsers.household(HOUSEHOLD_NOTES, listOf(HolderHint("B223456789", null)))
        assertEquals("2026-08-01", parsed.fields[MyDataParsers.REGISTERED_SINCE])
        assertEquals("false", BondsHolderDerived.derive(HolderDerivedTypes.household, parsed, rule, now)["registered_at_least_months"])
        val undated = MyDataParsers.household(
            HOUSEHOLD_NOTES.lines().filterNot { "民國95年" in it || "遷入登記" in it }.joinToString("\n"), listOf(HolderHint("B223456789", null)),
        )
        val e = assertFailsWith<HolderDerivedException> { BondsHolderDerived.derive(HolderDerivedTypes.household, undated, rule, now) }
        assertTrue("遷入日期" in e.message!!, e.message)
    }

    @Test
    fun textHelpers() {
        assertEquals("2024-02-01", MyDataText.isoDate("113/02/01"))
        assertEquals("2024-02-01", MyDataText.isoDate("民國113年2月1日"))
        assertEquals("2024-02-01", MyDataText.isoDate("1130201"))
        assertEquals("2024-02-01", MyDataText.isoDate("２０２４－０２－０１"))
        assertNull(MyDataText.isoDate("113/13/01"))
        assertEquals("1234567", MyDataText.digits("NT$1,234,567 元"))
        assertEquals("2024", MyDataText.gregorianYear("113年度"))
        assertEquals("113", MyDataText.value("所得年度", "所得年度：113  所得人：測試"))
        assertEquals("臺中市", MyDataText.normalised("台中市"))
    }

    companion object {
        const val HOST = "verifier.mock.example"
        const val ORIGIN = "https://$HOST"

        val INCOME = """
            個人所得資料
            所得年度：113
            扣繳單位：測試公司甲  給付總額：300,000
            扣繳單位：測試公司乙  給付總額：150,000
            合計　　450,000
        """.trimIndent()

        val INCOME_SUMMARY = """
            個人所得資料
            所得年度：114
            扣繳單位名稱： 測試銀行股份有限公司
            所得筆數： 共 1 筆 給付總額(收入)合計： 2,134 扣繳稅額合計： 0
            所得額合計： 2,134稽可扣抵稅額合計： 0
            不含分離課稅資料 給付總額(收入)合計： 2,134 扣繳稅額合計： 0
            以下空白
        """.trimIndent()

        val HOUSEHOLD_NOTES = """
            現戶全戶戶籍資料
            戶號：A0000001
            戶籍地址：台北市中正區測試里測試路1號
            稱謂：戶長
            姓名：測試戶長
            統一編號：A123456789
            記事：民國90年05月01日出生登記。
            稱謂：子
            姓名：測試持有人
            統一編號：B223456789
            記事：民國95年02月03日出生登記。民國115年08月01日由新北市板橋區
            遷入登記。
        """.trimIndent()

        val LABOR = """
            被保險人投保資料
            投保單位 加保日期 退保日期
            測試公司甲 110/03/01 110/12/31
            測試公司乙 113/02/01
        """.trimIndent()

        val HOUSEHOLD_BLOCKS = """
            現戶全戶戶籍資料
            戶號：A0000001
            戶籍地址：台北市中正區測試里測試路1號
            稱謂：戶長
            姓名：測試戶長
            統一編號：A123456789
            遷入日期：民國90年05月01日
            稱謂：子
            姓名：測試持有人
            統一編號：B223456789
            遷入日期：民國115年08月01日
        """.trimIndent()

        val TRANSCRIPT = """
            現戶全戶戶籍資料
            戶號：A0000001
            戶長姓名：測試戶長
            戶籍地址：臺北市中正區測試里測試路1號
            稱謂：戶長
            姓名：測試戶長
            姓名羅馬拼音：CE-SHIH HU-CHANG
            統一編號：A123456789
            出生日期：民國060年01月01日
            父姓名：測試祖父
            遷入日期：民國090年05月01日
            個人註記：現住人口
            原住民身分：無
            原住民族別：
            個人記事：1.出生地臺灣省臺北市
            2026-10-15 21:23:08 第 1/3頁
            現戶全戶戶籍資料
            戶號：A0000001
            稱謂：配偶
            姓名：測試配偶
            姓名羅馬拼音：CE-SHIH PEI-OU
            統一編號：B200000001
            出生日期：民國062年02月02日
            父姓名：測試外祖父
            遷入日期：民國099年03月03日
            個人註記：現住人口
            原住民身分：無
            原住民族別：
            2026-10-15 21:23:08 第 2/3頁
            現戶全戶戶籍資料
            戶號：A0000001
            稱謂：子
            姓名：測試持有人
            統一編號：B223456789
            出生日期：民國090年02月02日
            父姓名：測試戶長
            遷入日期：民國115年08月01日
            個人註記：現住人口
            原住民身分：無
            原住民族別：
            個人記事：1.出生地臺灣省屏東縣
            姓名羅馬拼音：CE-SHIH CHIH-YU-JEN
            2026-10-15 21:23:08 第 3/3頁
        """.trimIndent()

        val HOUSEHOLD_TABLE = """
            現戶全戶戶籍資料
            戶號：A0000001
            戶籍地址：臺北市中正區測試里測試路1號
            稱謂 姓名 統一編號 出生日期 遷入日期
            戶長 測試戶長 A123456789 060/01/01 090/05/01
            子 測試持有人 B223456789 090/02/02 115/08/01
        """.trimIndent()
    }
}

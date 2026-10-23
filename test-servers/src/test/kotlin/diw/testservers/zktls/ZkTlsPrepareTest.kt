package diw.testservers.zktls

import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.zktls.ZkTlsPlanner
import diw.wallet.core.zktls.ZkTlsPrepare
import diw.wallet.core.zktls.ZkTlsProfile
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Pages with a picture code: the session this device opens before the query, and its hidden Cookie header. */
class ZkTlsPrepareTest {
    private val picture = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 1, 2, 3)

    private fun profile(prepare: ZkTlsProfile.Prepare = captcha(), headers: Map<String, String> = emptyMap()) = ZkTlsProfile(
        id = "diw.test.captcha/1",
        title = "驗證碼查驗頁",
        host = "site.example",
        prepare = prepare,
        request = ZkTlsProfile.Request(
            method = "POST",
            path = "/result",
            body = "serial={serial}&code={code}",
            headers = headers,
            inputs = listOf(
                ZkTlsProfile.Input("serial", "序號", "^[0-9]{6}$"),
                ZkTlsProfile.Input("code", "驗證碼", "^[A-Za-z0-9]{4}$"),
            ),
        ),
        status = ZkTlsProfile.Status("<h2>[^<]{1,40}</h2>", "OK"),
        fields = listOf(ZkTlsProfile.Field("name", "姓名", "<td id=\"name\">([^<]{1,40})</td>")),
    )

    private fun captcha() = ZkTlsProfile.Prepare("captcha", "/form", "/captcha", "code", listOf("SID"))

    /** A site that opens a session on /form and serves a picture only within it. */
    private fun site(seen: MutableList<String> = mutableListOf(), imageType: String = "image/jpeg") = HttpClient(MockEngine { request ->
        seen += request.url.encodedPath + " " + (request.headers[HttpHeaders.Cookie] ?: "-")
        when (request.url.encodedPath) {
            "/form" -> respond("<form></form>", HttpStatusCode.OK, headersOf(HttpHeaders.SetCookie, listOf("SID=s1; Path=/; Secure; HttpOnly", "OTHER=x; Path=/")))
            "/captcha" -> if (request.headers[HttpHeaders.Cookie]?.contains("SID=s1") == true) {
                respond(picture, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, imageType))
            } else {
                respond("no session", HttpStatusCode.Forbidden)
            }
            else -> respond("", HttpStatusCode.NotFound)
        }
    }) { followRedirects = false }

    @Test
    fun captchaProfilesAreChecked() {
        profile().validated()
        fun bad(p: ZkTlsProfile) = assertFailsWith<ProtocolException> { p.validated() }
        bad(profile(captcha().copy(input = "other")))
        bad(profile(captcha().copy(image = null)))
        bad(profile(captcha().copy(cookies = emptyList())))
        bad(profile(captcha().copy(cookies = listOf("bad name"))))
        bad(profile(captcha().copy(page = "https://other.example/form")))
        bad(profile(captcha().copy(type = "webview")))
        bad(profile(ZkTlsProfile.Prepare(image = "/captcha")))
        bad(profile(headers = mapOf("Cookie" to "SID=fixed")))
    }

    @Test
    fun sessionAndPictureComeFromTheSite() = runBlocking<Unit> {
        val seen = mutableListOf<String>()
        site(seen).use { client ->
            val session = ZkTlsPrepare.start(client, profile())
            assertEquals(mapOf("SID" to "s1"), session.cookies)
            assertContentEquals(picture, session.image)
            assertEquals(listOf("/form -", "/captcha SID=s1"), seen)
            // A new picture continues the same session without opening the form again.
            ZkTlsPrepare.start(client, profile(), session)
            assertEquals("/captcha SID=s1", seen.last())
            assertEquals(3, seen.size)
            assertFalse("s1" in session.toString())
        }
    }

    @Test
    fun notAPictureIsRefused() = runBlocking<Unit> {
        site(imageType = "text/html").use { client ->
            assertFailsWith<ProtocolException> { ZkTlsPrepare.start(client, profile()) }
        }
        site().use { client ->
            assertFailsWith<ProtocolException> { ZkTlsPrepare.start(client, profile(captcha().copy(page = "/missing"))) }
        }
    }

    @Test
    fun sessionCookieIsSentButNotRevealed() {
        val p = profile()
        val bytes = ZkTlsPlanner.request(p, mapOf("serial" to "123456", "code" to "Ab12"), mapOf("SID" to "s1", "OTHER" to "x"))
        val text = bytes.decodeToString()
        assertTrue("\r\nCookie: SID=s1\r\n" in text)
        assertFalse("OTHER" in text)
        val shown = ZkTlsPlanner.sentReveal(p, bytes).joinToString("|") { bytes.copyOfRange(it.start, it.end).decodeToString() }
        assertEquals("POST /result |Host: site.example\r\n", shown)
        assertFailsWith<ProtocolException> { ZkTlsPlanner.request(p, mapOf("serial" to "123456", "code" to "Ab12")) }
        assertFailsWith<ProtocolException> { ZkTlsPlanner.request(p, mapOf("serial" to "123456", "code" to "Ab12"), mapOf("SID" to "a;b")) }
    }

    /** A form page whose CSRF token and picture key are read from the page, sent back in a multipart body. */
    private fun formProfile(
        values: List<ZkTlsProfile.PageValue> = listOf(
            ZkTlsProfile.PageValue("csrf", "name=\"_csrf\" value=\"([0-9a-f-]{8,64})\""),
            ZkTlsProfile.PageValue("key", "id=\"captchaKey\" value=\"([0-9a-f]{8,64})\""),
        ),
        image: String = "/captcha/image?CAPTCHA_KEY={key}",
        encoding: String = "multipart",
        files: List<String> = listOf("uploadFile"),
    ) = profile().let { p ->
        p.copy(
            prepare = captcha().copy(image = image, values = values),
            request = p.request.copy(body = "_csrf={csrf}&serial={serial}&code={code}&captchaKey={key}", encoding = encoding, files = files),
        )
    }

    private fun formSite(seen: MutableList<String>) = HttpClient(MockEngine { request ->
        seen += request.url.encodedPath + "?" + request.url.encodedQuery
        when (request.url.encodedPath) {
            "/form" -> respond("<input name=\"_csrf\" value=\"0a1b2c3d-0000\"/><input id=\"captchaKey\" value=\"feedbeef01\"/>", HttpStatusCode.OK,
                headersOf(HttpHeaders.SetCookie, "SID=s1; Path=/"))
            "/captcha/image" -> if (request.url.parameters["CAPTCHA_KEY"] == "feedbeef01") {
                respond(picture, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "image/jpeg"))
            } else respond("no key", HttpStatusCode.NotFound)
            else -> respond("", HttpStatusCode.NotFound)
        }
    }) { followRedirects = false }

    @Test
    fun pageValuesFillThePictureAndTheForm() = runBlocking<Unit> {
        val p = formProfile().validated()
        val seen = mutableListOf<String>()
        formSite(seen).use { client ->
            val session = ZkTlsPrepare.start(client, p)
            assertEquals(mapOf("csrf" to "0a1b2c3d-0000", "key" to "feedbeef01"), session.values)
            assertEquals("/captcha/image?CAPTCHA_KEY=feedbeef01", seen.last())
            assertFalse("feedbeef01" in session.toString())
            // A new picture keeps the page's values without opening the page again.
            val again = ZkTlsPrepare.start(client, p, session)
            assertEquals(session.values, again.values)
            assertEquals(3, seen.size)

            val bytes = ZkTlsPlanner.request(p, mapOf("serial" to "123456", "code" to "Ab12"), session.cookies, session.values)
            val text = bytes.decodeToString()
            val b = ZkTlsPlanner.BOUNDARY
            assertTrue("\r\nContent-Type: multipart/form-data; boundary=$b\r\n" in text)
            assertTrue("--$b\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n0a1b2c3d-0000\r\n" in text)
            assertTrue("--$b\r\nContent-Disposition: form-data; name=\"serial\"\r\n\r\n123456\r\n" in text)
            assertTrue("--$b\r\nContent-Disposition: form-data; name=\"uploadFile\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n--$b--\r\n" in text)
            val length = text.substringAfter("Content-Length: ").substringBefore("\r\n").toInt()
            assertEquals(length, bytes.size - text.indexOf("\r\n\r\n") - 4)
            val shown = ZkTlsPlanner.sentReveal(p, bytes).joinToString("|") { bytes.copyOfRange(it.start, it.end).decodeToString() }
            assertEquals("POST /result |Host: site.example\r\n", shown)
            // Without the page's values the session has to be prepared again.
            assertFailsWith<ProtocolException> { ZkTlsPlanner.request(p, mapOf("serial" to "123456", "code" to "Ab12"), session.cookies) }
        }
        // A page that no longer carries a value is refused before any picture is shown.
        val changed = formProfile(values = listOf(ZkTlsProfile.PageValue("csrf", "name=\"token\" value=\"([0-9a-f]+)\""),
            ZkTlsProfile.PageValue("key", "id=\"captchaKey\" value=\"([0-9a-f]{8,64})\"")))
        formSite(mutableListOf()).use { client -> assertFailsWith<ProtocolException> { ZkTlsPrepare.start(client, changed) } }
    }

    @Test
    fun pageValuesAreChecked() {
        fun bad(p: ZkTlsProfile) = assertFailsWith<ProtocolException> { p.validated() }
        bad(formProfile(image = "/captcha/image?CAPTCHA_KEY={other}"))
        bad(formProfile(values = listOf(ZkTlsProfile.PageValue("serial", "v=\"([0-9]+)\""))))
        bad(formProfile(values = listOf(ZkTlsProfile.PageValue("csrf", "no group"), ZkTlsProfile.PageValue("key", "k=([0-9]+)"))))
        bad(formProfile(encoding = "form"))
        bad(formProfile(encoding = "json"))
        bad(profile().copy(prepare = ZkTlsProfile.Prepare(values = listOf(ZkTlsProfile.PageValue("csrf", "v=([0-9]+)")))))
        formProfile(encoding = "form", files = emptyList()).validated()
    }

    /** An input's value as a stored document prints it, also when the text breaks it with white space. */
    @Test
    fun inputValueFromDocument() {
        val input = ZkTlsProfile.Input("ccode", "謄本檢查號", "^[A-Za-z0-9]{12}$", document = "檢查號[：:]?([A-Za-z0-9]{12})")
        assertEquals("AB12CD34EF56", input.fromDocument("戶籍謄本\n謄本檢查號：AB12CD34EF56\n"))
        assertEquals("AB12CD34EF56", input.fromDocument("謄本檢查號： AB12CD 34EF56"))
        assertEquals(null, input.fromDocument("謄本檢查號：AB12"))
        assertEquals(null, input.copy(document = null).fromDocument("檢查號：AB12CD34EF56"))
        assertFailsWith<ProtocolException> {
            profile().let { p -> p.copy(request = p.request.copy(inputs = p.request.inputs.map { it.copy(document = "no group") })) }.validated()
        }
    }

    /** Every page profile in the repository, drafts included, parses and validates. */
    @Test
    fun repositoryProfilesValidate() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "templates").isDirectory }
        val files = listOf("templates/zktls", "templates/drafts/zktls").flatMap { File(root, it).listFiles { f -> f.extension == "json" }.orEmpty().toList() }
        assertTrue(files.isNotEmpty())
        files.forEach { f -> ZkTlsProfile.parse(DiwJson.parseToJsonElement(f.readText()) as JsonObject) }
    }
}

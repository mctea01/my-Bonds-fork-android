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

    /** Every page profile in the repository, drafts included, parses and validates. */
    @Test
    fun repositoryProfilesValidate() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "templates").isDirectory }
        val files = listOf("templates/zktls", "templates/drafts/zktls").flatMap { File(root, it).listFiles { f -> f.extension == "json" }.orEmpty().toList() }
        assertTrue(files.isNotEmpty())
        files.forEach { f -> ZkTlsProfile.parse(DiwJson.parseToJsonElement(f.readText()) as JsonObject) }
    }
}

package diw.wallet.app

import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerification
import diw.wallet.core.profile.bonds.BondsAgeVerifier
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import diw.wallet.core.util.str
import diw.wallet.core.zk.OpenAcAgeVerifier
import diw.wallet.core.zk.ZkResult
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.URLProtocol
import io.ktor.http.Url
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.http.isSuccess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * The wallet as a Bonds web age verifier: an age host (the test server, or the user's own deployment of it) issues a
 * Bonds-compatible request QR and receives the holder's proof. When this device can check OpenAC proofs the host only
 * relays the package here and returns this device's verdict to the holder; otherwise the host verifies and this device
 * shows its verdict, labelled as such.
 */
class BondsAgeVerifierFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var job: Job? = null

    /** The configured age host: the user's setting, else the test server in the test environment. */
    fun host(): String? = model.settings.zkVerifierUrl.trim().trimEnd('/').takeIf { it.isNotEmpty() }
        ?: model.settings.takeIf { it.testEnvironment }?.testServerUrl?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }

    /** Plain http is allowed for the test server only, in the test environment. */
    fun insecureHosts(): Set<String> = model.settings.takeIf { it.testEnvironment }?.testServerUrl
        ?.let { runCatching { Url(it.trim()) }.getOrNull() }?.takeIf { it.protocol == URLProtocol.HTTP }
        ?.let { setOf("${it.host}:${it.port}") }.orEmpty()

    fun start(minimumAge: Int, source: BondsCredentialSource, purpose: String) {
        val host = host() ?: run {
            model.message.value = "請先在設定的「零知識證明」頁填入年齡查驗主機"
            return
        }
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("建立年齡查驗請求")
        job = model.scope.launch {
            try {
                val local = model.zk.ageVerifier()
                val engine = (local as? ZkResult.Ok)?.value
                val created = createSession(host, minimumAge, source, purpose, relay = engine != null)
                val request = BondsAgeRequest.parse(created.str("request") ?: throw ProtocolException("server_error", "No request"), insecureHosts())
                val session = created.str("sessionId") ?: throw ProtocolException("server_error", "No session")
                val token = created.str("token") ?: throw ProtocolException("server_error", "No token")
                val note = (local as? ZkResult.Failed)?.let { "這支手機無法驗證（${it.reason}），改由查驗主機驗證。" }
                model.platform.keepScreenOn(true)
                ui.value = OfflineUi.AgeVerifierWaiting(request, Url(host).host, engine != null, note)
                follow(host, session, token, request, engine, note)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed("無法建立年齡查驗：" + model.describe(e))
            } finally {
                model.platform.keepScreenOn(false)
            }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
    }

    private suspend fun createSession(host: String, minimumAge: Int, source: BondsCredentialSource, purpose: String, relay: Boolean): JsonObject {
        val response = model.http.post("$host/api/zkp/sessions") {
            contentType(ContentType.Application.Json)
            setBody(buildJsonObject {
                put("credentialSource", if (source == BondsCredentialSource.SELF_ISSUED) "selfIssued" else "government")
                put("minimumAge", minimumAge)
                put("purpose", purpose)
                put("mode", if (relay) "relay" else "server")
            }.toString())
        }
        val body = response.bodyAsText()
        val json = runCatching { DiwJson.parseToJsonElement(body) as? JsonObject }.getOrNull()
        if (!response.status.isSuccess() || json == null) {
            throw ProtocolException("server_error", json?.str("error_description") ?: "查驗主機回應 HTTP ${response.status.value}")
        }
        return json
    }

    /** Polls the host until the proof arrives (relay: verify it here and answer) or the host's verdict is in. */
    private suspend fun follow(host: String, session: String, token: String, request: BondsAgeRequest, engine: OpenAcAgeVerifier?, note: String?) {
        val url = "$host/api/zkp/sessions/$session?token=${token.encodeURLParameter()}"
        val hostName = Url(host).host
        while (Clock.System.now() < request.expiresAt + GRACE) {
            val state = runCatching { DiwJson.parseToJsonElement(model.http.get(url).bodyAsText()) as? JsonObject }.getOrNull()
            val posted = state?.str("package")
            when {
                engine != null && posted != null -> {
                    ui.value = OfflineUi.AgeVerifierWaiting(request, hostName, true, note, checking = true)
                    finishHere(host, session, token, request, engine, posted)
                    return
                }
                state?.str("state") == "done" -> {
                    val verdict = (state["verdict"] as? JsonObject)?.let { BondsAgeVerdict.parse(it.toString()) }
                    show(OfflineUi.AgeVerifierResult(request, hostName, null, verdict, if (verdict == null) "查驗主機的結果無法讀取" else null))
                    return
                }
                state?.str("state") == "received" ->
                    ui.value = OfflineUi.AgeVerifierWaiting(request, hostName, engine != null, note, checking = true)
            }
            delay(POLL)
        }
        show(OfflineUi.AgeVerifierResult(request, hostName, null, null, EXPIRED))
    }

    private suspend fun finishHere(host: String, session: String, token: String, request: BondsAgeRequest, engine: OpenAcAgeVerifier, posted: String) {
        val hostName = Url(host).host
        val result: OfflineUi.AgeVerifierResult = try {
            val pkg = BondsAgePackage.parse(posted, request)
            val verification = BondsAgeVerifier.verify(pkg, engine, model.didResolver(), model.didTrust)
            answer(host, session, token, verification.verdict())
            OfflineUi.AgeVerifierResult(request, hostName, verification, null, null)
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProtocolException) {
            answer(host, session, token, BondsAgeVerdict("failed", false, "證明回應缺少必要欄位", request.minimumAge, null))
            OfflineUi.AgeVerifierResult(request, hostName, null, null, "收到的證明無法讀取：" + model.describe(e))
        } catch (e: Exception) {
            answer(host, session, token, BondsAgeVerdict("failed", false, "查驗方無法完成驗證", request.minimumAge, null))
            OfflineUi.AgeVerifierResult(request, hostName, null, null, "這支手機無法完成驗證：" + model.describe(e))
        }
        show(result)
    }

    private suspend fun answer(host: String, session: String, token: String, verdict: BondsAgeVerdict) {
        runCatching {
            model.http.post("$host/api/zkp/sessions/$session/verdict?token=${token.encodeURLParameter()}") {
                contentType(ContentType.Application.Json)
                setBody(verdict.encode())
            }
        }
    }

    private fun show(result: OfflineUi.AgeVerifierResult) {
        ui.value = result
        val v = result.verification
        val accepted = v?.accepted ?: result.remote?.accepted ?: false
        val failure = when {
            accepted -> null
            v != null -> v.reason
            else -> result.remote?.reason ?: result.error ?: "沒有收到證明"
        }
        model.record(
            HistoryKind.VERIFIED, "年齡零知識證明", v?.issuerTrust,
            listOfNotNull(v?.let { if (it.selfIssued) "自發卡（持有者自己的金鑰）" else "發卡者 ${shortDid(it.issuerDid)}" }),
            listOf("年滿 ${result.request.minimumAge} 歲"),
            "OpenAC 零知識年齡查驗（Bonds 相容），" + (if (v != null) "在這支手機驗證" else "由 ${result.host} 驗證") +
                "，用途：${result.request.purpose.ifEmpty { "未說明" }}",
            failure,
        )
    }

    private fun shortDid(did: String) = if (did.length > 28) did.take(18) + "…" + did.takeLast(6) else did

    /** What the result screen says about a local verification. */
    companion object {
        val POLL = 1.seconds
        val GRACE = 30.seconds
        const val EXPIRED = "對方沒有在時限內出示，請重新產生查驗請求。"

        fun summary(v: BondsAgeVerification): List<String> = listOfNotNull(
            "出示者證明自己年滿 ${v.request.minimumAge} 歲（出生日期不晚於 ${v.request.cutoff}），沒有交出出生日期或其他欄位。",
            "零知識證明（OpenAC）：在這支手機驗證，耗時 ${v.verifyMs} ms；出示者產生證明 ${v.prepareMs + v.showMs} ms。",
            "出生日期欄位：${v.claimName}",
            if (v.selfIssued) "這是自發卡：由出示者自己的卡片金鑰簽署，不是政府背書。" else null,
            v.reason,
        )
    }
}

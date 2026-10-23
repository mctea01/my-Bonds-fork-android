package diw.wallet.app

import diw.wallet.core.profile.bonds.BondsAgePackage
import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsAgeVerdict
import diw.wallet.core.profile.bonds.BondsAgeVerification
import diw.wallet.core.profile.bonds.BondsAgeVerifier
import diw.wallet.core.profile.bonds.BondsCredentialSource
import diw.wallet.core.profile.bonds.BondsLinkTransport
import diw.wallet.core.jose.PlatformCrypto
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
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * The wallet as a Bonds age verifier. Through an age host (the test server, or the user's own deployment of it) it
 * issues a Bonds-compatible request QR and receives the holder's proof: when this device can check OpenAC proofs the
 * host only relays the package here and returns this device's verdict to the holder; otherwise the host verifies and
 * this device shows its verdict, labelled as such. Nearby ([startNearby]) there is no server at all: the holder's
 * phone sends the package over Bluetooth and this device verifies it and answers over the same link.
 */
class BondsAgeVerifierFlow(private val model: WalletModel, private val ui: MutableStateFlow<OfflineUi>) {
    private var job: Job? = null

    /** This device's OpenAC verifier, or why there is none; replaced in tests. */
    internal var engines: suspend () -> ZkResult<OpenAcAgeVerifier> = { model.zk.ageVerifier() }

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
                val local = engines()
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

    /**
     * A nearby check over the Bonds BLE link: the QR carries a one-time service UUID instead of a response address,
     * this device scans for the holder advertising it, verifies the package here and writes the verdict back.
     */
    fun startNearby(minimumAge: Int, source: BondsCredentialSource, purpose: String) {
        val link = model.platform.bondsLinkCentral ?: run {
            model.message.value = NO_CENTRAL
            return
        }
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("準備藍牙年齡查驗")
        job = model.scope.launch {
            try {
                link.unavailableReason()?.let {
                    ui.value = OfflineUi.Failed("藍牙無法使用：$it")
                    return@launch
                }
                val engine = localEngine("藍牙") ?: return@launch
                val request = BondsAgeRequest.create(minimumAge, source, purpose, null)
                val waiting = OfflineUi.AgeVerifierWaiting(request, BLUETOOTH, relay = true, note = null)
                model.platform.keepScreenOn(true)
                ui.value = waiting
                var result: OfflineUi.AgeVerifierResult? = null
                withTimeoutOrNull(request.expiresAt + GRACE - Clock.System.now()) {
                    link.receive(request.linkServiceId!!, BondsLinkTransport.AGE_MAX_PAYLOAD, onProgress = { text ->
                        (ui.value as? OfflineUi.AgeVerifierWaiting)?.takeIf { it.request == request }?.let { ui.value = it.copy(link = text) }
                    }, answer = { bytes ->
                        ui.value = waiting.copy(checking = true)
                        val (shown, verdict) = check(request, BLUETOOTH, engine, bytes.decodeToString())
                        result = shown
                        verdict.encode().encodeToByteArray()
                    })
                }
                show(result ?: OfflineUi.AgeVerifierResult(request, BLUETOOTH, null, null, EXPIRED))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed("藍牙年齡查驗沒有完成：" + model.describe(e))
            } finally {
                model.platform.keepScreenOn(false)
            }
        }
    }

    /**
     * A check over the local network: this device listens on its Wi-Fi or hotspot address, the QR names that address,
     * and the holder's phone on the same network posts the package here. No server, no Internet; the verdict is the
     * reply to the holder's post.
     */
    fun startLan(minimumAge: Int, source: BondsCredentialSource, purpose: String) {
        val lan = model.platform.bondsLan ?: run {
            model.message.value = "這個平台無法在區網接收證明，請改用藍牙或查驗主機。"
            return
        }
        stop()
        model.screen.value = Screen.Offline
        ui.value = OfflineUi.Working("準備區網年齡查驗")
        job = model.scope.launch {
            try {
                val address = lan.localAddresses().firstOrNull() ?: run {
                    ui.value = OfflineUi.Failed(NO_LAN)
                    return@launch
                }
                val engine = localEngine("區網") ?: return@launch
                val host = "區網 $address"
                var request: BondsAgeRequest? = null
                var result: OfflineUi.AgeVerifierResult? = null
                model.platform.keepScreenOn(true)
                withTimeoutOrNull(BondsAgeRequest.LIFETIME + GRACE) {
                    lan.serve(address, "/age/" + PlatformCrypto.randomBytes(16).toBase64Url(), BondsLinkTransport.AGE_MAX_PAYLOAD, onListening = { url ->
                        request = BondsAgeRequest.create(minimumAge, source, purpose, url)
                            .also { ui.value = OfflineUi.AgeVerifierWaiting(it, host, relay = true, note = null) }
                    }) { body ->
                        val r = request!!
                        ui.value = OfflineUi.AgeVerifierWaiting(r, host, relay = true, note = null, checking = true)
                        val (shown, verdict) = check(r, host, engine, body.decodeToString())
                        // A body that is not a package for this request (another device on the network) does not end the check.
                        if (shown.verification != null) result = shown
                        else ui.value = OfflineUi.AgeVerifierWaiting(r, host, relay = true, note = shown.error)
                        verdict.encode().encodeToByteArray() to (shown.verification != null)
                    }
                }
                show(result ?: OfflineUi.AgeVerifierResult(request ?: return@launch, host, null, null, EXPIRED))
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                ui.value = OfflineUi.Failed("區網年齡查驗沒有完成：" + model.describe(e))
            } finally {
                model.platform.keepScreenOn(false)
            }
        }
    }

    /** This device's verifier for a serverless check over [how], or null after showing why there is none. */
    private suspend fun localEngine(how: String): OpenAcAgeVerifier? = when (val r = engines()) {
        is ZkResult.Ok -> r.value
        is ZkResult.Failed -> {
            ui.value = OfflineUi.Failed("這支手機無法驗證年齡證明（${r.reason}）。${how}查驗要在這支手機驗證，可改用查驗主機。")
            null
        }
        ZkResult.Cancelled -> null
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
        val (result, verdict) = check(request, Url(host).host, engine, posted)
        answer(host, session, token, verdict)
        show(result)
    }

    /** Verifies a received package on this device: what to show here and the verdict to return to the holder. */
    private suspend fun check(request: BondsAgeRequest, host: String, engine: OpenAcAgeVerifier, posted: String): Pair<OfflineUi.AgeVerifierResult, BondsAgeVerdict> = try {
        val pkg = BondsAgePackage.parse(posted, request)
        val verification = BondsAgeVerifier.verify(pkg, engine, model.didResolver(), model.didTrust)
        OfflineUi.AgeVerifierResult(request, host, verification, null, null) to verification.verdict()
    } catch (e: CancellationException) {
        throw e
    } catch (e: ProtocolException) {
        OfflineUi.AgeVerifierResult(request, host, null, null, "收到的證明無法讀取：" + model.describe(e)) to
            BondsAgeVerdict("failed", false, "證明回應缺少必要欄位", request.minimumAge, null)
    } catch (e: Exception) {
        OfflineUi.AgeVerifierResult(request, host, null, null, "這支手機無法完成驗證：" + model.describe(e)) to
            BondsAgeVerdict("failed", false, "查驗方無法完成驗證", request.minimumAge, null)
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
            "OpenAC 零知識年齡查驗（Bonds 相容）" + (if (result.request.nearby) "，藍牙直接收到、不經伺服器" else if (result.request.lan) "，區網直接收到、不經伺服器" else "") +
                (if (v != null) "，在這支手機驗證" else "，由 ${result.host} 驗證") +
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
        const val BLUETOOTH = "藍牙"
        const val NO_LAN = "這支手機沒有連上 Wi-Fi 或開啟熱點，無法用區網查驗。請兩支手機連上同一個 Wi-Fi，或由其中一支開熱點讓另一支連上。"
        const val NO_CENTRAL = "這個平台無法以藍牙接收證明，請改用查驗主機。"

        fun summary(v: BondsAgeVerification): List<String> = listOfNotNull(
            "出示者證明自己年滿 ${v.request.minimumAge} 歲（出生日期不晚於 ${v.request.cutoff}），沒有交出出生日期或其他欄位。",
            "零知識證明（OpenAC）：在這支手機驗證，耗時 ${v.verifyMs} ms；出示者產生證明 ${v.prepareMs + v.showMs} ms。",
            "出生日期欄位：${v.claimName}",
            if (v.selfIssued) "這是自發卡：由出示者自己的卡片金鑰簽署，不是政府背書。" else null,
            v.reason,
        )
    }
}

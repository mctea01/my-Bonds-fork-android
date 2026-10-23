package diw.wallet.app

import diw.wallet.core.profile.bonds.BondsAgeRequest
import diw.wallet.core.profile.bonds.BondsPresentationRequest
import diw.wallet.core.profile.bonds.LanInterface
import io.ktor.http.Url

/** Technical details of serverless checks, shown folded under the main text so people see the network, not addresses. */
internal object LanDetails {
    /** "address:port" of a local network URL. */
    fun hostPort(url: String): String = runCatching { Url(url).let { "${it.host}:${it.port}" } }.getOrDefault(url)

    /** One line per listening URL with the network card it is on. */
    fun listening(urls: List<String>, interfaces: List<LanInterface>): List<String> = urls.map { url ->
        val host = runCatching { Url(url).host }.getOrNull()
        val card = interfaces.firstOrNull { it.address == host }?.let { i -> listOf(i.kind.title, i.label).distinct().joinToString("，") }
        "接收位址：" + hostPort(url) + (card?.let { "（$it）" } ?: "")
    }

    fun presentation(request: BondsPresentationRequest, listening: List<String> = emptyList()): List<String> = buildList {
        add("挑戰值：${request.challenge}")
        add("建立時間：${request.createdAt}")
        request.linkServiceId?.let { add("藍牙服務 UUID：$it") }
        add(if (request.qr) "對方畫面：DIWQ1 動態 QR Code（噴泉碼），Bonds 為 BTWVP1 輪播" else "對方畫面：BTWVP1 輪播 QR Code")
        addAll(listening)
        if (request.lanKey != null) {
            add("區網傳輸：HTTP，出示內容另以這次挑戰的一次性金鑰加密（ECDH-ES P-256，A256GCM），其他裝置無法讀取")
        }
    }

    fun age(request: BondsAgeRequest, listening: List<String> = emptyList()): List<String> = buildList {
        add("請求編號：${request.requestId}")
        add("出生日期截止：${request.cutoff}")
        request.linkServiceId?.let { add("藍牙服務 UUID：$it") }
        addAll(listening)
        if (listening.isNotEmpty()) add("區網傳輸：HTTP，證明包只含零知識證明與發卡者，不含出生日期")
    }
}

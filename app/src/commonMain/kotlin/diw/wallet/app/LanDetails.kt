package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
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
        val card = interfaces.firstOrNull { it.address == host }?.let { i -> listOf(i.kind.title, i.label).distinct().joinToString(tr(Res.string.sep_comma)) }
        tr(Res.string.lan_receive_at) + hostPort(url) + (card?.let { tr(Res.string.parenthesized, it) } ?: "")
    }

    fun presentation(request: BondsPresentationRequest, listening: List<String> = emptyList()): List<String> = buildList {
        add(tr(Res.string.lan_challenge, request.challenge))
        add(tr(Res.string.lan_created, request.createdAt))
        request.linkServiceId?.let { add(tr(Res.string.lan_ble_uuid, it)) }
        add(if (request.qr) tr(Res.string.lan_screen_diwq) else tr(Res.string.lan_screen_btwvp))
        addAll(listening)
        if (request.lanKey != null) {
            add(tr(Res.string.lan_transport_encrypted))
        }
    }

    fun age(request: BondsAgeRequest, listening: List<String> = emptyList()): List<String> = buildList {
        add(tr(Res.string.lan_request_id, request.requestId))
        add(tr(Res.string.lan_cutoff, request.cutoff))
        request.linkServiceId?.let { add(tr(Res.string.lan_ble_uuid, it)) }
        addAll(listening)
        if (listening.isNotEmpty()) add(tr(Res.string.lan_transport_age))
    }
}

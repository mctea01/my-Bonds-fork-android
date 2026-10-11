package diw.wallet.core.profile.twdiw

import diw.wallet.core.compat.TwdiwDialect
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.HttpHeaders

/**
 * Endpoints of the TWDIW platform (Taiwan Digital Wallet, Ministry of Digital Affairs). Production is the official
 * trust domain; UAT and the sandboxes are test domains and only count when the test environment is enabled.
 */
data class TwdiwPlatform(
    /** frontend host serving the trust list (/api/did), the service catalogues and the QR relay pages. */
    val frontendUrl: String = PRODUCTION_FRONTEND,
    /** Arbitrum One JSON-RPC endpoints, tried in order for the trust list anchor check. */
    val arbitrumRpcUrls: List<String> = listOf(ARBITRUM_RPC),
    val anchorContract: String = ANCHOR_CONTRACT,
    /** True for UAT / sandbox: decisions are TEST environment and never official. */
    val test: Boolean = false,
) {
    val frontendHost: String get() = frontendUrl.substringAfter("://").substringBefore('/').substringBefore(':')

    companion object {
        const val PRODUCTION_FRONTEND = "https://frontend.wallet.gov.tw"
        const val UAT_FRONTEND = "https://frontend-uat.wallet.gov.tw"
        const val ARBITRUM_RPC = "https://arb1.arbitrum.io/rpc"
        /** TWDIW DID registry contract on Arbitrum One. */
        const val ANCHOR_CONTRACT = "0x84172caf8dd126c76f1fa8a2733ca3233264d31f"
        /** Hosts of the official demo and sandbox services; never part of the production trust list. */
        val SANDBOX_HOSTS = setOf(
            "issuer-sandbox.wallet.gov.tw",
            "verifier-sandbox.wallet.gov.tw",
            "issuer-oid4vci.wallet.gov.tw",
            "verifier-oid4vp.wallet.gov.tw",
            "frontend-uat.wallet.gov.tw",
        )
        /** 7-ELEVEN convenience store pickup service (DWVP-05). */
        const val PICKUP_711_VP_UID = "22555003_711pickup"

        val PRODUCTION = TwdiwPlatform()
        val UAT = TwdiwPlatform(frontendUrl = UAT_FRONTEND, test = true)

        /**
         * Default User-Agent for TWDIW hosts. Their Cloudflare front rejects HTTP library default agents
         * (error 1010); the platform HTTP stack's agent string is accepted. Configurable in the app settings.
         */
        const val DEFAULT_USER_AGENT = "Dalvik/2.1.0 (Linux; U; Android 14)"
    }
}

/** Configuration of [TwdiwUserAgent]. */
class TwdiwUserAgentConfig {
    var userAgent: () -> String = { TwdiwPlatform.DEFAULT_USER_AGENT }
}

/**
 * Sets the User-Agent on requests to TWDIW hosts (wallet.gov.tw) only, so that other services keep the client's
 * own agent and no request outside TWDIW looks like the platform's own software.
 */
val TwdiwUserAgent = createClientPlugin("TwdiwUserAgent", ::TwdiwUserAgentConfig) {
    val agent = pluginConfig.userAgent
    onRequest { request, _ ->
        if (TwdiwDialect.isTwdiwHost(request.url.host)) {
            request.headers.remove(HttpHeaders.UserAgent)
            request.headers.append(HttpHeaders.UserAgent, agent())
        }
    }
}

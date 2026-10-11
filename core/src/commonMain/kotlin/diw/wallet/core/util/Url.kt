package diw.wallet.core.util

import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.parseQueryString

/** Splits a URI (custom scheme or https) into its query parameters. Fragment is ignored. */
fun queryParameters(uri: String): Parameters {
    val noFragment = uri.substringBefore('#')
    val q = noFragment.substringAfter('?', "")
    return parseQueryString(q)
}

/** Returns the origin (scheme://host[:port]) of an http(s) URL. */
fun originOf(url: String): String {
    val u = Url(url)
    val defaultPort = u.protocol.defaultPort
    return if (u.port == defaultPort) "${u.protocol.name}://${u.host}" else "${u.protocol.name}://${u.host}:${u.port}"
}

fun hostOf(url: String): String = Url(url).host

/**
 * Builds a well-known URL using RFC 8414 / OpenID4VCI path insertion:
 * https://host/path + suffix -> https://host/.well-known/suffix/path
 */
fun wellKnownUrl(identifier: String, suffix: String): String {
    val u = Url(identifier.trimEnd('/'))
    val path = u.segments.filter { it.isNotEmpty() }.joinToString("/", prefix = "/").takeIf { it != "/" } ?: ""
    return "${originOf(identifier)}/.well-known/$suffix$path"
}

/** Legacy OpenID Connect style: https://host/path/.well-known/suffix */
fun wellKnownUrlAppended(identifier: String, suffix: String): String =
    identifier.trimEnd('/') + "/.well-known/" + suffix

/**
 * Checks whether a URL is acceptable as an endpoint. HTTPS is required; plain HTTP is only allowed for
 * local test hosts ([isLocalTestHost]) and only when [allowInsecureLoopback] is set (test environment).
 */
fun isAcceptableEndpoint(url: String, allowInsecureLoopback: Boolean): Boolean {
    val u = try { Url(url) } catch (_: Exception) { return false }
    return when (u.protocol.name) {
        "https" -> true
        "http" -> allowInsecureLoopback && isLocalTestHost(u.host)
        else -> false
    }
}

/** Hosts a local test server can run on: loopback, the emulator's host alias and private IPv4 networks (RFC 1918). */
fun isLocalTestHost(host: String): Boolean {
    if (host == "localhost" || host == "::1" || host == "[::1]") return true
    val p = host.split('.').map { it.toIntOrNull() ?: return false }
    if (p.size != 4 || p.any { it !in 0..255 }) return false
    return p[0] == 127 || p[0] == 10 || (p[0] == 172 && p[1] in 16..31) || (p[0] == 192 && p[1] == 168)
}

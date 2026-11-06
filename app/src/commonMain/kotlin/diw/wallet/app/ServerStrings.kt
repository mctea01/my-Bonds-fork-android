package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res

/**
 * Every user-facing text of the production server settings, its sharing and the choice between two parties' servers,
 * kept in one place for translation.
 */
object ServerStrings {
    val POLICY_TITLE: String get() = tr(Res.string.server_policy_title)
    val POLICY_PREFER_OWN: String get() = tr(Res.string.server_prefer_own)
    val POLICY_PREFER_OWN_DETAIL: String get() = tr(Res.string.server_prefer_own_text)
    val POLICY_PREFER_PEER: String get() = tr(Res.string.server_prefer_peer)
    val POLICY_PREFER_PEER_DETAIL: String get() = tr(Res.string.server_prefer_peer_text)
    val POLICY_OWN_ONLY: String get() = tr(Res.string.server_own_only)
    val POLICY_OWN_ONLY_DETAIL: String get() = tr(Res.string.server_own_only_text)
    val POLICY_NOTE: String get() = tr(Res.string.server_policy_note_1) +
        tr(Res.string.server_policy_note_2)

    val SHARE: String get() = tr(Res.string.server_share)
    val SHARE_TITLE: String get() = tr(Res.string.server_share_title)
    val SHARE_INCLUDE_TOKEN: String get() = tr(Res.string.server_share_token)
    val SHARE_NOTE: String get() = tr(Res.string.server_share_note)
    val SHARE_PEER_NOTE: String get() = tr(Res.string.server_share_peer_note)
    val SHARE_NOTHING: String get() = tr(Res.string.server_share_nothing)
    val SHOW_MY_SERVER: String get() = tr(Res.string.server_show_mine)
    val COPY_LINK: String get() = tr(Res.string.server_copy_link)
    val LINK_COPIED: String get() = tr(Res.string.server_link_copied)
    val CLOSE: String get() = tr(Res.string.action_close)

    val IMPORT: String get() = tr(Res.string.server_import)
    val IMPORT_FIELD: String get() = tr(Res.string.server_import_field)
    val IMPORT_TITLE: String get() = tr(Res.string.server_import_title)
    val IMPORT_AS_MINE: String get() = tr(Res.string.server_import_mine)
    val IMPORT_FOR_SESSION: String get() = tr(Res.string.server_import_session)
    val IMPORT_CANCEL: String get() = tr(Res.string.action_cancel)
    val IMPORT_TOKEN: String get() = tr(Res.string.server_import_token)
    val IMPORT_REPLACES: String get() = tr(Res.string.server_import_replaces)
    val IMPORT_TRUST_NOTE: String get() = tr(Res.string.server_import_trust)

    val USE_PEER: String get() = tr(Res.string.server_use_peer)
    val USE_PEER_NOTE: String get() = tr(Res.string.server_use_peer_note_1) +
        tr(Res.string.server_use_peer_note_2)
    val SCAN_PEER: String get() = tr(Res.string.server_scan_peer)

    val FEDERATION_CONFIRMED: String get() = tr(Res.string.server_federation_confirmed)
    val SETTINGS_DIGEST: String get() = tr(Res.string.server_settings_digest)

    fun policyName(policy: ServerPolicy): String = when (policy) {
        ServerPolicy.PREFER_OWN -> POLICY_PREFER_OWN
        ServerPolicy.PREFER_PEER -> POLICY_PREFER_PEER
        ServerPolicy.OWN_ONLY -> POLICY_OWN_ONLY
    }

    fun policyDetail(policy: ServerPolicy): String = when (policy) {
        ServerPolicy.PREFER_OWN -> POLICY_PREFER_OWN_DETAIL
        ServerPolicy.PREFER_PEER -> POLICY_PREFER_PEER_DETAIL
        ServerPolicy.OWN_ONLY -> POLICY_OWN_ONLY_DETAIL
    }

    fun peerInUse(host: String) = tr(Res.string.server_peer_in_use, host)
    fun peerForSession(host: String) = tr(Res.string.server_peer_session, host)
    fun shareFingerprintMismatch(host: String) = tr(Res.string.server_fingerprint_mismatch, host)
    fun shareFingerprintMatches() = tr(Res.string.server_fingerprint_match)
    fun federationVerified(anchor: String) = tr(Res.string.server_federation_verified, anchor)
    fun federationMismatch(anchor: String) = tr(Res.string.server_federation_mismatch, anchor)
    fun ownOnlyNoRoute(host: String?) = if (host == null) {
        tr(Res.string.server_own_only_none)
    } else {
        tr(Res.string.server_own_only_unlisted, host)
    }
    fun noPeerRelay(own: String?) = if (own == null) {
        tr(Res.string.server_no_relay)
    } else {
        tr(Res.string.server_no_relay_own, own)
    }
    val AGE_NO_HOST: String get() = tr(Res.string.server_age_no_host)
}

/** How two wallets with different production servers settle on one for a check between them. */
enum class ServerPolicy(val id: String) {
    PREFER_OWN("prefer_own"),
    PREFER_PEER("prefer_peer"),
    OWN_ONLY("own_only");

    companion object {
        fun of(id: String): ServerPolicy = entries.firstOrNull { it.id == id } ?: PREFER_OWN
    }
}

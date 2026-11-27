package diw.wallet.app.legal

import androidx.compose.runtime.Composable
import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource

/** Interface strings of the first-start pages and the legal settings, read from the string resources (legal_*). */
object LegalStrings {
    val SUMMARY: String @Composable get() = stringResource(Res.string.legal_summary)
    /** Shown above a translated legal text: the Chinese original prevails (empty in Chinese). */
    val TRANSLATION_NOTE: String @Composable get() = stringResource(Res.string.legal_translation_note)
    val OPEN_ONLINE: String @Composable get() = stringResource(Res.string.legal_open_online)

    @Composable

    fun versionLine(version: Int, date: String) = stringResource(Res.string.legal_version_line, version, date)

    // Welcome
    val WELCOME_TITLE: String @Composable get() = stringResource(Res.string.legal_welcome_title)
    val WELCOME_TEXT: String @Composable get() = stringResource(Res.string.legal_welcome_text)
    val WELCOME_POINTS: List<Pair<String, String>>
        @Composable get() = listOf(
            stringResource(Res.string.legal_welcome_point_0_title) to stringResource(Res.string.legal_welcome_point_0_text),
            stringResource(Res.string.legal_welcome_point_1_title) to stringResource(Res.string.legal_welcome_point_1_text),
            stringResource(Res.string.legal_welcome_point_2_title) to stringResource(Res.string.legal_welcome_point_2_text),
        )
    val WELCOME_START: String @Composable get() = stringResource(Res.string.legal_welcome_start)
    val STEPS_TITLE: String @Composable get() = stringResource(Res.string.legal_steps_title)
    val STEPS_REQUIRED: String @Composable get() = stringResource(Res.string.legal_steps_required)
    @Composable
    fun stepsOptional(count: Int) = stringResource(Res.string.legal_steps_optional, count)

    /** Marks the terms and the privacy policy (required) and the integration statements (optional). */
    val REQUIRED: String @Composable get() = stringResource(Res.string.legal_required)
    val OPTIONAL: String @Composable get() = stringResource(Res.string.legal_optional)

    // Terms and privacy
    val BASICS_TITLE: String @Composable get() = stringResource(Res.string.legal_basics_title)
    val BASICS_UPDATED: String @Composable get() = stringResource(Res.string.legal_basics_updated)
    val AGREE_CONTINUE: String @Composable get() = stringResource(Res.string.legal_agree_continue)
    val DISAGREE: String @Composable get() = stringResource(Res.string.legal_disagree)
    val DISAGREE_TITLE: String @Composable get() = stringResource(Res.string.legal_disagree_title)
    val DISAGREE_TEXT: String @Composable get() = stringResource(Res.string.legal_disagree_text)
    val BACK_TO_READING: String @Composable get() = stringResource(Res.string.legal_back_to_reading)

    // Statements
    val STATEMENTS_TITLE: String @Composable get() = stringResource(Res.string.legal_statements_title)
    val STATEMENTS_UPDATED: String @Composable get() = stringResource(Res.string.legal_statements_updated)
    @Composable
    fun operatorLine(operator: String) = stringResource(Res.string.legal_operator_line, operator)
    val ACCEPT_ENABLE: String @Composable get() = stringResource(Res.string.legal_accept_enable)
    val DECLINE_DISABLE: String @Composable get() = stringResource(Res.string.legal_decline_disable)

    // The consent page
    val CONSENT_TITLE: String @Composable get() = stringResource(Res.string.legal_consent_title)
    val CONSENT_TEXT: String @Composable get() = stringResource(Res.string.legal_consent_text)
    /** One check box for both required texts; %1$s and %2$s are the links [LINK_TERMS] and [LINK_PRIVACY]. */
    val AGREE_BASICS: String @Composable get() = stringResource(Res.string.legal_agree_basics)
    val LINK_TERMS: String @Composable get() = stringResource(Res.string.legal_link_terms)
    val LINK_PRIVACY: String @Composable get() = stringResource(Res.string.legal_link_privacy)
    /** The optional check box of an integration; %1$s is the link to its statement. */
    val AGREE_STATEMENT: String @Composable get() = stringResource(Res.string.legal_agree_statement)
    val OPTIONAL_HINT: String @Composable get() = stringResource(Res.string.legal_optional_hint)
    /** "%1$s, %2$s": the operator line and the link [OPERATOR_SITE] to the operator's own page about the service. */
    val OPERATOR_WITH_LINK: String @Composable get() = stringResource(Res.string.legal_operator_with_link)
    val OPERATOR_SITE: String @Composable get() = stringResource(Res.string.legal_operator_site)
    val SHOW_POINTS: String @Composable get() = stringResource(Res.string.legal_show_points)
    val HIDE_POINTS: String @Composable get() = stringResource(Res.string.legal_hide_points)
    val BACK: String @Composable get() = stringResource(Res.string.action_back)
    val OPTIONAL_TITLE: String @Composable get() = stringResource(Res.string.legal_optional_title)

    /** What the integration is for, in one line. */
    @Composable
    fun purpose(i: Integration): String = stringResource(
        when (i) {
            Integration.TWDIW -> Res.string.legal_purpose_twdiw
            Integration.MS_VERIFIED_ID -> Res.string.legal_purpose_ms_verified_id
            Integration.MOBILE_MOICA -> Res.string.legal_purpose_mobile_moica
            Integration.MYDATA -> Res.string.legal_purpose_mydata
            Integration.ZKPASSPORT -> Res.string.legal_purpose_zkpassport
        },
    )

    // Done
    val DONE_TITLE: String @Composable get() = stringResource(Res.string.legal_done_title)
    val DONE_TEXT: String @Composable get() = stringResource(Res.string.legal_done_text)
    val DONE_START: String @Composable get() = stringResource(Res.string.legal_done_start)
    val DONE_GUIDE: String @Composable get() = stringResource(Res.string.legal_done_guide)
    val DONE_REQUIRED: String @Composable get() = stringResource(Res.string.legal_done_required)
    val DONE_ACCEPTED: String @Composable get() = stringResource(Res.string.legal_done_accepted)
    val DONE_OPTIONAL: String @Composable get() = stringResource(Res.string.legal_done_optional)

    // Settings
    val SETTINGS_SECTION: String @Composable get() = stringResource(Res.string.legal_settings_section)
    val SETTINGS_BASICS: String @Composable get() = stringResource(Res.string.legal_settings_basics)
    val SETTINGS_STATEMENTS_TEXT: String @Composable get() = stringResource(Res.string.legal_settings_statements_text)
    val SETTINGS_ONLINE: String @Composable get() = stringResource(Res.string.legal_settings_online)
    @Composable
    fun acceptedLine(version: Int, date: String) = stringResource(Res.string.legal_accepted_line, version, date)
    @Composable
    fun settingsSummary(enabled: Int, total: Int) = stringResource(Res.string.legal_settings_summary, enabled, total)

    // Statement page and status
    @Composable
    fun enabledLine(version: Int, date: String) = stringResource(Res.string.legal_enabled_line, version, date)
    val DISABLED_LINE: String @Composable get() = stringResource(Res.string.legal_disabled_line)
    val PENDING_LINE: String @Composable get() = stringResource(Res.string.legal_pending_line)
    val WITHDRAW: String @Composable get() = stringResource(Res.string.legal_withdraw)
    val WITHDRAW_TITLE: String @Composable get() = stringResource(Res.string.legal_withdraw_title)
    @Composable
    fun withdrawText(name: String) = stringResource(Res.string.legal_withdraw_text, name)
    val CANCEL: String @Composable get() = stringResource(Res.string.legal_cancel)
    @Composable
    fun pendingLink(name: String) = stringResource(Res.string.legal_pending_link, name)

    /** Shown where a feature of a switched-off service would be. */
    @Composable
    fun disabledRow(name: String) = stringResource(Res.string.legal_disabled_row, name)

    // Integrations that are not offered (yet) and service notes
    /** A reserved statement whose feature has not shipped; shown read-only in the legal settings. */
    @Composable
    fun notAvailableLine(name: String) = stringResource(Res.string.legal_not_available_line, name)
    /** The signing screen when no SP account of the mobile citizen certificate is available, even with the statement accepted. */
    val MOICA_SP_NOT_CONFIGURED: String @Composable get() = stringResource(Res.string.legal_moica_sp_not_configured)
    /** The developer setting: what the built-in SP option of the source code is for. */
    val MOICA_SP_FORK_ONLY: String @Composable get() = stringResource(Res.string.legal_moica_sp_fork_only)
    /** The holder picked the test environment of the mobile citizen certificate. */
    val MOICA_SP_ENV_TEST: String @Composable get() = stringResource(Res.string.legal_moica_sp_env_test)
    /** Bonds offline presentation: QR frames and the BLE link carry no session encryption. */
    val BONDS_UNENCRYPTED_WARNING: String @Composable get() = stringResource(Res.string.legal_bonds_unencrypted_warning)
    val BONDS_LINK_TITLE: String @Composable get() = stringResource(Res.string.legal_bonds_link_title)
    val BONDS_LINK_SEND: String @Composable get() = stringResource(Res.string.legal_bonds_link_send)

    /** Before the first request to the TWDIW platform after the statement was accepted. */
    val TWDIW_COMPATIBILITY_TITLE: String @Composable get() = stringResource(Res.string.legal_twdiw_compatibility_title)
    val TWDIW_COMPATIBILITY_WARNING: String @Composable get() = stringResource(Res.string.legal_twdiw_compatibility_warning)
    val TWDIW_COMPATIBILITY_CONTINUE: String @Composable get() = stringResource(Res.string.legal_twdiw_compatibility_continue)
    val READ_STATEMENT: String @Composable get() = stringResource(Res.string.legal_read_statement)

    /** An SP whose holder could not be confirmed. */
    val MOICA_SP_PROVIDER_UNKNOWN: String @Composable get() = stringResource(Res.string.legal_moica_sp_provider_unknown)
}

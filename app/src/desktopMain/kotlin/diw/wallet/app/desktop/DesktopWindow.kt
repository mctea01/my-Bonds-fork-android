package diw.wallet.app.desktop

import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.type
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.WindowPlacement
import androidx.compose.ui.window.WindowPosition
import androidx.compose.ui.window.WindowState
import diw.wallet.app.HomeTab
import diw.wallet.app.Screen
import diw.wallet.app.WalletModel
import java.util.prefs.Preferences

/** The window's size, position and maximised state, kept in the user's Java preferences between runs. */
internal object WindowMemory {
    private val prefs = Preferences.userRoot().node("diw/wallet/app/window")

    /** Smallest window in which every screen stays usable. */
    val minimum = DpSize(360.dp, 560.dp)

    fun restore(): WindowState {
        val width = prefs.getFloat("width", 480f).coerceAtLeast(minimum.width.value)
        val height = prefs.getFloat("height", 860f).coerceAtLeast(minimum.height.value)
        val x = prefs.getFloat("x", Float.NaN)
        val y = prefs.getFloat("y", Float.NaN)
        return WindowState(
            placement = if (prefs.getBoolean("maximized", false)) WindowPlacement.Maximized else WindowPlacement.Floating,
            position = if (x.isNaN() || y.isNaN()) WindowPosition.PlatformDefault else WindowPosition(x.dp, y.dp),
            size = DpSize(width.dp, height.dp),
        )
    }

    fun save(state: WindowState) = runCatching {
        prefs.putBoolean("maximized", state.placement == WindowPlacement.Maximized)
        // A maximised window keeps the size it had before, so restoring it un-maximises to that size.
        if (state.placement == WindowPlacement.Floating) {
            prefs.putFloat("width", state.size.width.value)
            prefs.putFloat("height", state.size.height.value)
            val p = state.position
            if (p.isSpecified) {
                prefs.putFloat("x", p.x.value)
                prefs.putFloat("y", p.y.value)
            }
        }
        prefs.flush()
    }
}

/**
 * Keyboard shortcuts of the main window, handled after the focused element had its turn (a text field keeps its own
 * keys): Esc or Alt+Left goes back as the Android back button does; Ctrl+1 to Ctrl+5 open the five tabs and
 * Ctrl+, opens the settings, both leaving the current screen the way the back button would.
 */
internal object DesktopShortcuts {
    private val tabs = listOf(HomeTab.DOCUMENTS, HomeTab.FILES, HomeTab.USE, HomeTab.VERIFY, HomeTab.HISTORY)

    fun handle(e: KeyEvent, model: WalletModel?): Boolean {
        if (model == null || e.type != KeyEventType.KeyDown) return false
        val command = e.isCtrlPressed || e.isMetaPressed
        return when {
            e.key == Key.Escape && !command && !e.isAltPressed && !e.isShiftPressed -> model.back()
            e.key == Key.DirectionLeft && e.isAltPressed && !command -> model.back()
            command && !e.isAltPressed && e.key == Key.Comma -> {
                home(model)
                if (model.screen.value == Screen.Home) model.screen.value = Screen.Settings
                true
            }
            command && !e.isAltPressed && tabKey(e.key) != null -> {
                home(model)
                if (model.screen.value == Screen.Home) model.tab.value = tabs[tabKey(e.key)!!]
                true
            }
            else -> false
        }
    }

    /** Goes back to the home screen through the same steps as the back button, so every flow is closed properly. */
    fun home(model: WalletModel) {
        repeat(12) {
            if (model.screen.value == Screen.Home) return
            if (!model.back()) return
        }
    }

    private fun tabKey(key: Key): Int? = when (key) {
        Key.One, Key.NumPad1 -> 0
        Key.Two, Key.NumPad2 -> 1
        Key.Three, Key.NumPad3 -> 2
        Key.Four, Key.NumPad4 -> 3
        Key.Five, Key.NumPad5 -> 4
        else -> null
    }
}

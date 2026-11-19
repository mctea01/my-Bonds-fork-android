package diw.wallet.app.ui

import androidx.compose.foundation.HorizontalScrollbar
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
actual fun VerticalScrollIndicator(state: ScrollState, modifier: Modifier) {
    VerticalScrollbar(rememberScrollbarAdapter(state), modifier)
}

@Composable
actual fun HorizontalScrollIndicator(state: ScrollState, modifier: Modifier) {
    HorizontalScrollbar(rememberScrollbarAdapter(state), modifier)
}

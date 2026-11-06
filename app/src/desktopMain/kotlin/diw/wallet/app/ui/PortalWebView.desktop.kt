package diw.wallet.app.ui

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import org.jetbrains.compose.resources.stringResource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import diw.wallet.app.PickedFile

/** The desktop opens source sites in the system browser (embeddedBrowser is false), so this is never shown there. */
@Composable
actual fun PortalWebView(url: String, modifier: Modifier, onFile: (PickedFile) -> Unit, onExternal: (String) -> Unit, onError: (String) -> Unit, autofill: PortalAutofill?) {
    Column(modifier.padding(16.dp)) {
        Text(stringResource(Res.string.portal_desktop_browser, url))
    }
}

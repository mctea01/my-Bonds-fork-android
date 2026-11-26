package diw.wallet.app.ui

import android.webkit.WebView

/**
 * The web view a composable created, kept for back navigation and for destroying it with the composable. The field
 * is read only inside this class, so no other code gets a WebView whose settings it did not set itself.
 */
internal class WebViewSlot {
    private var web: WebView? = null

    fun hold(view: WebView) {
        web = view
    }

    fun goBack() {
        web?.goBack()
    }

    fun destroy() {
        web?.destroy()
        web = null
    }
}

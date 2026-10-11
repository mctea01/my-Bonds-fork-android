package diw.wallet.app.ui

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.addPathNodes
import androidx.compose.ui.unit.dp

/**
 * Icons drawn from path data (24x24 grid, Material Design icon geometry, Apache License 2.0), so the app needs no
 * icon font or image resources on any platform.
 */
object WalletIcons {
    private fun icon(name: String, vararg paths: String): ImageVector =
        ImageVector.Builder(name, 24.dp, 24.dp, 24f, 24f).apply {
            paths.forEach { addPath(pathData = addPathNodes(it), fill = SolidColor(Color.Black)) }
        }.build()

    /** Government building: TWDIW (the government digital wallet). */
    val Government by lazy {
        icon("Government", "M4,10v7h3v-7H4zM10,10v7h3v-7h-3zM2,22h19v-3H2v3zM16,10v7h3v-7h-3zM11.5,1L2,6v2h19V6l-9.5,-5z")
    }

    /** A card: generic credential. */
    val Card by lazy {
        icon("Card", "M20,4H4c-1.11,0 -1.99,0.89 -1.99,2L2,18c0,1.11 0.89,2 2,2h16c1.11,0 2,-0.89 2,-2V6c0,-1.11 -0.89,-2 -2,-2zM20,18H4v-6h16v6zM20,8H4V6h16v2z")
    }

    /** Shield with a check mark: trust list, verified party. */
    val Shield by lazy {
        icon("Shield", "M12,1L3,5v6c0,5.55 3.84,10.74 9,12 5.16,-1.26 9,-6.45 9,-12V5l-9,-4zM10,17l-4,-4 1.41,-1.41L10,14.17l6.59,-6.59L18,9l-8,8z")
    }

    /** Store front: counter pickup. */
    val Store by lazy {
        icon("Store", "M20,4H4v2h16V4zM21,14v-2l-1,-5H4l-1,5v2h1v6h10v-6h4v6h2v-6h1zM12,18H6v-4h6v4z")
    }

    /** Phone: telecom phone number cards. */
    val Phone by lazy {
        icon("Phone", "M17,1.01L7,1c-1.1,0 -1.99,0.9 -1.99,2v18c0,1.1 0.89,2 1.99,2h10c1.1,0 2,-0.9 2,-2V3c0,-1.1 -0.9,-1.99 -2,-1.99zM17,19H7V5h10v14z")
    }

    /** QR code: show a code. */
    val Qr by lazy {
        icon(
            "Qr",
            "M3,11h8V3H3V11zM5,5h4v4H5V5z",
            "M3,21h8v-8H3V21zM5,15h4v4H5V15z",
            "M13,3v8h8V3H13zM19,9h-4V5h4V9z",
            "M19,19h2v2h-2z", "M13,13h2v2h-2z", "M15,15h2v2h-2z", "M13,17h2v2h-2z",
            "M15,19h2v2h-2z", "M17,17h2v2h-2z", "M17,13h2v2h-2z", "M19,15h2v2h-2z",
        )
    }

    /** Scanner frame: scan a code. */
    val Scan by lazy {
        icon(
            "Scan",
            "M22,7h-2V4h-3V2h5V7z", "M22,22v-5h-2v3h-3v2H22z", "M2,22h5v-2H4v-3H2V22z", "M2,2v5h2V4h3V2H2z",
            "M6,11h12v2H6z",
        )
    }

    /** Bluetooth: BLE link. */
    val Bluetooth by lazy {
        icon("Bluetooth", "M17.71,7.71L12,2h-1v7.59L6.41,5 5,6.41 10.59,12 5,17.59 6.41,19 11,14.41V22h1l5.71,-5.71 -4.3,-4.29 4.3,-4.29zM13,5.83l1.88,1.88L13,9.59V5.83zM14.88,16.29L13,18.17v-3.76l1.88,1.88z")
    }

    /** Document: signed documents (Bonds documents arrive in P5). */
    val Document by lazy {
        icon("Document", "M14,2H6c-1.1,0 -1.99,0.9 -1.99,2L4,20c0,1.1 0.89,2 1.99,2H18c1.1,0 2,-0.9 2,-2V8l-6,-6zM16,18H8v-2h8v2zM16,14H8v-2h8v2zM13,9V3.5L18.5,9H13z")
    }

    /** Office building: organisations (Microsoft Entra Verified ID). */
    val Organization by lazy {
        icon("Organization", "M12,7V3H2v18h20V7H12zM6,19H4v-2h2v2zM6,15H4v-2h2v2zM6,11H4V9h2v2zM6,7H4V5h2v2zM10,19H8v-2h2v2zM10,15H8v-2h2v2zM10,11H8V9h2v2zM10,7H8V5h2v2zM20,19h-8v-2h2v-2h-2v-2h2v-2h-2V9h8v10zM18,11h-2v2h2v-2zM18,15h-2v2h2v-2z")
    }

    /** Person badge: identity documents (PID, mDL). */
    val Person by lazy {
        icon("Person", "M12,12c2.21,0 4,-1.79 4,-4s-1.79,-4 -4,-4 -4,1.79 -4,4 1.79,4 4,4zM12,14c-2.67,0 -8,1.34 -8,4v2h16v-2c0,-2.66 -5.33,-4 -8,-4z")
    }

    /** Stacked links: Bonds (bonds.tw) offline presentation. */
    val Link by lazy {
        icon("Link", "M3.9,12c0,-1.71 1.39,-3.1 3.1,-3.1h4V7H7c-2.76,0 -5,2.24 -5,5s2.24,5 5,5h4v-1.9H7c-1.71,0 -3.1,-1.39 -3.1,-3.1zM8,13h8v-2H8v2zM17,7h-4v1.9h4c1.71,0 3.1,1.39 3.1,3.1s-1.39,3.1 -3.1,3.1h-4V17h4c2.76,0 5,-2.24 5,-5s-2.24,-5 -5,-5z")
    }

    val all: List<ImageVector> get() = listOf(Government, Card, Shield, Store, Phone, Qr, Scan, Bluetooth, Document, Organization, Person, Link)
}

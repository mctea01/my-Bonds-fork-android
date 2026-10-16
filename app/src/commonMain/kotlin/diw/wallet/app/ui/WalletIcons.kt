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

    /** Wallet: the documents tab. */
    val Wallet by lazy {
        icon("Wallet", "M21,18v1c0,1.1 -0.9,2 -2,2H5c-1.11,0 -2,-0.9 -2,-2V5c0,-1.1 0.89,-2 2,-2h14c1.1,0 2,0.9 2,2v1h-9c-1.11,0 -2,0.9 -2,2v8c0,1.1 0.89,2 2,2h9zM12,16h10V8H12v8zM16,13.5c-0.83,0 -1.5,-0.67 -1.5,-1.5s0.67,-1.5 1.5,-1.5 1.5,0.67 1.5,1.5 -0.67,1.5 -1.5,1.5z")
    }

    /** Clock with a back arrow: the history tab. */
    val History by lazy {
        icon("History", "M13,3c-4.97,0 -9,4.03 -9,9H1l3.89,3.89 0.07,0.14L9,12H6c0,-3.87 3.13,-7 7,-7s7,3.13 7,7 -3.13,7 -7,7c-1.93,0 -3.68,-0.79 -4.94,-2.06l-1.42,1.42C8.27,19.99 10.51,21 13,21c4.97,0 9,-4.03 9,-9s-4.03,-9 -9,-9zM12,8v5l4.28,2.54 0.72,-1.21 -3.5,-2.08V8H12z")
    }

    /** Gear: settings. */
    val Settings by lazy {
        icon("Settings", "M19.14,12.94c0.04,-0.3 0.06,-0.61 0.06,-0.94c0,-0.32 -0.02,-0.64 -0.07,-0.94l2.03,-1.58c0.18,-0.14 0.23,-0.41 0.12,-0.61l-1.92,-3.32c-0.12,-0.22 -0.37,-0.29 -0.59,-0.22l-2.39,0.96c-0.5,-0.38 -1.03,-0.7 -1.62,-0.94L14.4,2.81c-0.04,-0.24 -0.24,-0.41 -0.48,-0.41h-3.84c-0.24,0 -0.43,0.17 -0.47,0.41L9.25,5.35C8.66,5.59 8.12,5.92 7.63,6.29L5.24,5.33c-0.22,-0.08 -0.47,0 -0.59,0.22L2.74,8.87C2.62,9.08 2.66,9.34 2.86,9.48l2.03,1.58C4.84,11.36 4.8,11.69 4.8,12s0.02,0.64 0.07,0.94l-2.03,1.58c-0.18,0.14 -0.23,0.41 -0.12,0.61l1.92,3.32c0.12,0.22 0.37,0.29 0.59,0.22l2.39,-0.96c0.5,0.38 1.03,0.7 1.62,0.94l0.36,2.54c0.05,0.24 0.24,0.41 0.48,0.41h3.84c0.24,0 0.44,-0.17 0.47,-0.41l0.36,-2.54c0.59,-0.24 1.13,-0.56 1.62,-0.94l2.39,0.96c0.22,0.08 0.47,0 0.59,-0.22l1.92,-3.32c0.12,-0.22 0.07,-0.47 -0.12,-0.61L19.14,12.94zM12,15.6c-1.98,0 -3.6,-1.62 -3.6,-3.6s1.62,-3.6 3.6,-3.6s3.6,1.62 3.6,3.6S13.98,15.6 12,15.6z")
    }

    /** Plus: add a document. */
    val Add by lazy { icon("Add", "M19,13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z") }

    /** Arrow pointing left: back. */
    val Back by lazy { icon("Back", "M20,11H7.83l5.59,-5.59L12,4l-8,8 8,8 1.41,-1.41L7.83,13H20v-2z") }

    /** Chevron: a row that opens another screen. */
    val Chevron by lazy { icon("Chevron", "M10,6L8.59,7.41 13.17,12l-4.58,4.59L10,18l6,-6z") }

    /** Magnifier: search. */
    val Search by lazy {
        icon("Search", "M15.5,14h-0.79l-0.28,-0.27C15.41,12.59 16,11.11 16,9.5 16,5.91 13.09,3 9.5,3S3,5.91 3,9.5 5.91,16 9.5,16c1.61,0 3.09,-0.59 4.23,-1.57l0.27,0.28v0.79l5,4.99L20.49,19l-4.99,-5zM9.5,14C7.01,14 5,11.99 5,9.5S7.01,5 9.5,5 14,7.01 14,9.5 11.99,14 9.5,14z")
    }

    /** Paper plane: a presentation that was sent. */
    val Send by lazy { icon("Send", "M2.01,21L23,12 2.01,3 2,10l15,2 -15,2z") }

    /** Tray with a down arrow: a document that was received. */
    val Receive by lazy { icon("Receive", "M19,9h-4V3H9v6H5l7,7 7,-7zM5,18v2h14v-2H5z") }

    /** Filled circle with a check mark: verdict pass. */
    val Pass by lazy {
        icon("Pass", "M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10 10,-4.48 10,-10S17.52,2 12,2zM10,17l-5,-5 1.41,-1.41L10,14.17l7.59,-7.59L19,8l-9,9z")
    }

    /** Triangle with an exclamation mark: verdict caution. */
    val Info by lazy { icon("Info", "M12,2C6.48,2 2,6.48 2,12s4.48,10 10,10 10,-4.48 10,-10S17.52,2 12,2zM13,17h-2v-6h2v6zM13,9h-2V7h2v2z") }

    val Caution by lazy { icon("Caution", "M1,21h22L12,2 1,21zM13,18h-2v-2h2v2zM13,14h-2v-4h2v4z") }

    /** Filled circle with a cross: verdict fail, declined. */
    val Fail by lazy {
        icon("Fail", "M12,2C6.47,2 2,6.47 2,12s4.47,10 10,10 10,-4.47 10,-10S17.53,2 12,2zM17,15.59L15.59,17 12,13.41 8.41,17 7,15.59 10.59,12 7,8.41 8.41,7 12,10.59 15.59,7 17,8.41 13.41,12 17,15.59z")
    }

    /** Waste bin: delete. */
    val Delete by lazy { icon("Delete", "M6,19c0,1.1 0.9,2 2,2h8c1.1,0 2,-0.9 2,-2V7H6v12zM19,4h-3.5l-1,-1h-5l-1,1H5v2h14V4z") }

    /** NFC mark: contactless reading (later versions). */
    val Nfc by lazy {
        icon("Nfc", "M20,2L4,2c-1.1,0 -2,0.9 -2,2v16c0,1.1 0.9,2 2,2h16c1.1,0 2,-0.9 2,-2L22,4c0,-1.1 -0.9,-2 -2,-2zM20,20L4,20L4,4h16v16zM18,6h-5c-1.1,0 -2,0.9 -2,2v2.28c-0.6,0.35 -1,0.98 -1,1.72 0,1.1 0.9,2 2,2s2,-0.9 2,-2c0,-0.74 -0.4,-1.38 -1,-1.72L13,8h3v8L8,16L8,8h2L10,6L6,6v12h12L18,6z")
    }

    val all: List<ImageVector>
        get() = listOf(
            Government, Card, Shield, Store, Phone, Qr, Scan, Bluetooth, Document, Organization, Person, Link,
            Wallet, History, Settings, Add, Back, Chevron, Search, Send, Receive, Pass, Caution, Fail, Delete, Nfc,
        )
}

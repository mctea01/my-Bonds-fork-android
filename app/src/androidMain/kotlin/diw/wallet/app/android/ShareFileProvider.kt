package diw.wallet.app.android

import androidx.core.content.FileProvider

/** The share sheet's provider; its own class so it does not merge with the FileProvider Multipaz declares. */
class ShareFileProvider : FileProvider()

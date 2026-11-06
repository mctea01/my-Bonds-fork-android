package diw.wallet.app.android

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.tr
import android.app.Activity
import android.content.Context
import android.security.KeyChain
import android.security.KeyChainException
import diw.wallet.app.ExternalKeys
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.JcaDocumentSigner
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume

/**
 * Android KeyChain: certificates the user installed in system settings (or a work profile pushed), picked in the
 * system's own dialog; the wallet only gets the alias the user grants. Android has no PKCS#11, so hardware tokens
 * go through the citizen certificate card path (NFC or a USB reader) instead.
 */
class AndroidKeys(private val context: Context, private val activity: () -> Activity?) : ExternalKeys {
    override val systemUnavailableReason: String? = null
    override val tokenUnavailableReason = tr(Res.string.ak_no_pkcs11)
    override val systemPicker = true

    override suspend fun systemSigner(id: String?): DocumentSigner {
        val alias = id ?: choose() ?: throw SigningException(tr(Res.string.ak_no_key_chosen))
        return withContext(Dispatchers.IO) {
            try {
                val key = KeyChain.getPrivateKey(context, alias) ?: throw SigningException(tr(Res.string.ak_no_access))
                val chain = KeyChain.getCertificateChain(context, alias)?.toList().orEmpty()
                if (chain.isEmpty()) throw SigningException(tr(Res.string.key_no_certificate))
                JcaDocumentSigner(key, chain, SignerSource.SYSTEM_KEYSTORE)
            } catch (e: KeyChainException) {
                throw SigningException(tr(Res.string.key_refused) + (e.message ?: "KeyChain"), e)
            }
        }
    }

    /** The system dialog listing installed certificates; null when the user cancels. */
    private suspend fun choose(): String? {
        val a = activity() ?: throw SigningException(tr(Res.string.ak_choose_while_open))
        return suspendCancellableCoroutine { cont ->
            a.runOnUiThread {
                KeyChain.choosePrivateKeyAlias(a, { alias -> if (cont.isActive) cont.resume(alias) }, arrayOf("RSA", "EC"), null, null, null)
            }
        }
    }

    override suspend fun tokenSigner(library: String, pin: String, id: String): DocumentSigner = throw SigningException(tokenUnavailableReason)
}

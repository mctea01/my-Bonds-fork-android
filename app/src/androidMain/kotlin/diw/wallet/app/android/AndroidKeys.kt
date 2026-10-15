package diw.wallet.app.android

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
    override val tokenUnavailableReason = "Android 不提供 PKCS#11；自然人憑證請用「自然人憑證卡」（NFC 或 USB 讀卡機），其他憑證可先安裝到系統再用「系統金鑰」"
    override val systemPicker = true

    override suspend fun systemSigner(id: String?): DocumentSigner {
        val alias = id ?: choose() ?: throw SigningException("沒有選擇金鑰；可在系統設定的「加密與憑證」安裝憑證後再試")
        return withContext(Dispatchers.IO) {
            try {
                val key = KeyChain.getPrivateKey(context, alias) ?: throw SigningException("系統沒有提供這把金鑰的使用權")
                val chain = KeyChain.getCertificateChain(context, alias)?.toList().orEmpty()
                if (chain.isEmpty()) throw SigningException("這把金鑰沒有憑證")
                JcaDocumentSigner(key, chain, SignerSource.SYSTEM_KEYSTORE)
            } catch (e: KeyChainException) {
                throw SigningException("系統拒絕使用這把金鑰：" + (e.message ?: "KeyChain"), e)
            }
        }
    }

    /** The system dialog listing installed certificates; null when the user cancels. */
    private suspend fun choose(): String? {
        val a = activity() ?: throw SigningException("請在 App 開著時選擇金鑰")
        return suspendCancellableCoroutine { cont ->
            a.runOnUiThread {
                KeyChain.choosePrivateKeyAlias(a, { alias -> if (cont.isActive) cont.resume(alias) }, arrayOf("RSA", "EC"), null, null, null)
            }
        }
    }

    override suspend fun tokenSigner(library: String, pin: String, id: String): DocumentSigner = throw SigningException(tokenUnavailableReason)
}

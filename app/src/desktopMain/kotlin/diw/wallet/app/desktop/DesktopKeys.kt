package diw.wallet.app.desktop

import diw.wallet.app.ExternalKeyOption
import diw.wallet.app.ExternalKeys
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.JcaDocumentSigner
import diw.wallet.core.document.sign.SignerSource
import diw.wallet.core.document.sign.SigningException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Provider
import java.security.Security
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import javax.security.auth.x500.X500Principal

/**
 * Desktop signing keys: the Windows certificate store (SunMSCAPI, which also lists cards whose middleware registers
 * with Windows, such as HiCOS for the citizen certificate), the macOS keychain, and PKCS#11 modules through
 * SunPKCS11. Providers are used as instances and never registered globally.
 */
object DesktopKeys : ExternalKeys {
    private val os = System.getProperty("os.name").orEmpty()
    private val windows = os.startsWith("Windows")
    private val mac = os.startsWith("Mac")

    /** One SunPKCS11 provider per module path; a module cannot be loaded twice in one process. */
    private val tokens = mutableMapOf<String, Provider>()

    override val systemUnavailableReason: String? = when {
        windows || mac -> null
        else -> "Linux 沒有統一的系統金鑰庫，請改用硬體憑證（PKCS#11）或憑證檔"
    }

    override val tokenUnavailableReason: String?
        get() = if (Security.getProvider("SunPKCS11") == null) "這個 Java 執行環境沒有 SunPKCS11 模組" else null

    override fun tokenLibraries(): List<String> = CANDIDATES.filter { File(it).isFile }

    private fun systemStore(): KeyStore = when {
        windows -> KeyStore.getInstance("Windows-MY").apply { load(null, null) }
        mac -> KeyStore.getInstance("KeychainStore").apply { load(null, null) }
        else -> throw SigningException(systemUnavailableReason ?: "沒有系統金鑰庫")
    }

    override suspend fun systemKeys(): List<ExternalKeyOption> = withContext(Dispatchers.IO) {
        val ks = try { systemStore() } catch (e: SigningException) { throw e } catch (e: Exception) {
            throw SigningException("無法開啟系統金鑰庫：" + (e.message ?: e::class.simpleName), e)
        }
        options(ks)
    }

    override suspend fun systemSigner(id: String?): DocumentSigner = withContext(Dispatchers.IO) {
        val alias = id ?: throw SigningException("請先選擇金鑰")
        val ks = systemStore()
        // The keychain exports the key under a passphrase of our choosing; the Windows store ignores it.
        val key = runCatching { ks.getKey(alias, KEYCHAIN_PASSPHRASE) as? PrivateKey }.getOrElse {
            throw SigningException("系統拒絕使用這把金鑰：" + (it.message ?: it::class.simpleName), it)
        } ?: throw SigningException("這個項目沒有私密金鑰")
        JcaDocumentSigner(key, chainOf(ks, alias), SignerSource.SYSTEM_KEYSTORE)
    }

    private fun token(library: String): Provider = synchronized(tokens) {
        tokens.getOrPut(library) {
            if (!File(library).isFile) throw SigningException("找不到 PKCS#11 模組：$library")
            val base = Security.getProvider("SunPKCS11") ?: throw SigningException(tokenUnavailableReason ?: "沒有 SunPKCS11")
            val name = "diw" + tokens.size
            val config = "--name=$name\nlibrary=${library.replace("\\", "/")}\n"
            try {
                base.configure(config)
            } catch (e: Exception) {
                throw SigningException("無法載入 PKCS#11 模組（讀卡機或卡片未就緒，或模組不相容）：" + (e.message ?: e::class.simpleName), e)
            }
        }
    }

    private fun tokenStore(library: String, pin: String): Pair<KeyStore, Provider> {
        val provider = token(library)
        val ks = try {
            KeyStore.getInstance("PKCS11", provider).apply { load(null, pin.toCharArray()) }
        } catch (e: Exception) {
            val text = generateSequence(e as Throwable) { it.cause }.mapNotNull { it.message }.joinToString(" ")
            throw SigningException(
                if ("CKR_PIN_INCORRECT" in text) "PIN 碼錯誤" else if ("CKR_PIN_LOCKED" in text) "PIN 碼已鎖定" else "無法開啟硬體憑證：$text",
                e,
            )
        }
        return ks to provider
    }

    override suspend fun tokenKeys(library: String, pin: String): List<ExternalKeyOption> = withContext(Dispatchers.IO) {
        options(tokenStore(library, pin).first)
    }

    override suspend fun tokenSigner(library: String, pin: String, id: String): DocumentSigner = withContext(Dispatchers.IO) {
        val (ks, provider) = tokenStore(library, pin)
        val key = ks.getKey(id, pin.toCharArray()) as? PrivateKey ?: throw SigningException("這個項目沒有私密金鑰")
        JcaDocumentSigner(key, chainOf(ks, id), SignerSource.PKCS11, provider)
    }

    private fun chainOf(ks: KeyStore, alias: String): List<X509Certificate> =
        ks.getCertificateChain(alias)?.filterIsInstance<X509Certificate>()?.takeIf { it.isNotEmpty() }
            ?: (ks.getCertificate(alias) as? X509Certificate)?.let { listOf(it) }
            ?: throw SigningException("這把金鑰沒有憑證")

    /** Key entries with a certificate that can sign, newest expiry first. */
    private fun options(ks: KeyStore): List<ExternalKeyOption> {
        val day = SimpleDateFormat("yyyy-MM-dd")
        return ks.aliases().toList().mapNotNull { alias ->
            if (!runCatching { ks.isKeyEntry(alias) }.getOrDefault(false)) return@mapNotNull null
            val cert = runCatching { ks.getCertificate(alias) as? X509Certificate }.getOrNull() ?: return@mapNotNull null
            // keyUsage bit 0 (digitalSignature) or 1 (nonRepudiation); absent means unrestricted.
            val usage = cert.keyUsage
            if (usage != null && !(usage.getOrNull(0) == true || usage.getOrNull(1) == true)) return@mapNotNull null
            cert to ExternalKeyOption(
                alias,
                cn(cert.subjectX500Principal) ?: alias,
                "發行者：" + (cn(cert.issuerX500Principal) ?: cert.issuerX500Principal.name) + "，有效至 " + day.format(cert.notAfter),
            )
        }.sortedByDescending { it.first.notAfter }.map { it.second }
    }

    private fun cn(p: X500Principal): String? =
        p.getName(X500Principal.RFC2253).split(Regex("(?<!\\\\),")).firstOrNull { it.trim().startsWith("CN=") }?.substringAfter("CN=")

    private val KEYCHAIN_PASSPHRASE = "diw-wallet".toCharArray()

    /** PKCS#11 modules of common drivers: HiCOS (citizen certificate), OpenSC, SafeNet, and macOS. */
    private val CANDIDATES = listOf(
        "C:\\Windows\\System32\\HiCOSPKCS11.dll",
        "C:\\Windows\\System32\\opensc-pkcs11.dll",
        "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
        "C:\\Windows\\System32\\eTPKCS11.dll",
        "/usr/local/lib/libHiCOSPKCS11.dylib",
        "/Library/OpenSC/lib/opensc-pkcs11.so",
        "/usr/local/lib/opensc-pkcs11.so",
        "/usr/lib/libHiCOSPKCS11.so",
        "/usr/local/lib/libHiCOSPKCS11.so",
        "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
        "/usr/lib64/opensc-pkcs11.so",
        "/usr/lib/opensc-pkcs11.so",
        "/usr/lib/libeTPkcs11.so",
    )
}

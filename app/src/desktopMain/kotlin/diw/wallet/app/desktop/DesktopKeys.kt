package diw.wallet.app.desktop

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.app.tr
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
        else -> tr(Res.string.dk_linux_no_store)
    }

    override val tokenUnavailableReason: String?
        get() = if (Security.getProvider("SunPKCS11") == null) tr(Res.string.dk_no_sunpkcs11_module) else null

    override fun tokenLibraries(): List<String> = CANDIDATES.filter { File(it).isFile }

    private fun systemStore(): KeyStore = when {
        windows -> KeyStore.getInstance("Windows-MY").apply { load(null, null) }
        mac -> KeyStore.getInstance("KeychainStore").apply { load(null, null) }
        else -> throw SigningException(systemUnavailableReason ?: tr(Res.string.dk_no_store))
    }

    override suspend fun systemKeys(): List<ExternalKeyOption> = withContext(Dispatchers.IO) {
        val ks = try { systemStore() } catch (e: SigningException) { throw e } catch (e: Exception) {
            throw SigningException(tr(Res.string.dk_store_failed) + (e.message ?: e::class.simpleName), e)
        }
        options(ks)
    }

    override suspend fun systemSigner(id: String?): DocumentSigner = withContext(Dispatchers.IO) {
        val alias = id ?: throw SigningException(tr(Res.string.dk_choose_key))
        val ks = systemStore()
        // The keychain exports the key under a passphrase of our choosing; the Windows store ignores it.
        val key = runCatching { ks.getKey(alias, KEYCHAIN_PASSPHRASE) as? PrivateKey }.getOrElse {
            throw SigningException(tr(Res.string.key_refused) + (it.message ?: it::class.simpleName), it)
        } ?: throw SigningException(tr(Res.string.dk_no_private_key))
        JcaDocumentSigner(key, chainOf(ks, alias), SignerSource.SYSTEM_KEYSTORE)
    }

    private fun token(library: String): Provider = synchronized(tokens) {
        tokens.getOrPut(library) {
            if (!File(library).isFile) throw SigningException(tr(Res.string.dk_module_missing, library))
            val base = Security.getProvider("SunPKCS11") ?: throw SigningException(tokenUnavailableReason ?: tr(Res.string.dk_no_sunpkcs11))
            val name = "diw" + tokens.size
            val config = "--name=$name\nlibrary=${library.replace("\\", "/")}\n"
            try {
                base.configure(config)
            } catch (e: Exception) {
                throw SigningException(tr(Res.string.dk_module_load_failed) + (e.message ?: e::class.simpleName), e)
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
                if ("CKR_PIN_INCORRECT" in text) tr(Res.string.dk_pin_wrong) else if ("CKR_PIN_LOCKED" in text) tr(Res.string.dk_pin_locked) else tr(Res.string.dk_token_failed, text),
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
        val key = ks.getKey(id, pin.toCharArray()) as? PrivateKey ?: throw SigningException(tr(Res.string.dk_no_private_key))
        JcaDocumentSigner(key, chainOf(ks, id), SignerSource.PKCS11, provider)
    }

    private fun chainOf(ks: KeyStore, alias: String): List<X509Certificate> =
        ks.getCertificateChain(alias)?.filterIsInstance<X509Certificate>()?.takeIf { it.isNotEmpty() }
            ?: (ks.getCertificate(alias) as? X509Certificate)?.let { listOf(it) }
            ?: throw SigningException(tr(Res.string.key_no_certificate))

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
                tr(Res.string.dk_issuer) + (cn(cert.issuerX500Principal) ?: cert.issuerX500Principal.name) + tr(Res.string.dk_valid_until) + day.format(cert.notAfter),
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

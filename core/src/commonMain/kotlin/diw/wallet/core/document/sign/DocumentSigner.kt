package diw.wallet.core.document.sign

import diw.wallet.core.i18n.ct

/** Key type of a [DocumentSigner]; the signature algorithm is always with SHA-256. */
enum class SignerKeyType { RSA, EC_P256 }

/** Where a signing key lives, shown on the signing screen and recorded with the signed file. */
enum class SignerSource(private val titleKey: String) {
    /** Citizen digital certificate (MOICA) or another GPKI card read over NFC, USB or PC/SC. */
    SMART_CARD("core_src_smart_card"),
    /** A PKCS#12 file the user imported (software certificate). */
    PKCS12("core_src_pkcs12"),
    /** The wallet's own document key with a self-issued certificate. */
    WALLET("core_src_wallet"),
    /** A key the operating system keeps (Android KeyChain, Windows certificate store, macOS keychain). */
    SYSTEM_KEYSTORE("core_src_system"),
    /** A hardware token reached through PKCS#11 (USB token, card reader with the vendor's module). */
    PKCS11("core_src_pkcs11"),
    /** The mobile citizen certificate through the TW FidO SP API. */
    MOBILE_MOICA("core_src_mobile_moica"),
    /** A remote signing service through the Cloud Signature Consortium API. */
    CSC("core_src_csc"),
    /** A PIV card (NIST SP 800-73-4): YubiKey, PIVKey, US PIV/CAC and the like, read over NFC, USB or PC/SC. */
    PIV("core_src_piv"),
    /** An OpenPGP card (YubiKey, Nitrokey, Gnuk and the like) read over NFC, USB or PC/SC. */
    OPENPGP("core_src_openpgp");

    val title: String get() = if (titleKey.startsWith("core_")) ct(titleKey) else titleKey
}

/**
 * A signing key with its certificate: a smart card, an imported PKCS#12 key, a system or PKCS#11 key, the mobile
 * citizen certificate, or the wallet's own key. Every document format (PAdES, CAdES, ASiC-E, XAdES, the self-made
 * certificate) signs through this interface.
 */
interface DocumentSigner {
    /** Signer certificate first, then any intermediate certificates (DER). */
    val certificateChain: List<ByteArray>
    val keyType: SignerKeyType
    val source: SignerSource

    /**
     * Signs [data]: RSASSA-PKCS1-v1_5 with SHA-256 for RSA keys, ECDSA P-256 with SHA-256 (DER encoded) for EC
     * keys. A smart card may ask for the PIN here; failures surface as exceptions with a user-facing message.
     */
    suspend fun sign(data: ByteArray): ByteArray
}

/** A failure the user can act on (wrong PIN, card removed, key not usable); [message] is shown as is. */
class SigningException(message: String, cause: Throwable? = null) : Exception(message, cause)

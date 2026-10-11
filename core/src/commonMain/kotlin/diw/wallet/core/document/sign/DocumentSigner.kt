package diw.wallet.core.document.sign

/** Key type of a [DocumentSigner]; the signature algorithm is always with SHA-256. */
enum class SignerKeyType { RSA, EC_P256 }

/** Where a signing key lives, shown on the signing screen and recorded with the signed file. */
enum class SignerSource(val title: String) {
    /** Citizen digital certificate (MOICA) or another GPKI card read over NFC, USB or PC/SC. */
    SMART_CARD("自然人憑證卡"),
    /** A PKCS#12 file the user imported (software certificate). */
    PKCS12("憑證檔（PKCS#12）"),
    /** The wallet's own document key with a self-issued certificate. */
    WALLET("錢包自有金鑰"),
}

/**
 * A signing key with its certificate: a smart card, an imported PKCS#12 key, or the wallet's own key. Every
 * document format (PAdES, CAdES, ASiC-E, XAdES, the self-made certificate) signs through this interface.
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

package diw.wallet.core.document.mrtd

/**
 * Key agreement on one domain, an elliptic curve or a Diffie-Hellman group, as PACE and Chip Authentication use it.
 * Public keys are encoded as the protocols send them: an uncompressed point (04 || X || Y) or the unsigned
 * big-endian group element.
 */
interface AgreementDomain {
    val elliptic: Boolean

    /** Bytes of the field (EC) or modulus (DH): the length of a shared secret. */
    val size: Int

    fun generate(): AgreementKeyPair

    /** The shared secret: the x-coordinate of priv * peer (EC), or peer ^ priv mod p (DH), as [size] bytes. */
    fun agree(own: AgreementKeyPair, peerPublic: ByteArray): ByteArray

    /**
     * Generic mapping (ICAO 9303 part 11, 4.4.3.3.1): the domain with the new generator s * G + H (EC) or g ^ s * h
     * (DH), where H (h) is the agreement of [own] with [peerPublic] as a group element.
     */
    fun mapGeneric(nonce: ByteArray, own: AgreementKeyPair, peerPublic: ByteArray): AgreementDomain

    /** [publicKey] is a valid element of the group: on the curve and not the identity, or in 2..p-2. */
    fun validPublic(publicKey: ByteArray): Boolean
}

/** An ephemeral key pair on an [AgreementDomain]; [handle] holds the private key for the platform code only. */
class AgreementKeyPair(val publicKey: ByteArray, val handle: Any)

/** The public key algorithms of the chip, as stated in DG14 and DG15. */
expect object MrtdCrypto {
    /** PACE standardized domain parameters (BSI TR-03110 part 3, A.2.1.1): 0 to 2 DH, 8 to 18 EC; null otherwise. */
    fun standardDomain(id: Int): AgreementDomain?

    /** The domain and public key of a SubjectPublicKeyInfo: EC (named or explicit parameters) or DH; null otherwise. */
    fun publicKeyDomain(spki: ByteArray): Pair<AgreementDomain, ByteArray>?

    /**
     * Active Authentication (ICAO 9303 part 11, 6.1): [response] to INTERNAL AUTHENTICATE over [challenge], with the
     * DG15 key [spki]. RSA uses ISO/IEC 9796-2 scheme 1 with the hash named by the trailer; ECDSA uses plain r || s
     * with the hash of [signatureOid] (from DG14), or each common hash when DG14 names none. Returns the hash used,
     * or null when the response does not verify.
     */
    fun verifyActiveAuthentication(spki: ByteArray, challenge: ByteArray, response: ByteArray, signatureOid: String?): String?

    /** "RSA 2048", "EC brainpoolP256r1" and the like, for display. */
    fun describeKey(spki: ByteArray): String?
}

package diw.wallet.core.document.mrtd

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.card.CardChannel

/** The password of PACE: the MRZ access key, or the card access number printed on the document. */
sealed class AccessSecret {
    data class MrzSecret(val key: MrzKey) : AccessSecret()
    data class Can(val number: String) : AccessSecret() {
        init { require(number.isNotEmpty() && number.all { it.isDigit() }) { "CAN" } }
    }

    /** f(pi) of ICAO 9303 part 11, 9.7.3: SHA-1 of the MRZ information, or the CAN itself. */
    val seed: ByteArray get() = when (this) {
        is MrzSecret -> DocCrypto.digest("SHA-1", key.information.encodeToByteArray())
        is Can -> number.encodeToByteArray()
    }

    /** The password reference of MSE:Set AT (1 MRZ, 2 CAN). */
    val reference: Int get() = if (this is MrzSecret) 1 else 2
}

/**
 * The access control and chip protocols of ICAO 9303 part 11: Basic Access Control, PACE with generic mapping, Chip
 * Authentication and Active Authentication. Each takes the plain channel to the chip (or the current secure
 * channel) and returns the secure channel to continue with.
 */
object MrtdAccess {
    private fun ok(sw: Int) = sw == 0x9000

    /** BAC (ICAO 9303 part 11, 4.3): 3DES session keys from the MRZ key and the two exchanged key halves. */
    suspend fun bac(channel: CardChannel, key: MrzKey): SecureChannel {
        val seed = DocCrypto.digest("SHA-1", key.information.encodeToByteArray()).copyOf(16)
        val kEnc = MrtdCrypt.kdf(SmCipher.DES3, seed, MrtdCrypt.KDF_ENC)
        val kMac = MrtdCrypt.kdf(SmCipher.DES3, seed, MrtdCrypt.KDF_MAC)
        val challenge = channel.transmit(0x00, 0x84, 0x00, 0x00, ByteArray(0), 8)
        if (!ok(challenge.sw) || challenge.data.size != 8) throw MrtdException("bac_challenge", challenge.sw)
        val rndIcc = challenge.data
        val rndIfd = DocCrypto.randomBytes(8)
        val kIfd = DocCrypto.randomBytes(16)
        val eIfd = DocCrypto.desEdeCbc(true, kEnc, ByteArray(8), rndIfd + rndIcc + kIfd)
        val mIfd = MrtdCrypt.retailMac(kMac, MrtdCrypt.pad(eIfd, 8))
        val r = channel.transmit(0x00, 0x82, 0x00, 0x00, eIfd + mIfd, 40)
        // 6300 or 6982: the chip refused the cryptogram, which means the typed document data are wrong.
        if (r.sw == 0x6300 || r.sw == 0x6982) throw MrtdException("access_denied", r.sw)
        if (!ok(r.sw) || r.data.size != 40) throw MrtdException("bac_failed", r.sw)
        val eIcc = r.data.copyOf(32)
        if (!MrtdCrypt.retailMac(kMac, MrtdCrypt.pad(eIcc, 8)).contentEquals(r.data.copyOfRange(32, 40))) throw MrtdException("bac_mac")
        val plain = DocCrypto.desEdeCbc(false, kEnc, ByteArray(8), eIcc)
        if (!plain.copyOfRange(0, 8).contentEquals(rndIcc) || !plain.copyOfRange(8, 16).contentEquals(rndIfd)) throw MrtdException("bac_mismatch")
        val kIcc = plain.copyOfRange(16, 32)
        val sessionSeed = ByteArray(16) { (kIfd[it].toInt() xor kIcc[it].toInt()).toByte() }
        val ssc = rndIcc.copyOfRange(4, 8) + rndIfd.copyOfRange(4, 8)
        return SecureChannel(channel, SmCipher.DES3,
            MrtdCrypt.kdf(SmCipher.DES3, sessionSeed, MrtdCrypt.KDF_ENC), MrtdCrypt.kdf(SmCipher.DES3, sessionSeed, MrtdCrypt.KDF_MAC), ssc)
    }

    /** The public key data object of PACE authentication tokens: 7F49 with the protocol OID and the key. */
    fun publicKeyObject(oid: String, publicKey: ByteArray, elliptic: Boolean): ByteArray =
        BerTlv.encode(0x7F49, BerTlv.encode(0x06, BerTlv.oidValue(oid)) + BerTlv.encode(if (elliptic) 0x86 else 0x84, publicKey))

    /** PACE authentication token: retail MAC (3DES, padded) or CMAC (AES) of the public key data object, 8 bytes. */
    fun token(cipher: SmCipher, kMac: ByteArray, oid: String, publicKey: ByteArray, elliptic: Boolean): ByteArray {
        val obj = publicKeyObject(oid, publicKey, elliptic)
        return if (cipher.aes) diw.wallet.core.document.DocCryptoUtil.aesCmac(kMac, obj).copyOf(8)
        else MrtdCrypt.retailMac(kMac, MrtdCrypt.pad(obj, 8))
    }

    /** The data objects inside a GENERAL AUTHENTICATE response (dynamic authentication data, tag 7C). */
    private fun dynamic(data: ByteArray): ByteArray {
        val t = BerTlv.read(data, 0) ?: throw MrtdException("pace_format")
        if (t.tag != 0x7C) throw MrtdException("pace_format")
        return t.value
    }

    private suspend fun generalAuthenticate(channel: CardChannel, tag: Int, value: ByteArray, last: Boolean): ByteArray {
        val r = channel.transmit(if (last) 0x00 else 0x10, 0x86, 0x00, 0x00, BerTlv.encode(0x7C, if (tag == 0) ByteArray(0) else BerTlv.encode(tag, value)), 256)
        if (r.sw == 0x6300 || r.sw and 0xFFF0 == 0x63C0 || r.sw == 0x6982) throw MrtdException("access_denied", r.sw)
        if (!ok(r.sw)) throw MrtdException("pace_failed", r.sw)
        return dynamic(r.data)
    }

    /**
     * PACE with generic mapping (ICAO 9303 part 11, 4.4): the nonce from the chip decrypted with the password key,
     * the mapped generator, the ephemeral key agreement and the mutual authentication tokens.
     */
    suspend fun pace(channel: CardChannel, secret: AccessSecret, info: SecurityInfo.Pace): SecureChannel {
        val cipher = info.cipher ?: throw MrtdException("pace_unsupported")
        if (!info.genericMapping) throw MrtdException("pace_unsupported")
        val domain = info.parameterId?.let { MrtdCrypto.standardDomain(it) } ?: throw MrtdException("pace_unsupported")
        val oid = info.oid
        val mse = BerTlv.encode(0x80, BerTlv.oidValue(oid)) + byteArrayOf(0x83.toByte(), 1, secret.reference.toByte()) +
            byteArrayOf(0x84.toByte(), 1, info.parameterId.toByte())
        val set = channel.transmit(0x00, 0x22, 0xC1, 0xA4, mse, 0)
        if (!ok(set.sw)) throw MrtdException("pace_refused", set.sw)
        val z = BerTlv.find(generalAuthenticate(channel, 0, ByteArray(0), false), 0x80) ?: throw MrtdException("pace_format")
        val kPi = MrtdCrypt.kdf(cipher, secret.seed, MrtdCrypt.KDF_PACE)
        val s = MrtdCrypt.decrypt(cipher, kPi, ByteArray(cipher.blockSize), z)
        val mapKey = domain.generate()
        val cardMap = BerTlv.find(generalAuthenticate(channel, 0x81, mapKey.publicKey, false), 0x82) ?: throw MrtdException("pace_format")
        if (cardMap.contentEquals(mapKey.publicKey)) throw MrtdException("pace_failed")
        val mapped = domain.mapGeneric(s, mapKey, cardMap)
        val eph = mapped.generate()
        val cardEph = BerTlv.find(generalAuthenticate(channel, 0x83, eph.publicKey, false), 0x84) ?: throw MrtdException("pace_format")
        if (cardEph.contentEquals(eph.publicKey) || !mapped.validPublic(cardEph)) throw MrtdException("pace_failed")
        val k = mapped.agree(eph, cardEph)
        val kEnc = MrtdCrypt.kdf(cipher, k, MrtdCrypt.KDF_ENC)
        val kMac = MrtdCrypt.kdf(cipher, k, MrtdCrypt.KDF_MAC)
        val tPcd = token(cipher, kMac, oid, cardEph, domain.elliptic)
        val last = generalAuthenticate(channel, 0x85, tPcd, true)
        val tPicc = BerTlv.find(last, 0x86) ?: throw MrtdException("pace_format")
        if (!tPicc.contentEquals(token(cipher, kMac, oid, eph.publicKey, domain.elliptic))) throw MrtdException("pace_token")
        return SecureChannel(channel, cipher, kEnc, kMac, ByteArray(cipher.blockSize))
    }

    /**
     * Chip Authentication (ICAO 9303 part 11, 6.2): an ephemeral key agreement with the chip's static key from DG14
     * inside the current session, then new session keys. A chip whose private key was not there (a copy of the data
     * on another chip) cannot answer under the new keys, which the caller sees on the next read.
     */
    suspend fun chipAuthentication(
        current: SecureChannel,
        plain: CardChannel,
        key: SecurityInfo.ChipAuthenticationPublicKey,
        info: SecurityInfo.ChipAuthentication?,
    ): SecureChannel {
        val (domain, chipKey) = MrtdCrypto.publicKeyDomain(key.publicKey) ?: throw MrtdException("ca_unsupported")
        val eph = domain.generate()
        val cipher = info?.cipher ?: SmCipher.DES3
        val keyId = key.keyId ?: info?.keyId
        val idObject = keyId?.let { id ->
            val v = if (id < 0x100) byteArrayOf(id.toByte()) else byteArrayOf((id shr 8).toByte(), id.toByte())
            BerTlv.encode(0x84, v)
        } ?: ByteArray(0)
        if (cipher == SmCipher.DES3) {
            // Version 1 with 3DES: MSE:Set KAT carries the ephemeral key.
            val r = current.transmit(0x00, 0x22, 0x41, 0xA6, BerTlv.encode(0x91, eph.publicKey) + idObject, 0)
            if (!ok(r.sw)) throw MrtdException("ca_refused", r.sw)
        } else {
            val oid = info?.oid ?: throw MrtdException("ca_unsupported")
            val set = current.transmit(0x00, 0x22, 0x41, 0xA4, BerTlv.encode(0x80, BerTlv.oidValue(oid)) + idObject, 0)
            if (!ok(set.sw)) throw MrtdException("ca_refused", set.sw)
            val ga = current.transmit(0x00, 0x86, 0x00, 0x00, BerTlv.encode(0x7C, BerTlv.encode(0x80, eph.publicKey)), 256)
            if (!ok(ga.sw)) throw MrtdException("ca_refused", ga.sw)
        }
        val k = domain.agree(eph, chipKey)
        return SecureChannel(plain, cipher, MrtdCrypt.kdf(cipher, k, MrtdCrypt.KDF_ENC), MrtdCrypt.kdf(cipher, k, MrtdCrypt.KDF_MAC), ByteArray(cipher.blockSize))
    }

    /** Active Authentication: the chip signs [challenge] with the DG15 private key; the response is returned as is. */
    suspend fun activeAuthentication(channel: CardChannel, challenge: ByteArray): ByteArray {
        val r = channel.transmit(0x00, 0x88, 0x00, 0x00, challenge, 256)
        if (!ok(r.sw) || r.data.isEmpty()) throw MrtdException("aa_failed", r.sw)
        return r.data
    }
}

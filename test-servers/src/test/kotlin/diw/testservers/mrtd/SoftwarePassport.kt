package diw.testservers.mrtd

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.card.CardChannel
import diw.wallet.core.document.card.CardResponse
import diw.wallet.core.document.mrtd.AccessSecret
import diw.wallet.core.document.mrtd.AgreementDomain
import diw.wallet.core.document.mrtd.AgreementKeyPair
import diw.wallet.core.document.mrtd.BerTlv
import diw.wallet.core.document.mrtd.MrtdAccess
import diw.wallet.core.document.mrtd.MrtdCrypt
import diw.wallet.core.document.mrtd.MrtdCrypto
import diw.wallet.core.document.mrtd.MrtdOids
import diw.wallet.core.document.mrtd.MrzKey
import diw.wallet.core.document.mrtd.SmCipher
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.signers.ISO9796d2Signer
import java.security.KeyPair
import java.security.Signature
import java.security.interfaces.RSAPrivateCrtKey

/**
 * A software ICAO 9303 chip for tests: EF.CardAccess, BAC, PACE with generic mapping, secure messaging (3DES and
 * AES), SELECT and READ BINARY (also with an odd instruction for offsets past 32767), Chip Authentication (version 1
 * with 3DES and the AES variant) and Active Authentication (RSA ISO/IEC 9796-2 or plain ECDSA). The chip side is
 * written from the specification, not by calling the wallet's reader.
 */
class SoftwarePassport(
    private val files: Map<Int, ByteArray>,
    private val key: MrzKey,
    /** EF.CardAccess; null for a BAC-only chip. */
    private val cardAccess: ByteArray?,
    /** The Chip Authentication private key and its domain: the key whose public half DG14 holds. */
    private val caKey: Pair<AgreementDomain, AgreementKeyPair>? = null,
    /** The protocol named in DG14's ChipAuthenticationInfo, which sets the CA cipher. */
    private val caOid: String? = null,
    private val aaRsa: KeyPair? = null,
    private val aaEc: KeyPair? = null,
    /** Refuses PACE so the reader has to fall back to BAC. */
    private val refusePace: Boolean = false,
) : CardChannel {
    private class Sm(val cipher: SmCipher, val kEnc: ByteArray, val kMac: ByteArray, var ssc: ByteArray)

    private var sm: Sm? = null
    private var appSelected = false
    private var selected: Int? = null
    private var challenge: ByteArray? = null

    // PACE state
    private var paceOid: String? = null
    private var paceParam: Int? = null
    private var paceStep = 0
    private var nonce: ByteArray? = null
    private var mapped: AgreementDomain? = null
    private var chipMap: AgreementKeyPair? = null
    private var chipEph: AgreementKeyPair? = null
    private var pcdEph: ByteArray? = null
    private var paceK: ByteArray? = null

    // Chip Authentication with the AES protocol: set by MSE:Set AT, done by GENERAL AUTHENTICATE.
    private var caPending = false

    /** Commands seen, by instruction, for assertions. */
    val instructions = ArrayList<Int>()

    private fun r(sw: Int, data: ByteArray = ByteArray(0)) = CardResponse(sw, data)

    override suspend fun transmit(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): CardResponse {
        instructions.add(ins)
        val s = sm
        if (cla and 0x0C == 0x0C) {
            if (s == null) return r(0x6987)
            val plain = unwrap(s, cla, ins, p1, p2, data) ?: run { sm = null; return r(0x6988) }
            val (resp, after) = process(plain.first, ins, p1, p2, plain.second, plain.third)
            val wrapped = wrap(s, resp)
            after?.invoke()
            return wrapped
        }
        // Plain commands: only before access control, and only what the protocols need.
        if (s != null && ins != 0x86 && ins != 0x22) { sm = null; return r(0x6982) }
        return process(cla, ins, p1, p2, data, le).first
    }

    private fun inc(s: Sm) {
        for (i in s.ssc.indices.reversed()) {
            val v = (s.ssc[i].toInt() and 0xFF) + 1
            s.ssc[i] = v.toByte()
            if (v <= 0xFF) break
        }
    }

    private fun iv(s: Sm) = if (s.cipher.aes) DocCrypto.aesEcb(true, s.kEnc, s.ssc) else ByteArray(8)

    /** Checks and opens a protected command: (class, data, Le). */
    private fun unwrap(s: Sm, cla: Int, ins: Int, p1: Int, p2: Int, body: ByteArray): Triple<Int, ByteArray, Int>? {
        inc(s)
        var macInput = MrtdCrypt.pad(byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte()), s.cipher.blockSize)
        var data = ByteArray(0)
        var le = 0
        var mac: ByteArray? = null
        for (t in BerTlv.children(body)) {
            val raw = body.copyOfRange(t.start, t.end)
            when (t.tag) {
                0x87 -> { macInput += raw; data = MrtdCrypt.unpad(MrtdCrypt.decrypt(s.cipher, s.kEnc, iv(s), t.value.copyOfRange(1, t.value.size))) }
                0x85 -> { macInput += raw; data = MrtdCrypt.unpad(MrtdCrypt.decrypt(s.cipher, s.kEnc, iv(s), t.value)) }
                0x97 -> { macInput += raw; le = (t.value.firstOrNull()?.toInt() ?: 0) and 0xFF; if (le == 0) le = 256 }
                0x8E -> mac = t.value
            }
        }
        val expected = MrtdCrypt.mac(s.cipher, s.kMac, MrtdCrypt.pad(s.ssc + macInput.copyOfRange(0, macInput.size), s.cipher.blockSize))
        if (mac == null || !mac.contentEquals(expected)) return null
        return Triple(cla and 0xF3, data, le)
    }

    private fun wrap(s: Sm, resp: CardResponse): CardResponse {
        inc(s)
        var dos = ByteArray(0)
        if (resp.data.isNotEmpty()) {
            dos += BerTlv.encode(0x87, byteArrayOf(1) + MrtdCrypt.encrypt(s.cipher, s.kEnc, iv(s), MrtdCrypt.pad(resp.data, s.cipher.blockSize)))
        }
        dos += byteArrayOf(0x99.toByte(), 2, (resp.sw shr 8).toByte(), resp.sw.toByte())
        val mac = MrtdCrypt.mac(s.cipher, s.kMac, MrtdCrypt.pad(s.ssc + dos, s.cipher.blockSize))
        return CardResponse(resp.sw, dos + BerTlv.encode(0x8E, mac))
    }

    /** Runs a plain command; the second value runs after the response is protected (session key changes). */
    private fun process(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): Pair<CardResponse, (() -> Unit)?> = when (ins) {
        0xA4 -> select(p1, data) to null
        0xB0 -> readBinary(p1, p2, le) to null
        0xB1 -> readOdd(data, le) to null
        0x84 -> {
            challenge = DocCrypto.randomBytes(8)
            r(0x9000, challenge!!) to null
        }
        0x82 -> externalAuthenticate(data) to null
        0x22 -> mse(p1, p2, data)
        0x86 -> generalAuthenticate(cla, data)
        0x88 -> internalAuthenticate(data) to null
        else -> r(0x6D00) to null
    }

    private fun select(p1: Int, data: ByteArray): CardResponse {
        if (p1 == 0x04) {
            if (!data.contentEquals(byteArrayOf(0xA0.toByte(), 0, 0, 2, 0x47, 0x10, 1))) return r(0x6A82)
            appSelected = true
            selected = null
            return r(0x9000)
        }
        val fid = ((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF)
        if (fid == 0x011C) {
            if (cardAccess == null) return r(0x6A82)
            selected = fid
            return r(0x9000)
        }
        if (!appSelected) return r(0x6A82)
        if (sm == null) return r(0x6982)
        if (fid !in files) return r(0x6A82)
        selected = fid
        return r(0x9000)
    }

    private fun content(fid: Int?): ByteArray? = when (fid) {
        null -> null
        0x011C -> cardAccess
        else -> files[fid]
    }

    private fun readBinary(p1: Int, p2: Int, le: Int): CardResponse {
        val fid = if (p1 and 0x80 != 0) {
            val sfi = p1 and 0x1F
            if (sfi == 0x1C) 0x011C.takeIf { cardAccess != null } ?: return r(0x6A82) else return r(0x6A82)
        } else selected
        if (fid != 0x011C && sm == null) return r(0x6982)
        val f = content(fid) ?: return r(0x6986)
        val off = if (p1 and 0x80 != 0) p2 else ((p1 and 0x7F) shl 8) or p2
        if (off > f.size) return r(0x6B00)
        val n = minOf(if (le == 0) 256 else le, f.size - off)
        return r(if (n < le && off + n == f.size && le != 256) 0x6282 else 0x9000, f.copyOfRange(off, off + n))
    }

    private fun readOdd(data: ByteArray, le: Int): CardResponse {
        if (sm == null) return r(0x6982)
        val f = content(selected) ?: return r(0x6986)
        val off = BerTlv.uint(BerTlv.find(data, 0x54) ?: return r(0x6A80))
        if (off > f.size) return r(0x6B00)
        val n = minOf((if (le == 0) 256 else le) - 4, f.size - off)
        return r(0x9000, BerTlv.encode(0x53, f.copyOfRange(off, off + n)))
    }

    private fun externalAuthenticate(data: ByteArray): CardResponse {
        val rnd = challenge ?: return r(0x6985)
        challenge = null
        val seed = DocCrypto.digest("SHA-1", key.information.encodeToByteArray()).copyOf(16)
        val kEnc = MrtdCrypt.kdf(SmCipher.DES3, seed, 1)
        val kMac = MrtdCrypt.kdf(SmCipher.DES3, seed, 2)
        if (data.size != 40) return r(0x6700)
        if (!MrtdCrypt.retailMac(kMac, MrtdCrypt.pad(data.copyOf(32), 8)).contentEquals(data.copyOfRange(32, 40))) return r(0x6300)
        val s = DocCrypto.desEdeCbc(false, kEnc, ByteArray(8), data.copyOf(32))
        if (!s.copyOfRange(8, 16).contentEquals(rnd)) return r(0x6300)
        val rndIfd = s.copyOfRange(0, 8)
        val kIfd = s.copyOfRange(16, 32)
        val kIcc = DocCrypto.randomBytes(16)
        val e = DocCrypto.desEdeCbc(true, kEnc, ByteArray(8), rnd + rndIfd + kIcc)
        val m = MrtdCrypt.retailMac(kMac, MrtdCrypt.pad(e, 8))
        val seed2 = ByteArray(16) { (kIfd[it].toInt() xor kIcc[it].toInt()).toByte() }
        sm = Sm(SmCipher.DES3, MrtdCrypt.kdf(SmCipher.DES3, seed2, 1), MrtdCrypt.kdf(SmCipher.DES3, seed2, 2), rnd.copyOfRange(4, 8) + rndIfd.copyOfRange(4, 8))
        return r(0x9000, e + m)
    }

    private fun mse(p1: Int, p2: Int, data: ByteArray): Pair<CardResponse, (() -> Unit)?> {
        if (p1 == 0xC1 && p2 == 0xA4) {
            if (refusePace || cardAccess == null) return r(0x6A80) to null
            paceOid = BerTlv.find(data, 0x80)?.let { BerTlv.oidString(it) }
            paceParam = BerTlv.find(data, 0x84)?.let { BerTlv.uint(it) }
            if (BerTlv.find(data, 0x83)?.let { BerTlv.uint(it) } != 1) return r(0x6A80) to null
            paceStep = 0
            return r(0x9000) to null
        }
        val (domain, pair) = caKey ?: return r(0x6A80) to null
        if (p1 == 0x41 && p2 == 0xA6) {
            // Chip Authentication version 1 (3DES): new keys after this response.
            val eph = BerTlv.find(data, 0x91) ?: return r(0x6A80) to null
            val k = domain.agree(pair, eph)
            return r(0x9000) to { sm = Sm(SmCipher.DES3, MrtdCrypt.kdf(SmCipher.DES3, k, 1), MrtdCrypt.kdf(SmCipher.DES3, k, 2), ByteArray(8)) }
        }
        if (p1 == 0x41 && p2 == 0xA4) {
            val oid = BerTlv.find(data, 0x80)?.let { BerTlv.oidString(it) }
            if (oid != caOid) return r(0x6A80) to null
            caPending = true
            return r(0x9000) to null
        }
        return r(0x6A86) to null
    }

    private fun generalAuthenticate(cla: Int, data: ByteArray): Pair<CardResponse, (() -> Unit)?> {
        val inner = BerTlv.read(data, 0)?.takeIf { it.tag == 0x7C }?.value ?: return r(0x6A80) to null
        if (caPending) {
            caPending = false
            val (domain, pair) = caKey ?: return r(0x6985) to null
            val cipher = MrtdOids.cipherOf(caOid!!)!!
            val k = domain.agree(pair, BerTlv.find(inner, 0x80) ?: return r(0x6A80) to null)
            return r(0x9000, BerTlv.encode(0x7C, ByteArray(0))) to { sm = Sm(cipher, MrtdCrypt.kdf(cipher, k, 1), MrtdCrypt.kdf(cipher, k, 2), ByteArray(cipher.blockSize)) }
        }
        val oid = paceOid ?: return r(0x6985) to null
        val cipher = MrtdOids.cipherOf(oid)!!
        val domain = MrtdCrypto.standardDomain(paceParam!!)!!
        val elliptic = oid.startsWith(MrtdOids.PACE_ECDH_GM)
        val chained = cla and 0x10 != 0
        when (paceStep) {
            0 -> {
                if (!chained) return r(0x6883) to null
                val s = DocCrypto.randomBytes(cipher.blockSize)
                nonce = s
                val kPi = MrtdCrypt.kdf(cipher, AccessSecret.MrzSecret(key).seed, 3)
                paceStep = 1
                return r(0x9000, BerTlv.encode(0x7C, BerTlv.encode(0x80, MrtdCrypt.encrypt(cipher, kPi, ByteArray(cipher.blockSize), s)))) to null
            }
            1 -> {
                val pcdMap = BerTlv.find(inner, 0x81) ?: return r(0x6A80) to null
                val own = domain.generate()
                chipMap = own
                mapped = domain.mapGeneric(nonce!!, own, pcdMap)
                paceStep = 2
                return r(0x9000, BerTlv.encode(0x7C, BerTlv.encode(0x82, own.publicKey))) to null
            }
            2 -> {
                val pcd = BerTlv.find(inner, 0x83) ?: return r(0x6A80) to null
                val eph = mapped!!.generate()
                chipEph = eph
                pcdEph = pcd
                paceK = mapped!!.agree(eph, pcd)
                paceStep = 3
                return r(0x9000, BerTlv.encode(0x7C, BerTlv.encode(0x84, eph.publicKey))) to null
            }
            3 -> {
                if (chained) return r(0x6883) to null
                paceStep = 0
                val k = paceK!!
                val kMac = MrtdCrypt.kdf(cipher, k, 2)
                val expected = MrtdAccess.token(cipher, kMac, oid, chipEph!!.publicKey, elliptic)
                if (!expected.contentEquals(BerTlv.find(inner, 0x85))) return r(0x6300) to null
                val answer = MrtdAccess.token(cipher, kMac, oid, pcdEph!!, elliptic)
                sm = Sm(cipher, MrtdCrypt.kdf(cipher, k, 1), kMac, ByteArray(cipher.blockSize))
                return r(0x9000, BerTlv.encode(0x7C, BerTlv.encode(0x86, answer))) to null
            }
        }
        return r(0x6985) to null
    }

    private fun internalAuthenticate(challenge: ByteArray): CardResponse {
        if (sm == null) return r(0x6982)
        aaRsa?.let { kp ->
            val k = kp.private as RSAPrivateCrtKey
            val signer = ISO9796d2Signer(RSAEngine(), SHA1Digest(), true)
            signer.init(true, RSAKeyParameters(true, k.modulus, k.privateExponent))
            val m1 = DocCrypto.randomBytes(k.modulus.bitLength() / 8 - 20 - 2)
            val msg = m1 + challenge
            signer.update(msg, 0, msg.size)
            return r(0x9000, signer.generateSignature())
        }
        aaEc?.let { kp ->
            val sig = Signature.getInstance("SHA256withPLAIN-ECDSA", org.bouncycastle.jce.provider.BouncyCastleProvider())
            sig.initSign(kp.private)
            sig.update(challenge)
            return r(0x9000, sig.sign())
        }
        return r(0x6D00)
    }
}

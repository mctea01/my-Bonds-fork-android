package diw.testservers

import diw.wallet.core.document.DocCryptoUtil
import kotlinx.io.bytestring.ByteString
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPKdfParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair
import org.multipaz.nfc.CommandApdu
import org.multipaz.nfc.NfcIsoTag
import org.multipaz.nfc.NfcScanOptions
import org.multipaz.nfc.NfcTagReader
import org.multipaz.nfc.ResponseApdu
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import kotlin.coroutines.CoroutineContext

/** A key kind the simulated card can hold, with its OpenPGP algorithm attributes. */
enum class SimKey(val attributes: String) {
    RSA2048("010800001100"),
    P256_ECDSA("132A8648CE3D030107"),
    P256_ECDH("122A8648CE3D030107"),
    ED25519("162B06010401DA470F01"),
    X25519("122B060104019755010501"),
}

/**
 * A software OpenPGP card (OpenPGP card 3.4 command set) for tests: the keys live in memory, APDUs are answered as a
 * YubiKey does, including 61XX response chaining, command chaining, SELECT DATA for 7F21, PIN retry counters and an
 * optional KDF-DO. It also builds the matching OpenPGP certificate (with a user ID and binding signatures), as the
 * holder's published key would be, so signatures can be checked by other tools.
 */
class OpenPgpCardSim(
    val sig: SimKey,
    val dec: SimKey?,
    val pin: String = "123456",
    val kdf: Boolean = false,
    val signatureCertificate: ByteArray? = null,
    val name: String = "Lin<<Chu",
) {
    private val bc = BouncyCastleProvider()
    val created = Date((System.currentTimeMillis() / 1000 - 86_400) * 1000)
    val sigPair: KeyPair = generate(sig)
    val decPair: KeyPair? = dec?.let { generate(it) }
    var pinTries = 3
        private set
    private val verified = mutableSetOf<Int>()
    private var occurrence = 0
    private var pending = ByteArray(0)
    private var chained = ByteArray(0)
    var signatureCount = 0
        private set
    private val kdfSalt = ByteArray(8) { (it + 1).toByte() }
    /** Set to make the card answer with another key than it reports, as a swapped card would. */
    var swapSignatureKey: KeyPair? = null

    val certificate: PGPPublicKeyRing
    val secretRing: PGPSecretKeyRing

    init {
        val sigPgp = pgpPair(sig, sigPair)
        val calc = JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1)
        val hashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA) }.generate()
        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION, sigPgp, "Chu Lin <chu@example.org>", calc, hashed, null,
            JcaPGPContentSignerBuilder(sigPgp.publicKey.algorithm, HashAlgorithmTags.SHA256).setProvider(bc), null,
        )
        decPair?.let { kp ->
            val subHashed = PGPSignatureSubpacketGenerator().apply { setKeyFlags(false, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE) }.generate()
            gen.addSubKey(pgpPair(dec!!, kp), subHashed, null)
        }
        certificate = gen.generatePublicKeyRing()
        secretRing = gen.generateSecretKeyRing()
    }

    val sigFingerprint: ByteArray get() = certificate.publicKey.fingerprint
    val decFingerprint: ByteArray? get() = certificate.publicKeys.asSequence().firstOrNull { !it.isMasterKey }?.fingerprint

    private fun generate(k: SimKey): KeyPair = when (k) {
        SimKey.RSA2048 -> KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        SimKey.P256_ECDSA, SimKey.P256_ECDH -> KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        SimKey.ED25519 -> KeyPairGenerator.getInstance("Ed25519", bc).generateKeyPair()
        SimKey.X25519 -> KeyPairGenerator.getInstance("X25519", bc).generateKeyPair()
    }

    private fun pgpPair(k: SimKey, kp: KeyPair): JcaPGPKeyPair = when (k) {
        SimKey.RSA2048 -> JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, kp, created)
        SimKey.P256_ECDSA -> JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDSA, kp, created)
        SimKey.ED25519 -> JcaPGPKeyPair(PublicKeyAlgorithmTags.EDDSA_LEGACY, kp, created)
        SimKey.P256_ECDH, SimKey.X25519 ->
            JcaPGPKeyPair(PublicKeyAlgorithmTags.ECDH, PGPKdfParameters(HashAlgorithmTags.SHA256, SymmetricKeyAlgorithmTags.AES_128), kp, created)
    }

    // ---------------------------------------------------------------- APDU

    fun process(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): Pair<Int, ByteArray> {
        if (cla and 0x10 != 0) { chained += data; return 0x9000 to ByteArray(0) }
        val body = chained + data
        chained = ByteArray(0)
        return when (ins) {
            0xA4 -> if (body.copyOf(6).contentEquals(DocCryptoUtil.unhex("D27600012401"))) 0x9000 to ByteArray(0) else 0x6A82 to ByteArray(0)
            0xCA -> getData((p1 shl 8) or p2)
            0xA5 -> { occurrence = p1; 0x9000 to ByteArray(0) }
            0x47 -> if (p1 != 0x81) 0x6A86 to ByteArray(0) else publicKey(body[0].toInt() and 0xFF)
            0x20 -> verify(p2, body)
            0x2A -> when ((p1 shl 8) or p2) {
                0x9E9A -> sign(body)
                0x8086 -> decipher(body)
                else -> 0x6A86 to ByteArray(0)
            }
            else -> 0x6D00 to ByteArray(0)
        }
    }

    private fun tlv(tag: Int, v: ByteArray): ByteArray {
        val t = if (tag > 0xFF) byteArrayOf((tag shr 8).toByte(), tag.toByte()) else byteArrayOf(tag.toByte())
        val l = when {
            v.size < 0x80 -> byteArrayOf(v.size.toByte())
            v.size < 0x100 -> byteArrayOf(0x81.toByte(), v.size.toByte())
            else -> byteArrayOf(0x82.toByte(), (v.size shr 8).toByte(), v.size.toByte())
        }
        return t + l + v
    }

    private fun getData(tag: Int): Pair<Int, ByteArray> = when (tag) {
        0x6E -> {
            val aid = DocCryptoUtil.unhex("D2760001240103040006123456780000")
            val caps = byteArrayOf(if (kdf) 0x7D else 0x7C, 0, 0, 0, 0x08, 0, 0, 0xFF.toByte(), 0, 1)
            val fprs = sigFingerprint + (decFingerprint ?: ByteArray(20)) + ByteArray(20)
            val t = (created.time / 1000)
            val time = byteArrayOf((t shr 24).toByte(), (t shr 16).toByte(), (t shr 8).toByte(), t.toByte())
            val times = time + (if (dec != null) time else ByteArray(4)) + ByteArray(4)
            val inner = tlv(0xC0, caps) + tlv(0xC1, DocCryptoUtil.unhex(sig.attributes)) +
                tlv(0xC2, DocCryptoUtil.unhex((dec ?: SimKey.RSA2048).attributes)) + tlv(0xC3, DocCryptoUtil.unhex(SimKey.RSA2048.attributes)) +
                tlv(0xC4, byteArrayOf(0, 127, 127, 127, pinTries.toByte(), 0, 3)) + tlv(0xC5, fprs) + tlv(0xCD, times)
            0x9000 to tlv(0x6E, tlv(0x4F, aid) + tlv(0x5F52, DocCryptoUtil.unhex("0031C573C00140059000")) + tlv(0x73, inner))
        }
        0x65 -> 0x9000 to tlv(0x65, tlv(0x5B, name.encodeToByteArray()) + tlv(0x5F2D, "zh".encodeToByteArray()))
        0x5F50 -> 0x9000 to "https://keys.example.org/chu.asc".encodeToByteArray()
        0x7A -> 0x9000 to tlv(0x7A, tlv(0x93, byteArrayOf(0, 0, signatureCount.toByte())))
        0xF9 -> 0x9000 to if (kdf) tlv(0x81, byteArrayOf(3)) + tlv(0x82, byteArrayOf(8)) + tlv(0x83, byteArrayOf(0, 0, 0x10, 0)) + tlv(0x84, kdfSalt)
            else tlv(0x81, byteArrayOf(0))
        0x7F21 -> if (occurrence == 2 && signatureCertificate != null) 0x9000 to signatureCertificate else 0x6A88 to ByteArray(0)
        else -> 0x6A88 to ByteArray(0)
    }

    private fun publicKey(crt: Int): Pair<Int, ByteArray> {
        val (kind, kp) = when (crt) {
            0xB6 -> sig to sigPair
            0xB8 -> (dec ?: return 0x6A88 to ByteArray(0)) to decPair!!
            else -> return 0x6A88 to ByteArray(0)
        }
        val inner = when (kind) {
            SimKey.RSA2048 -> (kp.public as RSAPublicKey).let { tlv(0x81, unsigned(it.modulus)) + tlv(0x82, unsigned(it.publicExponent)) }
            SimKey.P256_ECDSA, SimKey.P256_ECDH -> (kp.public as ECPublicKey).let {
                tlv(0x86, byteArrayOf(4) + fixed(it.w.affineX, 32) + fixed(it.w.affineY, 32))
            }
            SimKey.ED25519, SimKey.X25519 -> tlv(0x86, kp.public.encoded.takeLast(32).toByteArray())
        }
        return 0x9000 to tlv(0x7F49, inner)
    }

    private fun verify(ref: Int, pinBytes: ByteArray): Pair<Int, ByteArray> {
        if (pinTries == 0) return 0x6983 to ByteArray(0)
        val expected = if (kdf) s2k(pin.encodeToByteArray()) else pin.encodeToByteArray()
        if (!pinBytes.contentEquals(expected)) {
            pinTries--
            return (0x63C0 or pinTries) to ByteArray(0)
        }
        pinTries = 3
        verified += ref
        return 0x9000 to ByteArray(0)
    }

    private fun s2k(p: ByteArray): ByteArray {
        val unit = kdfSalt + p
        val out = ByteArray(0x1000)
        var off = 0
        while (off < out.size) { val n = minOf(unit.size, out.size - off); unit.copyInto(out, off, 0, n); off += n }
        return MessageDigest.getInstance("SHA-256").digest(out)
    }

    private fun sign(input: ByteArray): Pair<Int, ByteArray> {
        if (0x81 !in verified) return 0x6982 to ByteArray(0)
        verified -= 0x81
        signatureCount++
        val kp = swapSignatureKey ?: sigPair
        val out = when (sig) {
            SimKey.RSA2048 -> Cipher.getInstance("RSA/ECB/PKCS1Padding").run { init(Cipher.ENCRYPT_MODE, kp.private); doFinal(input) }
            SimKey.P256_ECDSA -> {
                val der = Signature.getInstance("NONEwithECDSA").run { initSign(kp.private); update(input); sign() }
                rawEcdsa(der, 32)
            }
            SimKey.ED25519 -> Signature.getInstance("Ed25519", bc).run { initSign(kp.private); update(input); sign() }
            else -> return 0x6A80 to ByteArray(0)
        }
        return respond(out)
    }

    private fun decipher(input: ByteArray): Pair<Int, ByteArray> {
        if (0x82 !in verified) return 0x6982 to ByteArray(0)
        val kp = decPair ?: return 0x6A88 to ByteArray(0)
        return when (dec) {
            SimKey.RSA2048 -> {
                if (input[0] != 0.toByte()) return 0x6A80 to ByteArray(0)
                val m = runCatching { Cipher.getInstance("RSA/ECB/PKCS1Padding").run { init(Cipher.DECRYPT_MODE, kp.private); doFinal(input.copyOfRange(1, input.size)) } }
                    .getOrElse { return 0x6A80 to ByteArray(0) }
                respond(m)
            }
            SimKey.P256_ECDH -> {
                val point = input.copyOfRange(input.size - 65, input.size)
                val x = BigInteger(1, point.copyOfRange(1, 33)); val y = BigInteger(1, point.copyOfRange(33, 65))
                val params = (kp.public as ECPublicKey).params
                val peer = KeyFactory.getInstance("EC").generatePublic(java.security.spec.ECPublicKeySpec(java.security.spec.ECPoint(x, y), params))
                respond(KeyAgreement.getInstance("ECDH").run { init(kp.private); doPhase(peer, true); generateSecret() })
            }
            SimKey.X25519 -> {
                val raw = input.copyOfRange(input.size - 32, input.size)
                val peer = KeyFactory.getInstance("X25519", bc).generatePublic(X509EncodedKeySpec(DocCryptoUtil.unhex("302a300506032b656e032100") + raw))
                respond(KeyAgreement.getInstance("X25519", bc).run { init(kp.private); doPhase(peer, true); generateSecret() })
            }
            else -> 0x6A80 to ByteArray(0)
        }
    }

    /** Answers longer than 256 bytes come in parts with 61XX, as a YubiKey answers short APDUs. */
    private fun respond(out: ByteArray): Pair<Int, ByteArray> {
        if (out.size <= 256) return 0x9000 to out
        pending = out.copyOfRange(256, out.size)
        return (0x6100 or minOf(pending.size, 0xFF)) to out.copyOf(256)
    }

    fun getResponse(): Pair<Int, ByteArray> {
        val part = pending.copyOf(minOf(256, pending.size))
        pending = pending.copyOfRange(part.size, pending.size)
        return (if (pending.isEmpty()) 0x9000 else 0x6100 or minOf(pending.size, 0xFF)) to part
    }

    private fun unsigned(v: BigInteger): ByteArray = v.toByteArray().let { if (it[0] == 0.toByte() && it.size > 1) it.copyOfRange(1, it.size) else it }

    private fun fixed(v: BigInteger, n: Int): ByteArray = unsigned(v).let { ByteArray(n - it.size) + it }

    private fun rawEcdsa(der: ByteArray, n: Int): ByteArray {
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der)
        val r = (seq.getObjectAt(0) as org.bouncycastle.asn1.ASN1Integer).value
        val s = (seq.getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).value
        return fixed(r, n) + fixed(s, n)
    }

    // ---------------------------------------------------------------- NFC

    /** The card as a Multipaz tag, so the wallet's NfcCardChannel (61XX, 6CXX) is exercised too. */
    fun tag(): NfcIsoTag = object : NfcIsoTag() {
        override val maxTransceiveLength: Int get() = 261
        override suspend fun close() {}
        override suspend fun updateDialogMessage(message: String) {}
        override suspend fun transceive(command: CommandApdu): ResponseApdu {
            val data = command.payload.toByteArray()
            val (sw, out) = if (command.ins == 0xC0) getResponse()
                else process(command.cla, command.ins, command.p1, command.p2, data, command.le)
            return ResponseApdu(sw, ByteString(out))
        }
    }

    /** A reader that "taps" this card at once, as a USB YubiKey or PC/SC reader does. */
    fun reader(): NfcTagReader = object : NfcTagReader {
        override val external = true
        override val dialogAlwaysShown = false
        override val dialogNeverShown = true
        var taps = 0
        override suspend fun <T : Any> scan(
            message: String?,
            tagInteractionFunc: suspend (tag: NfcIsoTag) -> T?,
            options: NfcScanOptions,
            context: CoroutineContext,
        ): T { taps++; return tagInteractionFunc(tag()) ?: error("no result") }
    }
}

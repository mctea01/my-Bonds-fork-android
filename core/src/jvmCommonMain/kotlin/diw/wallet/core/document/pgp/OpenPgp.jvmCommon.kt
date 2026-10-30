package diw.wallet.core.document.pgp

import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.sign.SigningException
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.ECPublicBCPGKey
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import java.util.Date

actual object OpenPgp {
    internal val calculator = BcKeyFingerprintCalculator()

    /** Literal data larger than this is refused, so a compressed message cannot exhaust memory. */
    internal const val MAX_LITERAL = 256L * 1024 * 1024

    actual fun certificates(data: ByteArray): List<Pair<OpenPgpKeyInfo, ByteArray>> {
        val out = ArrayList<Pair<OpenPgpKeyInfo, ByteArray>>()
        for (block in blocks(data)) {
            val f = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(block)))
            while (true) {
                val o = runCatching { f.nextObject() }.getOrNull() ?: break
                when (o) {
                    is PGPPublicKeyRing -> out.add(describe(o, false) to o.getEncoded(true))
                    is PGPSecretKeyRing -> {
                        val ring = PGPPublicKeyRing(o.publicKeys.asSequence().toList())
                        out.add(describe(ring, true) to ring.getEncoded(true))
                    }
                    is PGPMarker -> {}
                    else -> break
                }
            }
        }
        return out
    }

    actual fun keyBodies(certificate: ByteArray): List<ByteArray> = runCatching {
        blocks(certificate).flatMap { block ->
            val f = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(block)))
            generateSequence { runCatching { f.nextObject() }.getOrNull() }
                .filterIsInstance<PGPPublicKeyRing>()
                .flatMap { ring -> ring.publicKeys.asSequence().map { it.publicKeyPacket.encodedContents } }
                .toList()
        }
    }.getOrDefault(emptyList())

    /** Each armored block of [data] on its own (a file may hold several), or the binary data itself. */
    internal fun blocks(data: ByteArray): List<ByteArray> {
        val text = runCatching { data.decodeToString(throwOnInvalidSequence = true) }.getOrNull() ?: return listOf(data)
        if ("-----BEGIN PGP " !in text) return listOf(data)
        return Regex("-----BEGIN PGP ([A-Z ]+)-----[\\s\\S]*?-----END PGP \\1-----").findAll(text).map { it.value.encodeToByteArray() }.toList()
    }

    actual fun verifyDetached(keyBody: ByteArray, data: ByteArray, signature: ByteArray): Boolean = runCatching {
        val key = PGPPublicKeyRing(OpenPgpPackets.packet(6, keyBody), calculator).publicKey
        val sigs = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(signature))).nextObject() as PGPSignatureList
        val sig = sigs[0]
        sig.init(BcPGPContentVerifierBuilderProvider(), key)
        sig.update(data)
        sig.verify()
    }.getOrDefault(false)

    actual fun encrypt(data: ByteArray, fileName: String, recipients: List<ByteArray>, armor: Boolean): ByteArray {
        if (recipients.isEmpty()) throw SigningException("請至少選擇一位收件人")
        val keys = recipients.map { bytes ->
            val ring = PGPPublicKeyRing(bytes, calculator)
            encryptionKey(ring) ?: throw SigningException("「" + (ring.publicKey.userIDs.asSequence().firstOrNull() ?: hex(ring.publicKey.fingerprint)) + "」沒有可用的加密金鑰（已撤銷、過期或金鑰旗標不允許加密）")
        }
        val bout = ByteArrayOutputStream()
        val sink: OutputStream = if (armor) ArmoredOutputStream(bout) else bout
        val gen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true).setSecureRandom(SecureRandom()),
        )
        keys.forEach { gen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(it)) }
        val encOut = gen.open(sink, ByteArray(1 shl 16))
        val literal = PGPLiteralDataGenerator()
        literal.open(encOut, PGPLiteralData.BINARY, fileName, data.size.toLong(), Date()).use { it.write(data) }
        literal.close()
        encOut.close()
        gen.close()
        if (armor) sink.close()
        return bout.toByteArray()
    }

    /**
     * The key of [ring] to encrypt to. A certificate the wallet built from a card has no signatures: its encryption
     * subkey is used. A published certificate needs a subkey (or primary key) whose binding allows encryption and that
     * is neither revoked nor expired.
     */
    internal fun encryptionKey(ring: PGPPublicKeyRing): PGPPublicKey? {
        val keys = ring.publicKeys.asSequence().toList()
        val master = ring.publicKey
        if (keys.none { it.signatures.hasNext() }) {
            return keys.firstOrNull { !it.isMasterKey && it.isEncryptionKey } ?: master.takeIf { it.isEncryptionKey }
        }
        val now = System.currentTimeMillis()
        fun usable(k: PGPPublicKey, flags: Int): Boolean = k.isEncryptionKey && !k.hasRevocation() &&
            (k.validSeconds == 0L || k.creationTime.time + k.validSeconds * 1000 > now) &&
            (flags == 0 || flags and (KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE) != 0)
        if (master.hasRevocation()) return null
        keys.filter { !it.isMasterKey }.forEach { k ->
            val binding = validBinding(master, k) ?: return@forEach
            if (usable(k, binding.hashedSubPackets?.keyFlags ?: 0) && binding.hashedSubPackets?.keyFlags != 0) return k
        }
        return master.takeIf { usable(it, primaryFlags(it)) && primaryFlags(it) != 0 }
    }

    /** The first subkey binding signature of [sub] that verifies with [master]. */
    internal fun validBinding(master: PGPPublicKey, sub: PGPPublicKey): PGPSignature? =
        sub.getSignaturesOfType(PGPSignature.SUBKEY_BINDING).asSequence().firstOrNull { s ->
            runCatching {
                s.init(BcPGPContentVerifierBuilderProvider(), master)
                s.verifyCertification(master, sub)
            }.getOrDefault(false)
        }

    /** Key flags of a primary key from its self-signatures (user ID certifications or a direct-key signature). */
    internal fun primaryFlags(k: PGPPublicKey): Int = k.signatures.asSequence()
        .filter { it.keyID == k.keyID && (it.isCertification || it.signatureType == PGPSignature.DIRECT_KEY) }
        .mapNotNull { it.hashedSubPackets?.keyFlags?.takeIf { f -> f != 0 } }
        .firstOrNull() ?: 0

    actual fun decrypt(message: ByteArray, algorithm: Int, key: ByteArray): OpenPgpPlaintext {
        val f = BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(message)))
        var o = f.nextObject()
        while (o is PGPMarker) o = f.nextObject()
        val list = o as? PGPEncryptedDataList ?: throw SigningException("這不是 OpenPGP 加密訊息")
        val enc = list.encryptedDataObjects.asSequence().filterIsInstance<PGPPublicKeyEncryptedData>().firstOrNull()
            ?: throw SigningException("這份加密訊息沒有公開金鑰收件人")
        if (!enc.isIntegrityProtected && !enc.isAEAD) throw SigningException("這份加密訊息沒有完整性保護（舊式 SED），為避免遭竄改的內容被當成可信資料，已拒絕解密")
        val alg = if (algorithm == 0) SymmetricKeyAlgorithmTags.AES_256 else algorithm
        val stream = try {
            enc.getDataStream(BcSessionKeyDataDecryptorFactory(PGPSessionKey(alg, key)))
        } catch (e: Exception) {
            throw SigningException("無法以卡片解出的會話金鑰解密：" + (e.message ?: e.javaClass.simpleName), e)
        }
        val content = readMessage(BcPGPObjectFactory(stream))
        if (enc.isIntegrityProtected && !enc.isAEAD && !runCatching { enc.verify() }.getOrDefault(false)) {
            throw SigningException("解密後的完整性檢查（MDC）失敗：資料可能被竄改，已不保存")
        }
        return content
    }

    actual fun literal(message: ByteArray): OpenPgpPlaintext? = runCatching {
        readMessage(BcPGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(message))))
    }.getOrNull()?.takeIf { it.fileName != null || it.data.isNotEmpty() }

    /** Reads a (decrypted) message: decompresses, takes the literal data and keeps the signatures as a detached one. */
    internal fun readMessage(f: BcPGPObjectFactory): OpenPgpPlaintext {
        var name: String? = null
        var data: ByteArray? = null
        val signatures = ArrayList<PGPSignature>()
        fun walk(factory: BcPGPObjectFactory, depth: Int) {
            if (depth > 4) throw SigningException("OpenPGP 訊息巢狀層數過多")
            while (true) {
                when (val o = factory.nextObject() ?: return) {
                    is PGPCompressedData -> walk(BcPGPObjectFactory(o.dataStream), depth + 1)
                    is PGPLiteralData -> {
                        name = o.fileName.takeIf { it.isNotBlank() && it != PGPLiteralData.CONSOLE }
                        data = readCapped(o.inputStream)
                    }
                    is PGPSignatureList -> signatures.addAll(o.asSequence())
                    is PGPOnePassSignatureList, is PGPMarker -> {}
                    else -> {}
                }
            }
        }
        walk(f, 0)
        val detached = if (signatures.isEmpty()) null else ByteArrayOutputStream().also { out ->
            signatures.forEach { it.encode(out) }
        }.toByteArray()
        return OpenPgpPlaintext(name, data ?: throw SigningException("OpenPGP 訊息內沒有資料"), detached)
    }

    internal fun readCapped(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(1 shl 16)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > MAX_LITERAL) throw SigningException("OpenPGP 訊息內容超過 256 MB，已停止")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    // ---------------------------------------------------------------- description

    internal fun describe(ring: PGPPublicKeyRing, hadSecret: Boolean): OpenPgpKeyInfo {
        val master = ring.publicKey
        val subs = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
        val flags = primaryFlags(master)
        val primary = keyInfo(master, flags, master)
        return OpenPgpKeyInfo(
            fingerprint = hex(master.fingerprint),
            version = master.version,
            userIds = master.userIDs.asSequence().toList(),
            primary = primary,
            subkeys = subs.map { k -> keyInfo(k, validBinding(master, k)?.hashedSubPackets?.keyFlags ?: if (k.signatures.hasNext()) -1 else 0, master) },
            hadSecret = hadSecret,
        )
    }

    /** [flags] -1 marks a subkey whose binding does not verify: listed, but usable for nothing. */
    private fun keyInfo(k: PGPPublicKey, flags: Int, master: PGPPublicKey): OpenPgpSubkeyInfo {
        val created = k.creationTime.time / 1000
        val signer = k.algorithm in SIGNING_ALGORITHMS
        return OpenPgpSubkeyInfo(
            fingerprint = hex(k.fingerprint),
            algorithm = algorithmName(k),
            created = created,
            expires = k.validSeconds.takeIf { it > 0 }?.let { created + it },
            revoked = revoked(k, master),
            canSign = flags != -1 && signer && (flags == 0 || flags and KeyFlags.SIGN_DATA != 0),
            canEncrypt = flags != -1 && k.isEncryptionKey && (flags == 0 || flags and (KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE) != 0),
        )
    }

    /** A revocation signature on [k] that verifies (by the primary key). */
    internal fun revocation(k: PGPPublicKey, master: PGPPublicKey): PGPSignature? {
        val type = if (k.isMasterKey) PGPSignature.KEY_REVOCATION else PGPSignature.SUBKEY_REVOCATION
        return k.getSignaturesOfType(type).asSequence().firstOrNull { s ->
            runCatching {
                s.init(BcPGPContentVerifierBuilderProvider(), master)
                if (k.isMasterKey) s.verifyCertification(k) else s.verifyCertification(master, k)
            }.getOrDefault(false)
        }
    }

    private fun revoked(k: PGPPublicKey, master: PGPPublicKey): Boolean = revocation(k, master) != null

    internal val SIGNING_ALGORITHMS = setOf(
        PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN, PublicKeyAlgorithmTags.DSA,
        PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.EDDSA_LEGACY, PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.Ed448,
    )

    fun algorithmName(k: PGPPublicKey): String {
        val curve = (k.publicKeyPacket.key as? ECPublicBCPGKey)?.curveOID?.id?.let { CURVES[it] ?: it }
        return when (k.algorithm) {
            PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN, PublicKeyAlgorithmTags.RSA_ENCRYPT -> "RSA ${k.bitStrength}"
            PublicKeyAlgorithmTags.DSA -> "DSA ${k.bitStrength}"
            PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT, PublicKeyAlgorithmTags.ELGAMAL_GENERAL -> "ElGamal ${k.bitStrength}"
            PublicKeyAlgorithmTags.ECDSA -> "ECDSA $curve"
            PublicKeyAlgorithmTags.ECDH -> "ECDH $curve"
            PublicKeyAlgorithmTags.EDDSA_LEGACY -> "EdDSA $curve"
            PublicKeyAlgorithmTags.Ed25519 -> "Ed25519"
            PublicKeyAlgorithmTags.Ed448 -> "Ed448"
            PublicKeyAlgorithmTags.X25519 -> "X25519"
            PublicKeyAlgorithmTags.X448 -> "X448"
            else -> "演算法 ${k.algorithm}"
        }
    }

    fun hashName(id: Int): String = when (id) {
        1 -> "MD5"
        2 -> "SHA-1"
        3 -> "RIPEMD-160"
        8 -> "SHA-256"
        9 -> "SHA-384"
        10 -> "SHA-512"
        11 -> "SHA-224"
        12 -> "SHA3-256"
        14 -> "SHA3-512"
        else -> "雜湊 $id"
    }

    fun publicKeyAlgorithmName(id: Int): String = when (id) {
        1, 2, 3 -> "RSA"
        16, 20 -> "ElGamal"
        17 -> "DSA"
        18 -> "ECDH"
        19 -> "ECDSA"
        22 -> "EdDSA"
        25 -> "X25519"
        26 -> "X448"
        27 -> "Ed25519"
        28 -> "Ed448"
        else -> "演算法 $id"
    }

    fun symmetricName(id: Int): String = when (id) {
        2 -> "3DES"
        3 -> "CAST5"
        4 -> "Blowfish"
        7 -> "AES-128"
        8 -> "AES-192"
        9 -> "AES-256"
        10 -> "Twofish"
        11, 12, 13 -> "Camellia"
        else -> "演算法 $id"
    }

    private val CURVES = mapOf(
        "1.2.840.10045.3.1.7" to "NIST P-256",
        "1.3.132.0.34" to "NIST P-384",
        "1.3.132.0.35" to "NIST P-521",
        "1.3.36.3.3.2.8.1.1.7" to "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.11" to "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" to "brainpoolP512r1",
        "1.3.6.1.4.1.11591.15.1" to "Ed25519",
        "1.3.6.1.4.1.3029.1.5.1" to "Curve25519",
        "1.3.101.112" to "Ed25519",
        "1.3.101.110" to "X25519",
    )

    fun hex(b: ByteArray): String = DocCryptoUtil.hex(b).uppercase()
}

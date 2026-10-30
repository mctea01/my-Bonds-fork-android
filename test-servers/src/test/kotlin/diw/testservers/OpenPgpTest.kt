package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocumentFormat
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.DocumentVerdict
import diw.wallet.core.document.card.NfcCardChannel
import diw.wallet.core.document.card.OpenPgpCard
import diw.wallet.core.document.card.OpenPgpKeySlot
import diw.wallet.core.document.pgp.OpenPgp
import diw.wallet.core.document.pgp.OpenPgpCards
import diw.wallet.core.document.pgp.OpenPgpKind
import diw.wallet.core.document.pgp.OpenPgpPackets
import diw.wallet.core.document.pgp.OpenPgpTapSigner
import diw.wallet.core.document.pgp.OpenPgpTrust
import diw.wallet.core.document.pgp.OpenPgpTrustedKey
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.trust.TrustTier
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.multipaz.crypto.X509Cert
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

class OpenPgpTest {
    private val content = "DIW MY WALLET OpenPGP 測試文件\n第二行\n".encodeToByteArray()

    private fun trust(vararg keys: OpenPgpTrustedKey) = object : DocumentTrustSource {
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: Instant) =
            TrustDecision(TrustTier.T4, null, false, null, emptySet())
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
        override suspend fun openPgpKeys(): List<OpenPgpTrustedKey> = keys.toList()
    }

    private fun armored(bytes: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toByteArray()
    }

    @Test
    fun readsCardAndMatchesFingerprints() = runBlocking<Unit> {
        for ((sig, dec) in listOf(SimKey.RSA2048 to SimKey.RSA2048, SimKey.ED25519 to SimKey.X25519, SimKey.P256_ECDSA to SimKey.P256_ECDH)) {
            val sim = OpenPgpCardSim(sig, dec)
            val card = OpenPgpCard(NfcCardChannel(sim.tag()))
            card.connect()
            val info = OpenPgpCards.withPackets(card.readInfo(), emptyList())
            assertEquals("3.4", info.version)
            assertEquals("Yubico", info.manufacturerName)
            assertEquals("12345678", info.serial)
            assertEquals("Chu Lin", info.cardholder)
            assertEquals(3, info.pinStatus?.pw1Tries)
            val s = assertNotNull(info.key(OpenPgpKeySlot.SIGNATURE))
            assertContentEquals(sim.sigFingerprint, OpenPgpPackets.fingerprint(assertNotNull(s.packet, "$sig packet")))
            val d = assertNotNull(info.key(OpenPgpKeySlot.DECRYPTION))
            assertContentEquals(sim.decFingerprint, OpenPgpPackets.fingerprint(assertNotNull(d.packet, "$dec packet")))
        }
    }

    @Test
    fun detachedSignatureVerifiesWithPublishedCertificate() = runBlocking<Unit> {
        for (kind in listOf(SimKey.RSA2048, SimKey.ED25519, SimKey.P256_ECDSA)) {
            val sim = OpenPgpCardSim(kind, null, kdf = kind == SimKey.ED25519)
            val signer = OpenPgpTapSigner(sim.reader(), sim.pin)
            signer.load(x509 = false)
            val asc = signer.signDetached(content)
            assertTrue(asc.decodeToString().startsWith("-----BEGIN PGP SIGNATURE-----"))
            val cert = sim.certificate.getEncoded(true)
            val report = DocumentInspector.inspect(asc, "doc.txt.asc", trust(OpenPgpTrustedKey(cert, "Chu", OpenPgpTrust.VERIFIED)), content)
            assertEquals(DocumentFormat.OPENPGP, report.format)
            assertEquals(OpenPgpKind.DETACHED_SIGNATURE, report.openPgp?.kind)
            val s = report.signatures.single()
            assertEquals(Check.PASS, s.integrity, "$kind: ${s.problems}")
            assertEquals(Check.PASS, s.certificateValidity, "$kind: ${s.problems}")
            assertEquals("T2", s.trust?.tier)
            assertEquals(DocumentVerdict.VALID, report.verdict)
            gpgVerify(cert, asc, content)

            val tampered = DocumentInspector.inspect(asc, "doc.txt.asc", trust(OpenPgpTrustedKey(cert, "Chu")), content + 0x20)
            assertEquals(DocumentVerdict.INVALID, tampered.verdict)
            val unknown = DocumentInspector.inspect(asc, "doc.txt.asc", trust(), content)
            assertEquals(Check.NOT_CHECKED, unknown.signatures.single().integrity)
            assertTrue(unknown.openPgp!!.signers.single() == OpenPgp.hex(sim.sigFingerprint))
            val unverified = DocumentInspector.inspect(asc, "doc.txt.asc", trust(OpenPgpTrustedKey(cert, "Chu", OpenPgpTrust.UNVERIFIED)), content)
            assertEquals("T3", unverified.signatures.single().trust?.tier)
            val distrusted = DocumentInspector.inspect(asc, "doc.txt.asc", trust(OpenPgpTrustedKey(cert, "Chu", OpenPgpTrust.DISTRUSTED)), content)
            assertEquals("T4", distrusted.signatures.single().trust?.tier)
        }
    }

    @Test
    fun cardOnlyCertificateVerifiesItsOwnSignatures() = runBlocking<Unit> {
        val sim = OpenPgpCardSim(SimKey.ED25519, SimKey.X25519)
        val info = OpenPgpCards.read(sim.reader(), "tap")
        val bodies = listOfNotNull(info.key(OpenPgpKeySlot.SIGNATURE)?.packet, info.key(OpenPgpKeySlot.DECRYPTION)?.packet)
        val cardCert = OpenPgpPackets.cardCertificate(bodies)
        val keys = OpenPgp.certificates(cardCert)
        assertEquals(OpenPgp.hex(sim.sigFingerprint), keys.single().first.fingerprint)
        val signer = OpenPgpTapSigner(sim.reader(), sim.pin)
        signer.load(false)
        val asc = signer.signDetached(content)
        val report = DocumentInspector.inspect(asc, "a.asc", trust(OpenPgpTrustedKey(cardCert, info.label, OpenPgpTrust.OWN_CARD)), content)
        assertEquals(DocumentVerdict.VALID, report.verdict, report.signatures.single().problems.toString())
    }

    @Test
    fun wrongPinStopsWithRemainingTries() = runBlocking<Unit> {
        val sim = OpenPgpCardSim(SimKey.RSA2048, null)
        val signer = OpenPgpTapSigner(sim.reader(), "000000")
        signer.load(false)
        val e = assertFailsWith<SigningException> { signer.signDetached(content) }
        assertTrue("還可以再試 2 次" in e.message!!, e.message)
        assertEquals(2, sim.pinTries)
    }

    @Test
    fun swappedCardIsRefused() = runBlocking<Unit> {
        val sim = OpenPgpCardSim(SimKey.P256_ECDSA, null)
        val signer = OpenPgpTapSigner(sim.reader(), sim.pin)
        signer.load(false)
        sim.swapSignatureKey = OpenPgpCardSim(SimKey.P256_ECDSA, null).sigPair
        assertFailsWith<SigningException> { signer.signDetached(content) }
    }

    @Test
    fun x509SigningWithCardholderCertificateAndSelfIssued() = runBlocking<Unit> {
        // Without a cardholder certificate the card certifies itself in the first tap.
        val rsa = OpenPgpCardSim(SimKey.RSA2048, null)
        val self = OpenPgpTapSigner(rsa.reader(), rsa.pin)
        self.load(x509 = true, subject = "林測試")
        val made = assertNotNull(self.selfIssued)
        assertEquals(SignerKeyType.RSA, self.keyType)
        val cades = DocumentSigning.signCades(content, self, true, null, null, false)
        val report = DocumentInspector.inspect(cades, "doc.txt.p7s", trust(), content)
        assertEquals(Check.PASS, report.signatures.single().integrity)
        assertTrue(DocumentSigning.certificateSummary(made)!!.first.contains("林測試"))

        // A cached certificate is used again without another signature.
        val again = OpenPgpTapSigner(rsa.reader(), rsa.pin, cachedCertificate = { made })
        val before = rsa.signatureCount
        again.load(x509 = true)
        assertNull(again.selfIssued)
        assertEquals(before, rsa.signatureCount)

        // A P-256 card with its own certificate in the signature slot (DO 7F21, third occurrence).
        val probe = OpenPgpCardSim(SimKey.P256_ECDSA, null)
        val probeSigner = OpenPgpTapSigner(probe.reader(), probe.pin)
        probeSigner.load(x509 = true, subject = "P-256")
        val cert = probeSigner.selfIssued!!
        val withCert = OpenPgpTapSigner(CertCard(probe, cert).reader(), probe.pin)
        withCert.load(x509 = true)
        assertNull(withCert.selfIssued)
        assertContentEquals(cert, withCert.certificateChain.first())
        val sig = withCert.sign(content)
        assertTrue(sig.isNotEmpty())

        // Ed25519 cannot sign X.509 formats.
        val ed = OpenPgpCardSim(SimKey.ED25519, null)
        assertFailsWith<SigningException> { OpenPgpTapSigner(ed.reader(), ed.pin).load(x509 = true) }
    }

    /** The same simulated card, answering 7F21 for the signature slot with [cert]. */
    private class CertCard(private val sim: OpenPgpCardSim, private val cert: ByteArray) {
        private var occurrence = 0
        fun reader() = object : org.multipaz.nfc.NfcTagReader {
            override val external = true
            override val dialogAlwaysShown = false
            override val dialogNeverShown = true
            override suspend fun <T : Any> scan(
                message: String?, tagInteractionFunc: suspend (tag: org.multipaz.nfc.NfcIsoTag) -> T?,
                options: org.multipaz.nfc.NfcScanOptions, context: kotlin.coroutines.CoroutineContext,
            ): T {
                val inner = sim.tag()
                val tag = object : org.multipaz.nfc.NfcIsoTag() {
                    override val maxTransceiveLength = 261
                    override suspend fun close() {}
                    override suspend fun updateDialogMessage(message: String) {}
                    override suspend fun transceive(command: org.multipaz.nfc.CommandApdu): org.multipaz.nfc.ResponseApdu {
                        if (command.ins == 0xA5) occurrence = command.p1
                        if (command.ins == 0xCA && command.p1 == 0x7F && command.p2 == 0x21 && occurrence == 2) {
                            return org.multipaz.nfc.ResponseApdu(0x9000, kotlinx.io.bytestring.ByteString(cert))
                        }
                        return inner.transceive(command)
                    }
                }
                return tagInteractionFunc(tag)!!
            }
        }
    }

    @Test
    fun encryptsToCardAndDecryptsWithIt() = runBlocking<Unit> {
        for (dec in listOf(SimKey.RSA2048, SimKey.X25519, SimKey.P256_ECDH)) {
            val sim = OpenPgpCardSim(if (dec == SimKey.RSA2048) SimKey.RSA2048 else SimKey.ED25519, dec)
            for (armor in listOf(false, true)) {
                val message = OpenPgp.encrypt(content, "報告.pdf", listOf(sim.certificate.getEncoded(true)), armor)
                val report = DocumentInspector.inspect(message, "報告.pdf.gpg", trust())
                assertEquals(OpenPgpKind.ENCRYPTED, report.openPgp?.kind)
                assertEquals(OpenPgp.hex(sim.decFingerprint!!).takeLast(16), report.openPgp!!.recipients.single().key.takeLast(16))
                val (_, session) = OpenPgpCards.sessionKey(sim.reader(), "tap", sim.pin, message)
                val plain = OpenPgp.decrypt(message, session.first, session.second)
                assertContentEquals(content, plain.data, "$dec")
                assertEquals("報告.pdf", plain.fileName)
            }
            gpgEncryptAndCardDecrypt(sim)
        }
    }

    @Test
    fun messageForAnotherCardIsRefused() = runBlocking<Unit> {
        val a = OpenPgpCardSim(SimKey.ED25519, SimKey.X25519)
        val b = OpenPgpCardSim(SimKey.ED25519, SimKey.X25519)
        val message = OpenPgp.encrypt(content, "x.txt", listOf(a.certificate.getEncoded(true)), false)
        val e = assertFailsWith<SigningException> { OpenPgpCards.sessionKey(b.reader(), "tap", b.pin, message) }
        assertTrue("不是寄給這張卡片" in e.message!!, e.message)
    }

    @Test
    fun introducerRaisesUnverifiedKeysOneLevel() = runBlocking<Unit> {
        val intro = OpenPgpCardSim(SimKey.P256_ECDSA, null)
        val subject = OpenPgpCardSim(SimKey.ED25519, null)
        val bc = org.bouncycastle.jce.provider.BouncyCastleProvider()
        val introPub = intro.certificate.publicKey
        val introKey = intro.secretRing.secretKey.extractPrivateKey(null)
        val uid = subject.certificate.publicKey.userIDs.next()
        val gen = org.bouncycastle.openpgp.PGPSignatureGenerator(
            org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder(introPub.algorithm, org.bouncycastle.bcpg.HashAlgorithmTags.SHA256).setProvider(bc),
            introPub,
        )
        gen.init(org.bouncycastle.openpgp.PGPSignature.POSITIVE_CERTIFICATION, introKey)
        val certification = gen.generateCertification(uid, subject.certificate.publicKey)
        val certified = org.bouncycastle.openpgp.PGPPublicKey.addCertification(subject.certificate.publicKey, uid, certification)
        val subjectCert = org.bouncycastle.openpgp.PGPPublicKeyRing.insertPublicKey(subject.certificate, certified).getEncoded(true)
        val introCert = intro.certificate.getEncoded(true)

        val signer = OpenPgpTapSigner(subject.reader(), subject.pin)
        signer.load(false)
        val asc = signer.signDetached(content)
        suspend fun tier(introTrust: OpenPgpTrust, introducer: Boolean) = DocumentInspector.inspect(
            asc, "doc.asc",
            trust(OpenPgpTrustedKey(introCert, "Intro", introTrust, introducer), OpenPgpTrustedKey(subjectCert, "Subject", OpenPgpTrust.UNVERIFIED)),
            content,
        ).signatures.single().trust?.tier
        assertEquals("T2", tier(OpenPgpTrust.VERIFIED, true))
        assertEquals("T2", tier(OpenPgpTrust.OWN_CARD, true))
        assertEquals("T3", tier(OpenPgpTrust.VERIFIED, false))
        assertEquals("T3", tier(OpenPgpTrust.UNVERIFIED, true))

        // An introducer revoked as compromised, or a certification it withdrew, raises nothing.
        fun generator(type: Int, reason: Int? = null) = org.bouncycastle.openpgp.PGPSignatureGenerator(
            org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder(introPub.algorithm, org.bouncycastle.bcpg.HashAlgorithmTags.SHA256).setProvider(bc),
            introPub,
        ).apply {
            init(type, introKey)
            if (reason != null) setHashedSubpackets(org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator().apply { setRevocationReason(false, reason.toByte(), "") }.generate())
        }
        val revocation = generator(org.bouncycastle.openpgp.PGPSignature.KEY_REVOCATION, org.bouncycastle.bcpg.sig.RevocationReasonTags.KEY_COMPROMISED.toInt())
            .generateCertification(introPub)
        val revokedIntro = org.bouncycastle.openpgp.PGPPublicKeyRing.insertPublicKey(
            intro.certificate, org.bouncycastle.openpgp.PGPPublicKey.addCertification(introPub, revocation),
        ).getEncoded(true)
        suspend fun tierWith(introCertificate: ByteArray, subjectCertificate: ByteArray) = DocumentInspector.inspect(
            asc, "doc.asc",
            trust(OpenPgpTrustedKey(introCertificate, "Intro", OpenPgpTrust.VERIFIED, true), OpenPgpTrustedKey(subjectCertificate, "Subject", OpenPgpTrust.UNVERIFIED)),
            content,
        ).signatures.single().trust?.tier
        assertEquals("T3", tierWith(revokedIntro, subjectCert))
        val withdrawal = generator(org.bouncycastle.openpgp.PGPSignature.CERTIFICATION_REVOCATION).generateCertification(uid, certified)
        val withdrawn = org.bouncycastle.openpgp.PGPPublicKeyRing.insertPublicKey(
            subject.certificate, org.bouncycastle.openpgp.PGPPublicKey.addCertification(certified, uid, withdrawal),
        ).getEncoded(true)
        assertEquals("T3", tierWith(introCert, withdrawn))
        // A copy without the revocation, joined with the stored one, keeps it.
        assertTrue(OpenPgp.certificates(OpenPgp.merge(revokedIntro, introCert)).single().first.revoked)
        assertTrue(OpenPgp.certificates(OpenPgp.merge(introCert, revokedIntro)).single().first.revoked)

        // The key packets of a full certificate let a card key that cannot be rebuilt alone be matched.
        val bodies = OpenPgp.keyBodies(subjectCert)
        assertTrue(bodies.any { OpenPgpPackets.fingerprint(it).contentEquals(subject.sigFingerprint) })
    }

    @Test
    fun strippedCertificateCannotCarryAForeignSubkey() = runBlocking<Unit> {
        val victim = OpenPgpCardSim(SimKey.RSA2048, null)
        val attacker = OpenPgpCardSim(SimKey.P256_ECDSA, SimKey.P256_ECDH)
        val victimBody = victim.certificate.publicKey.publicKeyPacket.encodedContents
        val attackerSig = attacker.certificate.publicKey.publicKeyPacket.encodedContents
        val attackerDec = attacker.certificate.publicKeys.asSequence().first { !it.isMasterKey }.publicKeyPacket.encodedContents
        // The trusted primary key with every signature removed and the attacker's keys appended as subkeys.
        val stripped = OpenPgpPackets.cardCertificate(listOf(victimBody, attackerSig, attackerDec))
        val signer = OpenPgpTapSigner(attacker.reader(), attacker.pin)
        signer.load(false)
        val asc = signer.signDetached(content)
        val forged = DocumentInspector.inspect(asc, "doc.asc", trust(OpenPgpTrustedKey(stripped, "Victim", OpenPgpTrust.VERIFIED)), content)
        assertEquals(Check.FAIL, forged.signatures.single().certificateValidity)
        assertTrue(forged.verdict != DocumentVerdict.VALID)
        assertFailsWith<SigningException> { OpenPgp.encrypt(content, "x.txt", listOf(stripped), false) }
        assertTrue(OpenPgp.certificates(stripped).single().first.subkeys.none { it.canSign || it.canEncrypt })

        // The same keys read from the holder's own card need no binding.
        val cardKeys = setOf(OpenPgp.hex(attacker.sigFingerprint), OpenPgp.hex(attacker.decFingerprint!!))
        val own = DocumentInspector.inspect(asc, "doc.asc", trust(OpenPgpTrustedKey(stripped, "Card", OpenPgpTrust.OWN_CARD, cardKeys = cardKeys)), content)
        assertEquals(DocumentVerdict.VALID, own.verdict, own.signatures.single().problems.toString())
        assertTrue(OpenPgp.encrypt(content, "x.txt", listOf(stripped), false, cardKeys).isNotEmpty())
    }

    @Test
    fun certificatesAndSecretKeysAreDescribed() = runBlocking<Unit> {
        val sim = OpenPgpCardSim(SimKey.RSA2048, SimKey.RSA2048)
        val pub = armored(sim.certificate.getEncoded(true))
        val keys = OpenPgp.certificates(pub)
        val info = keys.single().first
        assertEquals("Chu Lin <chu@example.org>", info.name)
        assertTrue(info.canSign && info.canEncrypt)
        val report = DocumentInspector.inspect(pub, "chu.asc", trust())
        assertEquals(OpenPgpKind.PUBLIC_KEYS, report.openPgp?.kind)
        val secret = DocumentInspector.inspect(sim.secretRing.encoded, "chu-secret.gpg", trust())
        assertEquals(OpenPgpKind.SECRET_KEYS, secret.openPgp?.kind)
        assertTrue(OpenPgp.certificates(sim.secretRing.encoded).single().first.hadSecret)
    }

    @Test
    fun gpgClearsignedAndSignedMessagesVerify() = runBlocking<Unit> {
        val sim = OpenPgpCardSim(SimKey.ED25519, SimKey.X25519)
        val home = gpgHome() ?: return@runBlocking
        File(home, "sec.gpg").writeBytes(sim.secretRing.encoded)
        gpg(home, "--import", File(home, "sec.gpg").path)
        val input = File(home, "in.txt").apply { writeBytes(content) }
        gpg(home, "--clearsign", "--output", File(home, "clear.asc").path, input.path)
        gpg(home, "--sign", "--output", File(home, "signed.gpg").path, input.path)
        val cert = OpenPgpTrustedKey(sim.certificate.getEncoded(true), "Chu", OpenPgpTrust.VERIFIED)
        val clear = DocumentInspector.inspect(File(home, "clear.asc").readBytes(), "clear.asc", trust(cert))
        assertEquals(OpenPgpKind.CLEARTEXT_SIGNED, clear.openPgp?.kind)
        assertEquals(DocumentVerdict.VALID, clear.verdict, clear.signatures.map { it.problems }.toString())
        val signed = DocumentInspector.inspect(File(home, "signed.gpg").readBytes(), "signed.gpg", trust(cert))
        assertEquals(OpenPgpKind.SIGNED_MESSAGE, signed.openPgp?.kind)
        assertEquals(DocumentVerdict.VALID, signed.verdict, signed.signatures.map { it.problems }.toString())
        val literal = assertNotNull(OpenPgp.literal(File(home, "signed.gpg").readBytes()))
        assertContentEquals(content, literal.data)
        assertNotNull(literal.detachedSignature)
    }

    // ---------------------------------------------------------------- GnuPG interop (skipped without gpg)

    private fun gpgHome(): File? {
        if (runCatching { ProcessBuilder("gpg", "--version").start().waitFor() }.getOrNull() != 0) return null
        return kotlin.io.path.createTempDirectory("diw-gpg").toFile().also { it.setReadable(true, true); it.setWritable(true, true); it.setExecutable(true, true) }
    }

    private fun gpg(home: File, vararg args: String): String {
        val p = ProcessBuilder(listOf("gpg", "--homedir", home.path, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--trust-model", "always") + args)
            .redirectErrorStream(true).start()
        val out = p.inputStream.readBytes().decodeToString()
        assertTrue(p.waitFor(60, TimeUnit.SECONDS))
        assertEquals(0, p.exitValue(), out)
        return out
    }

    private fun gpgVerify(cert: ByteArray, asc: ByteArray, data: ByteArray) {
        val home = gpgHome() ?: return
        File(home, "cert.gpg").writeBytes(cert)
        gpg(home, "--import", File(home, "cert.gpg").path)
        File(home, "doc.txt").writeBytes(data)
        File(home, "doc.txt.asc").writeBytes(asc)
        val out = gpg(home, "--verify", File(home, "doc.txt.asc").path, File(home, "doc.txt").path)
        assertTrue("Good signature" in out || "完好的簽章" in out || "good signature" in out.lowercase(), out)
    }

    private suspend fun gpgEncryptAndCardDecrypt(sim: OpenPgpCardSim) {
        val home = gpgHome() ?: return
        File(home, "cert.gpg").writeBytes(sim.certificate.getEncoded(true))
        gpg(home, "--import", File(home, "cert.gpg").path)
        File(home, "doc.txt").writeBytes(content)
        gpg(home, "--encrypt", "--recipient", OpenPgp.hex(sim.sigFingerprint), "--output", File(home, "doc.txt.gpg").path, File(home, "doc.txt").path)
        val message = File(home, "doc.txt.gpg").readBytes()
        val (_, session) = OpenPgpCards.sessionKey(sim.reader(), "tap", sim.pin, message)
        assertContentEquals(content, OpenPgp.decrypt(message, session.first, session.second).data)
    }
}

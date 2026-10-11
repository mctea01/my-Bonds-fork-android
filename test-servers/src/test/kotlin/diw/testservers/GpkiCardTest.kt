package diw.testservers

import diw.wallet.core.document.Check
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.DocumentInspector
import diw.wallet.core.document.DocumentTrustSource
import diw.wallet.core.document.card.CardChannel
import diw.wallet.core.document.card.CardResponse
import diw.wallet.core.document.card.GpkiCard
import diw.wallet.core.document.card.GpkiCardSigner
import diw.wallet.core.document.pdf.PdfComposer
import diw.wallet.core.document.pdf.PdfSignOptions
import diw.wallet.core.document.sign.DocumentSigning
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.env.EnvironmentPolicy
import diw.wallet.core.trust.TrustDecision
import diw.wallet.core.trust.TrustRegistry
import diw.wallet.core.trust.TrustRole
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.DERUTF8String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Date
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** GPKI card commands: published key derivation vectors and both card generations against simulated cards. */
class GpkiCardTest {
    private fun hex(s: String) = DocCryptoUtil.unhex(s)

    @Test
    fun keyDiversificationAndSecureMessagingVectors() {
        val (enc, mac) = GpkiCard.diversify(hex("24056964130001903957"))
        assertContentEquals(hex("ab9c3c083fe63f483757da8e4feaf1bb"), enc)
        assertContentEquals(hex("32762e9842309b5a3ac37cc34f207759"), mac)
        val pin = "000000".toByteArray() + ByteArray(4) { 0xFF.toByte() }
        val body = GpkiCard.wrapForTest(enc, mac, hex("D405EC4CDC43CF8D"), hex("0361BB15A8B68C2E"), pin)
        assertContentEquals(hex("C5B3BE9F583A7EEDC0A311124389A497E6EB3952A40BC30D"), body)
    }

    private val key: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val certificate: ByteArray = JcaX509v3CertificateBuilder(
        X500Name("CN=MOICA Test"), BigInteger.TEN, Date(System.currentTimeMillis() - 86_400_000), Date(System.currentTimeMillis() + 86_400_000L * 30),
        X500Name("CN=測試者,SERIALNUMBER=0000000000000000"), key.public,
    ).build(JcaContentSignerBuilder("SHA256withRSA").build(key.private)).encoded

    private fun seq(vararg e: org.bouncycastle.asn1.ASN1Encodable) = DERSequence(ASN1EncodableVector().apply { e.forEach { add(it) } })

    /** PKCS#15 files under DF 5030: PrKDF (4100), CDF (4104), the certificate (4301) and the key file (0810). */
    private val files: Map<Int, ByteArray> = mapOf(
        0x4100 to seq(
            seq(DERUTF8String("SIGN"), DERBitString(byteArrayOf(0x80.toByte()))),
            seq(DEROctetString("SIGN".toByteArray()), DERBitString(byteArrayOf(0x20, 0x40)), ASN1Integer(0x02)),
            DERTaggedObject(true, 1, seq(seq(seq(DEROctetString(hex("0810"))), ASN1Integer(2048)))),
        ).encoded + seq(
            seq(DERUTF8String("KEYX")),
            seq(DEROctetString("KEYX".toByteArray()), DERBitString(byteArrayOf(0x40)), ASN1Integer(0x01)),
            DERTaggedObject(true, 1, seq(seq(seq(DEROctetString(hex("0810"))), ASN1Integer(2048)))),
        ).encoded + ByteArray(40),
        0x4104 to seq(
            seq(DERUTF8String("SIGN cert")),
            seq(DEROctetString("SIGN".toByteArray())),
            DERTaggedObject(true, 1, seq(seq(seq(DEROctetString(hex("3F0050304301")))))),
        ).encoded + ByteArray(1) { 0xFF.toByte() } + ByteArray(30),
        0x4301 to certificate + ByteArray(64),
        0x0810 to ByteArray(4),
    )

    private fun rsaRaw(block: ByteArray): ByteArray = Cipher.getInstance("RSA/ECB/NoPadding").run { init(Cipher.DECRYPT_MODE, key.private); doFinal(block) }

    private fun ok(data: ByteArray = ByteArray(0)) = CardResponse(0x9000, data)
    private fun sw(v: Int) = CardResponse(v, ByteArray(0))

    /** Common card state: selected file, PIN, and the RSA block being sent in two halves. */
    private abstract inner class SimCard(val pin: String) : CardChannel {
        var tries = 3
        var verified = false
        var current = 0
        var block = ByteArray(0)
        var result = ByteArray(0)

        fun select(fid: Int): CardResponse = when {
            fid == 0x3F00 || fid == 0x5030 || fid in files -> { current = fid; ok() }
            else -> sw(0x6A82)
        }

        fun read(offset: Int, le: Int): CardResponse {
            val f = files[current] ?: return sw(0x6986)
            if (offset >= f.size) return sw(0x6B00)
            return ok(f.copyOfRange(offset, minOf(f.size, offset + le)))
        }

        fun checkPin(pin10: ByteArray): CardResponse {
            if (tries == 0) return sw(0x6983)
            val expected = pin.toByteArray() + ByteArray(10 - pin.length) { 0xFF.toByte() }
            return if (pin10.contentEquals(expected)) { tries = 3; verified = true; ok() } else { tries--; verified = false; sw(0x63C0 or tries) }
        }

        fun signPart(p1: Int, data: ByteArray): CardResponse {
            if (!verified) return sw(0x6982)
            if (current != 0x0810) return sw(0x6985)
            block = if (p1 == 0x82) data else block + data
            if (p1 == 0x02) { result = rsaRaw(block); return ok(result.copyOfRange(0, 128)) }
            return ok()
        }
    }

    /** Second generation: GPPKI applet, SCP03 with diversified keys. */
    private inner class Gen2Card(pin: String) : SimCard(pin) {
        val cardId = hex("24056964130001903957")
        val keys = GpkiCard.diversify(cardId)
        var sEnc = ByteArray(0); var sMac = ByteArray(0); var mcv = ByteArray(16); var counter = 1
        var context = ByteArray(0)
        var app = "GPPKI"

        private fun cbc(encrypt: Boolean, k: ByteArray, iv: ByteArray, d: ByteArray) = Cipher.getInstance("AES/CBC/NoPadding").run {
            init(if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), IvParameterSpec(iv)); doFinal(d)
        }

        override suspend fun transmit(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): CardResponse {
            if (cla and 0x04 != 0 && ins != 0x82) return secure(cla and 0x04.inv(), ins, p1, p2, data)
            return when {
                ins == 0xA4 && p1 == 0x04 -> when {
                    data.contentEquals(GpkiCard.GPPKI_AID) -> { app = "GPPKI"; current = 0x3F00; ok() }
                    data.contentEquals(GpkiCard.ISD_CM_AID) -> { app = "CM"; ok() }
                    data.contentEquals(GpkiCard.ISD_AID) -> { app = "ISD"; ok() }
                    else -> sw(0x6A82)
                }
                ins == 0xA4 && p1 == 0x00 -> select(((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF))
                ins == 0xB0 -> read(((p1 and 0x7F) shl 8) or p2, le)
                ins == 0xCA && p2 == 0xE0 && app == "CM" -> ok(hex("E01AC00401FF8010"))
                ins == 0xCA && p2 == 0x45 && app == "ISD" -> ok(hex("450A") + cardId)
                ins == 0x50 -> {
                    val challenge = hex("0361BB15A8B68C2E")
                    context = data + challenge
                    sMac = GpkiCard.kdf(keys.second, 0x06, context, 128)
                    sEnc = GpkiCard.kdf(keys.first, 0x04, context, 128)
                    val cryptogram = GpkiCard.kdf(sMac, 0x00, context, 64)
                    ok(cardId + byteArrayOf(0x30, 0x03, 0x70) + challenge + cryptogram)
                }
                ins == 0x82 -> {
                    val host = GpkiCard.kdf(sMac, 0x01, context, 64)
                    val header = byteArrayOf(0x84.toByte(), 0x82.toByte(), 0x03, 0x00, 0x10)
                    val mac = DocCryptoUtil.aesCmac(sMac, ByteArray(16) + header + data.copyOf(8))
                    if (!data.copyOf(8).contentEquals(host) || !data.copyOfRange(8, 16).contentEquals(mac.copyOf(8))) return sw(0x6300)
                    mcv = mac; counter = 1
                    ok()
                }
                else -> sw(0x6D00)
            }
        }

        private fun secure(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray): CardResponse {
            val cipher = data.copyOf(data.size - 8)
            val header = byteArrayOf((cla or 0x04).toByte(), ins.toByte(), p1.toByte(), p2.toByte(), data.size.toByte())
            val mac = DocCryptoUtil.aesCmac(sMac, mcv + header + cipher)
            if (!mac.copyOf(8).contentEquals(data.copyOfRange(data.size - 8, data.size))) return sw(0x6988)
            mcv = mac
            val plain = if (cipher.isEmpty()) cipher else {
                val iv = Cipher.getInstance("AES/ECB/NoPadding").run { init(Cipher.ENCRYPT_MODE, SecretKeySpec(sEnc, "AES")); doFinal(ByteArray(12) + byteArrayOf(0, 0, 0, counter.toByte())) }
                counter++
                val p = cbc(false, sEnc, iv, cipher)
                p.copyOf(p.indexOfLast { it == 0x80.toByte() })
            }
            return when (ins) {
                0x20 -> checkPin(plain)
                0xA4 -> select(((plain[0].toInt() and 0xFF) shl 8) or (plain[1].toInt() and 0xFF))
                0xEA -> signPart(p1, plain)
                0xC1 -> ok(result.copyOfRange(128, 256))
                else -> sw(0x6D00)
            }
        }
    }

    /** First generation: CLA 80, PIN block under a fixed triple-DES key. */
    private inner class Gen1Card(pin: String) : SimCard(pin) {
        override suspend fun transmit(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, le: Int): CardResponse = when {
            ins == 0xA4 && p1 == 0x04 -> sw(0x6A82)
            ins == 0xA4 && cla == 0x80 -> select(((data[0].toInt() and 0xFF) shl 8) or (data[1].toInt() and 0xFF))
            ins == 0xB0 -> read(((p1 and 0x7F) shl 8) or p2, le)
            ins == 0x20 && cla == 0x8C -> {
                val iv = data.copyOf(8)
                val dec = Cipher.getInstance("DESede/CBC/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, SecretKeySpec(hex("434854544c3866304869436172645632434854544c386630"), "DESede"), IvParameterSpec(iv)); doFinal(data.copyOfRange(8, data.size))
                }
                val pin10 = dec.copyOf(10)
                if (!GpkiCard.gen1PinBlock(pin10, iv).contentEquals(data.copyOfRange(8, data.size))) sw(0x6988) else checkPin(pin10)
            }
            ins == 0xEA -> signPart(p1, data)
            ins == 0xC1 -> { val off = (p1 shl 8) or p2; ok(result.copyOfRange(off, minOf(256, off + le))) }
            else -> sw(0x6D00)
        }
    }

    private val trust = object : DocumentTrustSource {
        val registry = TrustRegistry(EphemeralStorage(), EnvironmentPolicy())
        override suspend fun decide(role: TrustRole, chain: List<X509Cert>, at: kotlin.time.Instant): TrustDecision = registry.decide(role, chain, at)
        override suspend fun fetchIssuerCertificates(url: String): List<ByteArray> = emptyList()
    }

    private suspend fun signWith(card: SimCard, pin: String, generation: GpkiCard.Generation) {
        val gpki = GpkiCard(card)
        assertEquals(generation, gpki.connect())
        val k = gpki.signingKey()
        assertContentEquals(certificate, k.certificate)
        assertEquals(2, k.keyRef)
        val pdf = PdfComposer.compose("卡片簽章測試", listOf(PdfComposer.Block.Paragraph("自然人憑證卡簽章")))
        val signed = DocumentSigning.signPdf(pdf, GpkiCardSigner(gpki, k, pin), PdfSignOptions(), null)
        val r = DocumentInspector.inspect(signed, "card.pdf", trust)
        assertEquals(Check.PASS, r.signatures.single().integrity, r.signatures.single().problems.toString())
        assertEquals("測試者", r.signatures.single().signerName)
    }

    @Test
    fun secondGenerationCardSigns() = runBlocking<Unit> {
        signWith(Gen2Card("123456"), "123456", GpkiCard.Generation.GEN2)
    }

    @Test
    fun firstGenerationCardSigns() = runBlocking<Unit> {
        signWith(Gen1Card("12345678"), "12345678", GpkiCard.Generation.GEN1)
    }

    @Test
    fun wrongPinStopsWithRemainingTries() = runBlocking<Unit> {
        for (card in listOf(Gen2Card("123456"), Gen1Card("123456"))) {
            val gpki = GpkiCard(card)
            gpki.connect()
            val k = gpki.signingKey()
            val e = runCatching { gpki.signSha256("654321", k.keyRef, ByteArray(32)) }.exceptionOrNull()
            assertTrue(e is SigningException && "還可以再試 2 次" in e.message!!, e.toString())
            assertEquals(2, card.tries)
        }
    }
}

package diw.wallet.core.document.card

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.sign.SigningException

/** The three keys of an OpenPGP card: control reference template, algorithm attribute tag, 7F21 occurrence, PIN. */
enum class OpenPgpKeySlot(val crt: Int, val attributeTag: Int, val certificateOccurrence: Int, val pinReference: Int, val title: String) {
    SIGNATURE(0xB6, 0xC1, 2, 0x81, "簽章金鑰"),
    DECRYPTION(0xB8, 0xC2, 1, 0x82, "解密金鑰"),
    AUTHENTICATION(0xA4, 0xC3, 0, 0x82, "認證金鑰"),
}

/** Elliptic curves an OpenPGP card names by OID in its algorithm attributes (RFC 6637, RFC 9580). */
enum class OpenPgpCurve(val oidHex: String, val title: String, val size: Int, val hash: String) {
    P256("2A8648CE3D030107", "NIST P-256", 32, "SHA-256"),
    P384("2B81040022", "NIST P-384", 48, "SHA-384"),
    P521("2B81040023", "NIST P-521", 66, "SHA-512"),
    BRAINPOOL_P256("2B2403030208010107", "brainpoolP256r1", 32, "SHA-256"),
    BRAINPOOL_P384("2B240303020801010B", "brainpoolP384r1", 48, "SHA-384"),
    BRAINPOOL_P512("2B240303020801010D", "brainpoolP512r1", 64, "SHA-512"),
    ED25519("2B06010401DA470F01", "Ed25519", 32, "SHA-256"),
    CURVE25519("2B060104019755010501", "Curve25519", 32, "SHA-256"),
    ;

    val oid: ByteArray get() = DocCryptoUtil.unhex(oidHex)

    /** Montgomery or Edwards curves keep native 32-byte keys; OpenPGP v4 writes them with a 0x40 prefix. */
    val native: Boolean get() = this == ED25519 || this == CURVE25519

    companion object {
        fun of(oid: ByteArray): OpenPgpCurve? = entries.firstOrNull { it.oid.contentEquals(oid) }
    }
}

/** A key's algorithm from its attribute DO (C1, C2, C3). [pgpId] is the OpenPGP public-key algorithm number. */
sealed class OpenPgpAlgorithm(val pgpId: Int) {
    class Rsa(val modulusBits: Int) : OpenPgpAlgorithm(1) {
        override fun toString() = "RSA $modulusBits"
    }

    /** ECDH (18), ECDSA (19) or EdDSA (22) on [curve]. */
    class Ec(pgpId: Int, val curve: OpenPgpCurve) : OpenPgpAlgorithm(pgpId) {
        override fun toString() = when (pgpId) {
            18 -> "ECDH " + curve.title
            22 -> "EdDSA " + curve.title
            else -> "ECDSA " + curve.title
        }
    }

    class Unsupported(val raw: ByteArray) : OpenPgpAlgorithm(raw.firstOrNull()?.toInt()?.and(0xFF) ?: 0) {
        override fun toString() = "不支援的演算法（" + DocCryptoUtil.hex(raw).uppercase() + "）"
    }

    companion object {
        fun parse(attributes: ByteArray): OpenPgpAlgorithm {
            if (attributes.isEmpty()) return Unsupported(attributes)
            val id = attributes[0].toInt() and 0xFF
            if (id == 1 && attributes.size >= 3) return Rsa(((attributes[1].toInt() and 0xFF) shl 8) or (attributes[2].toInt() and 0xFF))
            if (id in setOf(18, 19, 22)) {
                // The OID follows the algorithm byte; a trailing import-format byte (FF) may come after it.
                val rest = attributes.copyOfRange(1, attributes.size)
                val curve = OpenPgpCurve.entries.firstOrNull { c ->
                    rest.size >= c.oid.size && rest.copyOf(c.oid.size).contentEquals(c.oid) && (rest.size == c.oid.size || rest.size == c.oid.size + 1)
                } ?: return Unsupported(attributes)
                return Ec(id, curve)
            }
            return Unsupported(attributes)
        }
    }
}

/** The public part of a card key: an RSA modulus and exponent, or an EC point (native 32 bytes for 25519 curves). */
sealed class OpenPgpPublicMaterial {
    class Rsa(val modulus: ByteArray, val exponent: ByteArray) : OpenPgpPublicMaterial()
    class Ec(val point: ByteArray) : OpenPgpPublicMaterial()
}

/**
 * One key on the card. [fingerprint] and [created] are what the card stores (C5, CD); null when the slot is empty.
 * [packet] is the OpenPGP v4 public key packet body whose fingerprint matched [fingerprint] (see
 * [diw.wallet.core.document.pgp.OpenPgpPackets.matchCardKey]); null when none matched.
 */
class OpenPgpCardKey(
    val slot: OpenPgpKeySlot,
    val algorithm: OpenPgpAlgorithm,
    val fingerprint: ByteArray?,
    val created: Long,
    val publicKey: OpenPgpPublicMaterial?,
    val certificate: ByteArray?,
    val packet: ByteArray? = null,
) {
    val present: Boolean get() = publicKey != null

    fun withPacket(body: ByteArray?) = OpenPgpCardKey(slot, algorithm, fingerprint, created, publicKey, certificate, body)

    /** The fingerprint as GnuPG prints it: upper-case hex in groups of four. */
    val fingerprintText: String? get() = fingerprint?.let { OpenPgpCard.groupHex(it) }
}

/** PIN state (C4): whether one VERIFY covers several signatures, maximum lengths and remaining tries. */
class OpenPgpPinStatus(val pw1ValidForSeveral: Boolean, val pw1MaxLength: Int, val pw1Tries: Int, val resetTries: Int, val adminTries: Int)

/** The card's iterated-salted S2K for PINs (KDF-DO F9, OpenPGP card 3.3). */
class OpenPgpKdf(val hash: String, val iterations: Int, val salt: ByteArray)

/** Everything the wallet reads from an OpenPGP card without the PIN. */
class OpenPgpCardInfo(
    val aid: ByteArray,
    val version: String,
    val manufacturer: Int,
    val serial: String,
    val cardholder: String?,
    val url: String?,
    val signatureCount: Int?,
    val pinStatus: OpenPgpPinStatus?,
    val keys: List<OpenPgpCardKey>,
    val kdf: OpenPgpKdf?,
) {
    val manufacturerName: String get() = OpenPgpCard.manufacturerName(manufacturer)

    /** A label for lists and trust: "OpenPGP 卡 Yubico 12345678". */
    val label: String get() = "OpenPGP 卡 $manufacturerName $serial"

    fun key(slot: OpenPgpKeySlot): OpenPgpCardKey? = keys.firstOrNull { it.slot == slot && it.present }

    fun withKeys(list: List<OpenPgpCardKey>) = OpenPgpCardInfo(aid, version, manufacturer, serial, cardholder, url, signatureCount, pinStatus, list, kdf)
}

/**
 * An OpenPGP card (OpenPGP application on ISO smart cards, version 2.0 to 3.4.1): YubiKey, Nitrokey, Gnuk,
 * SmartPGP and the ZeitControl or FLOSS cards, over phone NFC, USB CCID or PC/SC. This is an independent
 * implementation of the published command set, not a vendor library: it reads the card's data objects and public
 * keys without the PIN, verifies PW1 right before each private-key operation (the PIN is never kept), signs with
 * PSO:COMPUTE DIGITAL SIGNATURE and decrypts with PSO:DECIPHER.
 */
class OpenPgpCard(private val channel: CardChannel) {
    private var info: OpenPgpCardInfo? = null

    /** Selects the OpenPGP application. */
    suspend fun connect() {
        val r = channel.transmit(0x00, 0xA4, 0x04, 0x00, AID_PREFIX, 0)
        if (!r.ok && !r.warning) throw SigningException("這張卡片不是 OpenPGP 卡（找不到 OpenPGP 應用程式）")
    }

    /** Reads the card's identity, PIN state, keys, fingerprints, generation times and cardholder certificates. */
    suspend fun readInfo(): OpenPgpCardInfo {
        val app = getData(0x6E) ?: throw SigningException("無法讀取 OpenPGP 卡的應用程式資料")
        val tlvs = Tlv.parse(app)
        val aid = Tlv.find(tlvs, 0x4F)?.value ?: throw SigningException("OpenPGP 卡沒有回傳 AID")
        if (aid.size < 14) throw SigningException("OpenPGP 卡的 AID 格式不正確")
        val major = aid[6].toInt() and 0xFF
        val minor = aid[7].toInt() and 0xFF
        val manufacturer = ((aid[8].toInt() and 0xFF) shl 8) or (aid[9].toInt() and 0xFF)
        val serial = DocCryptoUtil.hex(aid.copyOfRange(10, 14)).uppercase()
        val caps = Tlv.find(tlvs, 0xC0)?.value
        val fingerprints = Tlv.find(tlvs, 0xC5)?.value ?: ByteArray(0)
        val times = Tlv.find(tlvs, 0xCD)?.value ?: ByteArray(0)
        val pin = Tlv.find(tlvs, 0xC4)?.value?.takeIf { it.size >= 7 }?.let {
            OpenPgpPinStatus(it[0].toInt() != 0, it[1].toInt() and 0xFF, it[4].toInt() and 0xFF, it[5].toInt() and 0xFF, it[6].toInt() and 0xFF)
        }
        val cardholder = runCatching { getData(0x65) }.getOrNull()?.let { Tlv.find(Tlv.parse(it), 0x5B)?.value }?.let { cardholderName(it) }
        val url = runCatching { getData(0x5F50) }.getOrNull()?.takeIf { it.isNotEmpty() }?.decodeToString()?.trim()?.ifEmpty { null }
        val counter = runCatching { getData(0x7A) }.getOrNull()?.let { Tlv.find(Tlv.parse(it), 0x93)?.value }?.fold(0) { a, b -> (a shl 8) or (b.toInt() and 0xFF) }
        val kdfSupported = caps != null && caps.isNotEmpty() && (caps[0].toInt() and 0x01) != 0
        val kdf = if (kdfSupported) runCatching { getData(0xF9) }.getOrNull()?.let { parseKdf(it) } else null
        val keys = OpenPgpKeySlot.entries.mapIndexed { i, slot ->
            val algorithm = OpenPgpAlgorithm.parse(Tlv.find(tlvs, slot.attributeTag)?.value ?: ByteArray(0))
            val fpr = fingerprints.takeIf { it.size >= (i + 1) * 20 }?.copyOfRange(i * 20, (i + 1) * 20)?.takeIf { f -> f.any { it != 0.toByte() } }
            val created = times.takeIf { it.size >= (i + 1) * 4 }?.copyOfRange(i * 4, (i + 1) * 4)
                ?.fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xFF) } ?: 0L
            val material = runCatching { readPublicKey(slot) }.getOrNull()
            val certificate = runCatching { readCertificate(slot, major) }.getOrNull()
            OpenPgpCardKey(slot, algorithm, fpr, created, material, certificate)
        }
        return OpenPgpCardInfo(aid, "$major.$minor", manufacturer, serial, cardholder, url, counter, pin, keys, kdf).also { info = it }
    }

    /** GET DATA for a simple or constructed DO; null when the card does not hold it. */
    private suspend fun getData(tag: Int): ByteArray? {
        val r = channel.transmit(0x00, 0xCA, (tag shr 8) and 0xFF, tag and 0xFF, ByteArray(0), 256)
        return if (r.ok) r.data else null
    }

    /** The public key of [slot] (GENERATE ASYMMETRIC KEY PAIR, P1=81: read only); null when the slot is empty. */
    private suspend fun readPublicKey(slot: OpenPgpKeySlot): OpenPgpPublicMaterial? {
        val r = channel.transmit(0x00, 0x47, 0x81, 0x00, byteArrayOf(slot.crt.toByte(), 0x00), 256)
        if (!r.ok) return null
        val top = Tlv.find(Tlv.parse(r.data), 0x7F49) ?: return null
        val inner = Tlv.parse(top.value)
        val modulus = Tlv.find(inner, 0x81)?.value
        val exponent = Tlv.find(inner, 0x82)?.value
        if (modulus != null && exponent != null && modulus.isNotEmpty()) return OpenPgpPublicMaterial.Rsa(modulus, exponent)
        val point = Tlv.find(inner, 0x86)?.value ?: return null
        return if (point.isEmpty()) null else OpenPgpPublicMaterial.Ec(point)
    }

    /**
     * The cardholder certificate (7F21) of [slot]. From version 3.0 the card holds one per key, chosen with SELECT
     * DATA; some YubiKey firmware wants the data field without the 60 wrapper, so both forms are tried. Version 2
     * cards hold only the authentication key's certificate.
     */
    private suspend fun readCertificate(slot: OpenPgpKeySlot, major: Int): ByteArray? {
        if (major < 3) return if (slot == OpenPgpKeySlot.AUTHENTICATION) getData(0x7F21)?.let { certificateDer(it) } else null
        val forms = listOf(DocCryptoUtil.unhex("60045C027F21"), DocCryptoUtil.unhex("5C027F21"))
        for (form in forms) {
            val r = channel.transmit(0x00, 0xA5, slot.certificateOccurrence, 0x04, form, 0)
            if (!r.ok) continue
            return getData(0x7F21)?.let { certificateDer(it) }
        }
        return null
    }

    /** PIN parameters and key fingerprints read in this session without the full [readInfo]. */
    private class Session(val pinStatus: OpenPgpPinStatus?, val kdf: OpenPgpKdf?, val fingerprints: ByteArray)

    private var session: Session? = null

    /** Reads the PIN state, KDF-DO and fingerprints once per session (cheap: 6E and F9 only). */
    private suspend fun session(): Session {
        session?.let { return it }
        info?.let { i -> return Session(i.pinStatus, i.kdf, i.keys.fold(ByteArray(0)) { a, k -> a + (k.fingerprint ?: ByteArray(20)) }).also { session = it } }
        val tlvs = Tlv.parse(getData(0x6E) ?: throw SigningException("無法讀取 OpenPGP 卡的應用程式資料"))
        val pin = Tlv.find(tlvs, 0xC4)?.value?.takeIf { it.size >= 7 }?.let {
            OpenPgpPinStatus(it[0].toInt() != 0, it[1].toInt() and 0xFF, it[4].toInt() and 0xFF, it[5].toInt() and 0xFF, it[6].toInt() and 0xFF)
        }
        val caps = Tlv.find(tlvs, 0xC0)?.value
        val kdf = if (caps != null && caps.isNotEmpty() && (caps[0].toInt() and 0x01) != 0) runCatching { getData(0xF9) }.getOrNull()?.let { parseKdf(it) } else null
        return Session(pin, kdf, Tlv.find(tlvs, 0xC5)?.value ?: ByteArray(0)).also { session = it }
    }

    /** The fingerprint the card stores for [slot] now; null when the slot is empty. */
    suspend fun fingerprint(slot: OpenPgpKeySlot): ByteArray? {
        val all = session().fingerprints
        val i = slot.ordinal
        return all.takeIf { it.size >= (i + 1) * 20 }?.copyOfRange(i * 20, (i + 1) * 20)?.takeIf { f -> f.any { it != 0.toByte() } }
    }

    /** VERIFY PW1 with [reference] 81 (signing) or 82 (decryption); a wrong PIN stops with the remaining tries. */
    private suspend fun verifyPin(pin: String, reference: Int) {
        val s = session()
        val max = s.pinStatus?.pw1MaxLength?.takeIf { it > 0 } ?: PIN_MAX
        val bytes = pin.encodeToByteArray()
        if (bytes.size < PIN_MIN || bytes.size > max) throw SigningException("PIN 碼長度不正確（應為 $PIN_MIN 至 $max 個字元）")
        if (s.pinStatus?.pw1Tries == 0) throw SigningException("PIN 碼已鎖定，請在電腦上以重設碼或管理 PIN 解鎖（例如 gpg --card-edit）")
        val sent = s.kdf?.let { s2k(it, bytes) } ?: bytes
        val r = channel.transmit(0x00, 0x20, 0x00, reference, sent, 0)
        when {
            r.ok -> {}
            r.sw == 0x6983 -> throw SigningException("PIN 碼已鎖定，請在電腦上以重設碼或管理 PIN 解鎖（例如 gpg --card-edit）")
            r.sw and 0xFFF0 == 0x63C0 -> {
                val left = r.sw and 0x0F
                throw SigningException(if (left == 0) "PIN 碼錯誤，卡片已鎖定" else "PIN 碼錯誤，還可以再試 $left 次。為避免鎖卡，已停止。")
            }
            r.sw == 0x6982 -> throw SigningException("PIN 碼錯誤（卡片未說明剩餘次數）。為避免鎖卡，已停止。")
            else -> throw SigningException("OpenPGP 卡拒絕 PIN 驗證（${PivCard.hex4(r.sw)}）")
        }
    }

    /**
     * PSO:COMPUTE DIGITAL SIGNATURE with the signature key after VERIFY PW1 (81). [input] is a DigestInfo for RSA (the
     * card pads it) and the hash for ECDSA and EdDSA. Returns the raw RSA signature or r||s.
     */
    suspend fun sign(pin: String, input: ByteArray): ByteArray {
        verifyPin(pin, OpenPgpKeySlot.SIGNATURE.pinReference)
        val r = transmitChained(0x2A, 0x9E, 0x9A, input)
        if (!r.ok) throw SigningException(when (r.sw) {
            0x6982 -> "OpenPGP 卡要求重新輸入 PIN 碼"
            0x6A88, 0x6A80 -> "OpenPGP 卡上沒有可用的簽章金鑰"
            else -> "OpenPGP 卡拒絕簽章（${PivCard.hex4(r.sw)}）"
        })
        return r.data
    }

    /**
     * PSO:DECIPHER with the decryption key after VERIFY PW1 (82). For RSA [input] is the ciphertext (left padded to
     * the modulus length) and the card returns the unpadded session data; for ECDH it is the ephemeral public point
     * and the card returns the shared secret.
     */
    suspend fun decipher(pin: String, key: OpenPgpCardKey, input: ByteArray): ByteArray {
        verifyPin(pin, OpenPgpKeySlot.DECRYPTION.pinReference)
        val data = when (val alg = key.algorithm) {
            is OpenPgpAlgorithm.Rsa -> byteArrayOf(0x00) + input
            is OpenPgpAlgorithm.Ec -> berTlv(0xA6, berTlv(0x7F49, berTlv(0x86, input)))
            is OpenPgpAlgorithm.Unsupported -> throw SigningException("OpenPGP 卡的解密金鑰演算法不支援：$alg")
        }
        val r = transmitChained(0x2A, 0x80, 0x86, data)
        if (!r.ok) throw SigningException(when (r.sw) {
            0x6982 -> "OpenPGP 卡要求重新輸入 PIN 碼"
            0x6A80 -> "OpenPGP 卡無法解開這份資料（不是寄給這張卡，或資料損毀）"
            0x6A88 -> "OpenPGP 卡上沒有解密金鑰"
            else -> "OpenPGP 卡拒絕解密（${PivCard.hex4(r.sw)}）"
        })
        return r.data
    }

    /** A command with [data] longer than one short APDU, sent with command chaining (CLA 10). */
    private suspend fun transmitChained(ins: Int, p1: Int, p2: Int, data: ByteArray): CardResponse {
        if (data.size <= 255) return channel.transmit(0x00, ins, p1, p2, data, 256)
        var off = 0
        while (true) {
            val end = minOf(off + 255, data.size)
            val last = end == data.size
            val r = channel.transmit(if (last) 0x00 else 0x10, ins, p1, p2, data.copyOfRange(off, end), if (last) 256 else 0)
            if (last || (!r.ok && !r.warning)) return r
            off = end
        }
    }

    companion object {
        /** PW1 is at least six characters (OpenPGP card 3.4.1, 4.3); the card states its maximum in C4. */
        const val PIN_MIN = 6
        const val PIN_MAX = 127

        /** RID D2 76 00 01 24 and application 01: selects any version and serial. */
        val AID_PREFIX = DocCryptoUtil.unhex("D27600012401")

        fun groupHex(b: ByteArray): String = DocCryptoUtil.hex(b).uppercase().chunked(4).joinToString(" ")

        /** "Doe<<John" to "John Doe" (ISO/IEC 7501-1 name with < fillers). */
        fun cardholderName(raw: ByteArray): String? {
            val s = raw.decodeToString().trim().ifEmpty { return null }
            if ("<<" !in s) return s.replace('<', ' ').trim()
            val surname = s.substringBefore("<<").replace('<', ' ').trim()
            val given = s.substringAfter("<<").replace('<', ' ').trim()
            return listOf(given, surname).filter { it.isNotEmpty() }.joinToString(" ").ifEmpty { null }
        }

        /** The DER certificate in a 7F21 response (the response is the certificate itself, or 7F21 wrapping it). */
        private fun certificateDer(data: ByteArray): ByteArray? {
            if (data.isEmpty()) return null
            val inner = Tlv.parse(data).firstOrNull()?.takeIf { it.tag == 0x7F21 }?.value ?: data
            return inner.takeIf { it.size > 16 && it[0] == 0x30.toByte() }
        }

        private fun parseKdf(data: ByteArray): OpenPgpKdf? {
            val tlvs = Tlv.parse(data)
            if ((Tlv.find(tlvs, 0x81)?.value?.firstOrNull()?.toInt() ?: 0) != 3) return null
            val hash = when (Tlv.find(tlvs, 0x82)?.value?.firstOrNull()?.toInt()) {
                0x08 -> "SHA-256"
                0x0A -> "SHA-512"
                else -> return null
            }
            val count = Tlv.find(tlvs, 0x83)?.value?.fold(0) { a, b -> (a shl 8) or (b.toInt() and 0xFF) } ?: return null
            val salt = Tlv.find(tlvs, 0x84)?.value ?: return null
            return OpenPgpKdf(hash, count, salt)
        }

        /** OpenPGP iterated and salted S2K (RFC 4880 3.7.1.3) of [pin] as the KDF-DO asks. */
        fun s2k(kdf: OpenPgpKdf, pin: ByteArray): ByteArray {
            val unit = kdf.salt + pin
            val total = maxOf(kdf.iterations, unit.size)
            val buffer = ByteArray(total)
            var off = 0
            while (off < total) {
                val n = minOf(unit.size, total - off)
                unit.copyInto(buffer, off, 0, n)
                off += n
            }
            return DocCrypto.digest(kdf.hash, buffer)
        }

        /** A BER-TLV element with a one- or two-byte tag. */
        fun berTlv(tag: Int, value: ByteArray): ByteArray {
            val t = if (tag > 0xFF) byteArrayOf((tag shr 8).toByte(), tag.toByte()) else byteArrayOf(tag.toByte())
            val n = value.size
            val len = when {
                n < 0x80 -> byteArrayOf(n.toByte())
                n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
                else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
            }
            return t + len + value
        }

        /** Manufacturer names from the OpenPGP card registry kept by GnuPG. */
        fun manufacturerName(id: Int): String = when (id) {
            0x0001 -> "PPC Card Systems"
            0x0002 -> "Prism"
            0x0003 -> "OpenFortress"
            0x0004 -> "Wewid"
            0x0005 -> "ZeitControl"
            0x0006 -> "Yubico"
            0x0007 -> "OpenKMS"
            0x0008 -> "LogoEmail"
            0x0009 -> "Fidesmo"
            0x000A -> "VivoKey"
            0x000B -> "Feitian"
            0x000D -> "Dangerous Things"
            0x000E -> "Excelsecu"
            0x000F -> "Nitrokey"
            0x002A -> "Magrathea"
            0x0042 -> "GnuPG e.V."
            0x1337 -> "Warsaw Hackerspace"
            0x2342 -> "warpzone"
            0x4354 -> "Confidential Technologies"
            0x5443 -> "TIF-IT"
            0x63AF -> "Trustica"
            0xBA53 -> "c-base"
            0xBD0E -> "Paranoidlabs"
            0xF1D0 -> "CanoKeys"
            0xF517 -> "FSIJ（Gnuk）"
            0xF5EC -> "F-Secure"
            0x0000, 0xFFFF -> "測試卡"
            in 0xFF00..0xFFFE -> "測試卡"
            else -> "廠商 " + id.toString(16).uppercase().padStart(4, '0')
        }
    }
}

/** BER-TLV with multi-byte tags (ISO/IEC 7816-4), as OpenPGP cards use for 5F50, 7F21, 7F49 and the like. */
internal class Tlv(val tag: Int, val value: ByteArray) {
    val constructed: Boolean get() = ((if (tag > 0xFF) tag shr 8 else tag) and 0x20) != 0

    companion object {
        fun parse(b: ByteArray): List<Tlv> {
            val out = ArrayList<Tlv>()
            var p = 0
            while (p < b.size) {
                val first = b[p].toInt() and 0xFF
                if (first == 0x00 || first == 0xFF) { p++; continue }
                var tag = first
                p++
                if (first and 0x1F == 0x1F) {
                    while (p < b.size) {
                        val next = b[p++].toInt() and 0xFF
                        tag = (tag shl 8) or next
                        if (next and 0x80 == 0) break
                    }
                }
                if (p >= b.size) break
                var len = b[p++].toInt() and 0xFF
                if (len and 0x80 != 0) {
                    val n = len and 0x7F
                    if (n == 0 || n > 3 || p + n > b.size) break
                    len = 0
                    repeat(n) { len = (len shl 8) or (b[p++].toInt() and 0xFF) }
                }
                if (p + len > b.size) break
                out.add(Tlv(tag, b.copyOfRange(p, p + len)))
                p += len
            }
            return out
        }

        /** The first element with [tag], searching inside constructed elements too. */
        fun find(list: List<Tlv>, tag: Int): Tlv? {
            for (t in list) {
                if (t.tag == tag) return t
                if (t.constructed) find(parse(t.value), tag)?.let { return it }
            }
            return null
        }
    }
}

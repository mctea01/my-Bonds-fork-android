package diw.wallet.core.document.mrtd

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.card.CardChannel
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.time.Clock

/** The outcome of a chip protocol at reading time. */
@Serializable
enum class ChipCheck { PASS, FAIL, NOT_SUPPORTED, NOT_RUN }

/** A challenge the wallet sent to the chip and the chip's Active Authentication signature over it. */
@Serializable
data class ActiveAuthenticationRecord(val challenge: String, val response: String)

/**
 * What was read from a travel document chip, stored as the wallet's file of the document: the raw LDS files as the
 * chip returned them (so passive authentication can be repeated at any time), EF.CardAccess, and what was checked
 * only while the chip was present (the access protocol and Chip Authentication). Active Authentication keeps its
 * challenge and response, so the signature can be verified again, but it only shows the chip held the key at
 * reading time.
 */
@Serializable
data class MrtdDump(
    val type: String = TYPE,
    /** LDS files by name ([LdsFile.name]), base64. */
    val files: Map<String, String>,
    val cardAccess: String? = null,
    /** "BAC" or the PACE protocol name. */
    val access: String,
    val chipAuthentication: ChipCheck = ChipCheck.NOT_RUN,
    val chipAuthenticationProtocol: String? = null,
    val activeAuthentication: ActiveAuthenticationRecord? = null,
    val activeAuthenticationResult: ChipCheck = ChipCheck.NOT_RUN,
    /** Files listed in EF.COM that could not be read (DG3 and DG4 need terminal authentication). */
    val unreadable: List<String> = emptyList(),
    val readAt: Long,
) {
    fun file(f: LdsFile): ByteArray? = files[f.name]?.let { Base64.decode(it) }

    val cardAccessBytes: ByteArray? get() = cardAccess?.let { Base64.decode(it) }

    fun encode(): ByteArray = JSON.encodeToString(serializer(), this).encodeToByteArray()

    companion object {
        const val TYPE = "urn:diw-wallet:emrtd:1"
        const val FILE_EXTENSION = "emrtd.json"

        /** Defaults are written, so the type is always the first member and [detect] finds it in the head. */
        private val JSON = Json { ignoreUnknownKeys = true; encodeDefaults = true; explicitNulls = false }

        /** A dump file: JSON whose type is [TYPE]. Only the head is read, so any file can be tested cheaply. */
        fun detect(bytes: ByteArray): Boolean {
            if (bytes.isEmpty() || bytes[0] != '{'.code.toByte()) return false
            val head = bytes.copyOfRange(0, minOf(bytes.size, 256)).decodeToString()
            return head.contains("\"type\"") && head.contains(TYPE)
        }

        fun decode(bytes: ByteArray): MrtdDump? = if (!detect(bytes)) null
            else runCatching { JSON.decodeFromString(serializer(), bytes.decodeToString()) }.getOrNull()?.takeIf { it.type == TYPE }
    }
}

/** A step of the reading, for the progress shown while the document stays on the phone. */
enum class MrtdStage { ACCESS, CHIP_AUTHENTICATION, READING, ACTIVE_AUTHENTICATION, DONE }

/**
 * Reads a travel document chip (ICAO 9303 LDS 1): PACE when EF.CardAccess offers a mapping this wallet implements,
 * BAC otherwise or when PACE fails; then EF.COM, Chip Authentication with DG14, every readable data group, the
 * security object and Active Authentication with DG15. DG3 and DG4 are listed as unreadable (they need terminal
 * authentication with a state's certificate).
 */
class MrtdReader(
    private val channel: CardChannel,
    private val secret: AccessSecret,
    private val progress: (MrtdStage, Int, Int) -> Unit = { _, _, _ -> },
    /** Bytes per READ BINARY; 0xDF keeps a protected response within a short APDU. */
    private val chunk: Int = 0xDF,
) {
    private var sm: SecureChannel? = null

    suspend fun read(): MrtdDump {
        progress(MrtdStage.ACCESS, 0, 1)
        val cardAccess = runCatching { readCardAccess() }.getOrNull()
        val paces = cardAccess?.let { SecurityInfo.parse(it) }.orEmpty().filterIsInstance<SecurityInfo.Pace>()
            .filter { it.genericMapping && it.cipher != null && it.parameterId?.let { id -> MrtdCrypto.standardDomain(id) } != null }
        var access = "BAC"
        var paceError: MrtdException? = null
        val pace = paces.maxByOrNull { (it.cipher?.ordinal ?: 0) * 100 + (if (it.oid.startsWith(MrtdOids.PACE_ECDH_GM)) 1 else 0) }
        if (pace != null) {
            try {
                sm = MrtdAccess.pace(channel, secret, pace)
                access = MrtdOids.protocolName(pace.oid)
            } catch (e: MrtdException) {
                paceError = e
            }
        }
        // PACE runs before the application is selected; BAC after.
        if (!select(sm ?: channel)) throw MrtdException("not_passport")
        if (sm == null) {
            val key = (secret as? AccessSecret.MrzSecret)?.key ?: throw (paceError ?: MrtdException("can_needs_pace"))
            try {
                sm = MrtdAccess.bac(channel, key)
            } catch (e: MrtdException) {
                // Wrong document data: report the access error, not BAC's fallback.
                if (paceError?.code == "access_denied") throw paceError
                throw e
            }
        }
        val files = LinkedHashMap<String, String>()
        val unreadable = ArrayList<String>()
        val com = readFile(LdsFile.COM) ?: throw MrtdException("no_com")
        files[LdsFile.COM.name] = Base64.encode(com)
        val listed = Lds.com(com)?.files.orEmpty()

        var ca = ChipCheck.NOT_SUPPORTED
        var caProtocol: String? = null
        if (LdsFile.DG14 in listed) {
            readFile(LdsFile.DG14)?.let { dg14 ->
                files[LdsFile.DG14.name] = Base64.encode(dg14)
                val infos = SecurityInfo.parse(dg14)
                val keys = infos.filterIsInstance<SecurityInfo.ChipAuthenticationPublicKey>()
                val cas = infos.filterIsInstance<SecurityInfo.ChipAuthentication>()
                val key = keys.firstOrNull()
                if (key != null) {
                    progress(MrtdStage.CHIP_AUTHENTICATION, 0, 1)
                    val info = cas.firstOrNull { c -> key.keyId == null || c.keyId == null || c.keyId == key.keyId }
                    val next = try {
                        MrtdAccess.chipAuthentication(sm!!, channel, key, info)
                    } catch (e: MrtdException) {
                        // A refused command leaves the current session as it was; the protocol counts as failed.
                        ca = if (e.code == "ca_unsupported") ChipCheck.NOT_SUPPORTED else ChipCheck.FAIL
                        null
                    }
                    if (next != null) {
                        caProtocol = info?.oid?.let { MrtdOids.protocolName(it) } ?: "CA-3DES"
                        sm = next
                        // The chip answers under the new keys only if it holds the private key of DG14; a chip that
                        // cannot is not the one the data were written to, and the session is over.
                        if (readHeader(LdsFile.COM) == null) throw MrtdException("ca_failed")
                        ca = ChipCheck.PASS
                    }
                }
            }
        }

        val toRead = (listOf(LdsFile.SOD) + listed.filter { it != LdsFile.COM && it != LdsFile.DG14 }).distinct()
        for ((i, f) in toRead.withIndex()) {
            progress(MrtdStage.READING, i, toRead.size)
            if (f.restricted) { unreadable.add(f.name); continue }
            val bytes = try { readFile(f) } catch (e: MrtdException) {
                if (e.code == "sm_mac" || e.code == "sm_error") throw e
                null
            }
            if (bytes == null) unreadable.add(f.name) else files[f.name] = Base64.encode(bytes)
        }
        if (LdsFile.SOD.name !in files) throw MrtdException("no_sod")

        var aa: ActiveAuthenticationRecord? = null
        var aaResult = ChipCheck.NOT_SUPPORTED
        files[LdsFile.DG15.name]?.let { dg15 ->
            progress(MrtdStage.ACTIVE_AUTHENTICATION, 0, 1)
            val challenge = DocCrypto.randomBytes(8)
            aaResult = try {
                val response = MrtdAccess.activeAuthentication(sm!!, challenge)
                aa = ActiveAuthenticationRecord(Base64.encode(challenge), Base64.encode(response))
                val spki = Lds.dg15(Base64.decode(dg15))
                val sigOid = files[LdsFile.DG14.name]?.let { SecurityInfo.parse(Base64.decode(it)) }
                    ?.filterIsInstance<SecurityInfo.ActiveAuthentication>()?.firstOrNull()?.signatureAlgorithm
                if (spki != null && MrtdCrypto.verifyActiveAuthentication(spki, challenge, response, sigOid) != null) ChipCheck.PASS else ChipCheck.FAIL
            } catch (e: MrtdException) {
                if (e.code == "sm_mac" || e.code == "sm_error") throw e
                ChipCheck.FAIL
            }
        }
        progress(MrtdStage.DONE, 1, 1)
        return MrtdDump(
            files = files,
            cardAccess = cardAccess?.let { Base64.encode(it) },
            access = access,
            chipAuthentication = ca,
            chipAuthenticationProtocol = caProtocol,
            activeAuthentication = aa,
            activeAuthenticationResult = aaResult,
            unreadable = unreadable,
            readAt = Clock.System.now().epochSeconds,
        )
    }

    /** EF.CardAccess under the master file, read by short file identifier, then by selecting it. */
    private suspend fun readCardAccess(): ByteArray? {
        val bySfi = channel.transmit(0x00, 0xB0, 0x80 or 0x1C, 0x00, ByteArray(0), 256)
        if (bySfi.sw == 0x9000 && bySfi.data.isNotEmpty()) {
            val total = BerTlv.totalLength(bySfi.data) ?: return bySfi.data
            return if (total <= bySfi.data.size) bySfi.data.copyOf(total) else bySfi.data + readRest(channel, bySfi.data.size, total)
        }
        val sel = channel.transmit(0x00, 0xA4, 0x02, 0x0C, byteArrayOf(0x01, 0x1C), 0)
        if (sel.sw != 0x9000) return null
        return readSelected(channel)
    }

    private suspend fun select(ch: CardChannel): Boolean =
        ch.transmit(0x00, 0xA4, 0x04, 0x0C, AID, 0).sw.let { it == 0x9000 || it and 0xFF00 == 0x6200 }

    private suspend fun selectFile(ch: CardChannel, fid: Int): Boolean {
        val r = ch.transmit(0x00, 0xA4, 0x02, 0x0C, byteArrayOf((fid shr 8).toByte(), fid.toByte()), 0)
        if (r.sw == 0x6A82 || r.sw == 0x6A88) return false
        if (r.sw == 0x6982) return false
        if (r.sw != 0x9000 && r.sw and 0xFF00 != 0x6200) throw MrtdException("select_failed", r.sw)
        return true
    }

    /** The first bytes of [f] under the current keys, or null when the chip does not answer them. */
    private suspend fun readHeader(f: LdsFile): ByteArray? = runCatching {
        val ch = sm ?: channel
        if (!selectFile(ch, f.fid)) null else ch.transmit(0x00, 0xB0, 0, 0, ByteArray(0), 4).takeIf { it.sw == 0x9000 }?.data
    }.getOrNull()

    private suspend fun readFile(f: LdsFile): ByteArray? {
        val ch = sm ?: channel
        if (!selectFile(ch, f.fid)) return null
        return readSelected(ch)
    }

    private suspend fun readSelected(ch: CardChannel): ByteArray? {
        val head = ch.transmit(0x00, 0xB0, 0, 0, ByteArray(0), 8)
        if (head.sw == 0x6982) return null
        if (head.sw != 0x9000 && head.sw != 0x6282) throw MrtdException("read_failed", head.sw)
        if (head.data.isEmpty()) return null
        val total = BerTlv.totalLength(head.data) ?: throw MrtdException("read_format")
        if (total <= head.data.size) return head.data.copyOf(total)
        return head.data + readRest(ch, head.data.size, total)
    }

    private suspend fun readRest(ch: CardChannel, from: Int, total: Int): ByteArray {
        val out = ArrayList<ByteArray>()
        var off = from
        var size = chunk
        while (off < total) {
            val want = minOf(size, total - off)
            val r = if (off <= 0x7FFF) ch.transmit(0x00, 0xB0, (off shr 8) and 0x7F, off and 0xFF, ByteArray(0), want)
            else {
                // Offsets beyond 32767 need READ BINARY with an odd instruction and the offset in DO'54'.
                val o = byteArrayOf((off shr 16).toByte(), (off shr 8).toByte(), off.toByte()).dropWhile { it == 0.toByte() }.toByteArray()
                val resp = ch.transmit(0x00, 0xB1, 0x00, 0x00, BerTlv.encode(0x54, o), want + 4)
                val data = if (resp.sw == 0x9000 || resp.sw == 0x6282) BerTlv.find(resp.data, 0x53) ?: ByteArray(0) else ByteArray(0)
                diw.wallet.core.document.card.CardResponse(resp.sw, data)
            }
            if (r.sw == 0x6700 || r.sw shr 8 == 0x6C) {
                if (size <= 0x20) throw MrtdException("read_failed", r.sw)
                size /= 2
                continue
            }
            if (r.sw != 0x9000 && r.sw != 0x6282) throw MrtdException("read_failed", r.sw)
            if (r.data.isEmpty()) break
            out.add(r.data)
            off += r.data.size
            if (r.sw == 0x6282) break
        }
        val all = ByteArray(out.sumOf { it.size })
        var p = 0
        for (b in out) { b.copyInto(all, p); p += b.size }
        if (from + all.size < total) throw MrtdException("read_short")
        return all
    }

    companion object {
        /** The LDS 1 eMRTD application. */
        val AID = byteArrayOf(0xA0.toByte(), 0x00, 0x00, 0x02, 0x47, 0x10, 0x01)
    }
}

/** The message of a reading failure in the app language, with the status word when the chip gave one. */
fun MrtdException.describe(): String {
    val key = when (code) {
        "access_denied", "bac_mac", "bac_mismatch", "pace_token" -> "core_mrtd_err_access"
        "not_passport" -> "core_mrtd_err_not_passport"
        "can_needs_pace" -> "core_mrtd_err_can"
        "ca_failed" -> "core_mrtd_err_clone"
        "sm_mac", "sm_error", "sm_missing", "sm_format", "bad_padding" -> "core_mrtd_err_session"
        "no_com", "no_sod" -> "core_mrtd_err_files"
        else -> "core_mrtd_err_other"
    }
    val text = diw.wallet.core.i18n.ct(key)
    return if (key == "core_mrtd_err_other") text + code + (sw?.let { " " + it.toString(16).uppercase().padStart(4, '0') } ?: "")
        else text + (sw?.let { " (" + it.toString(16).uppercase().padStart(4, '0') + ")" } ?: "")
}

package diw.wallet.app

import androidx.compose.ui.graphics.ImageBitmap
import diw.wallet.app.res.Res
import diw.wallet.app.res.*
import diw.wallet.core.document.card.NfcCardChannel
import diw.wallet.core.document.mrtd.AccessSecret
import diw.wallet.core.document.mrtd.DocumentDetails
import diw.wallet.core.document.mrtd.Lds
import diw.wallet.core.document.mrtd.LdsFile
import diw.wallet.core.document.mrtd.MrtdDump
import diw.wallet.core.document.mrtd.MrtdException
import diw.wallet.core.document.mrtd.MrtdReader
import diw.wallet.core.document.mrtd.MrtdStage
import diw.wallet.core.document.mrtd.Mrz
import diw.wallet.core.document.mrtd.PersonalDetails
import diw.wallet.core.document.mrtd.describe
import diw.wallet.core.document.sign.SigningException

/**
 * What the file screen shows of a travel document read from its chip: the zone with every given name, the full name
 * and other details of DG11 and DG12, and the portraits of DG2 and DG5. Pictures the device cannot decode (JPEG 2000
 * on most phones) are counted, not dropped silently.
 */
class PassportView(
    val dump: MrtdDump,
    val mrz: Mrz?,
    val personal: PersonalDetails?,
    val document: DocumentDetails?,
    val portraits: List<ImageBitmap>,
    val undecodedPortraits: List<String>,
    /** Every picture of DG2 and DG5 as stored on the chip, with its bitmap when the device decoded it. */
    val pictures: List<PassportPicture> = emptyList(),
)

/** One picture of a travel document: the chip's encoded [image] and its [bitmap], null when it could not be decoded. */
class PassportPicture(val image: diw.wallet.core.document.mrtd.MrtdImage, val bitmap: ImageBitmap?)

object Passports {
    /** The structured view of [dump]; [decode] turns an encoded picture into a bitmap, null when it cannot. */
    fun view(dump: MrtdDump, decode: (ByteArray) -> ImageBitmap?): PassportView {
        val images = (dump.file(LdsFile.DG2)?.let { Lds.dg2(it) }.orEmpty() + dump.file(LdsFile.DG5)?.let { Lds.displayedImages(it) }.orEmpty())
        val decoded = images.map { it to runCatching { decode(it.data) }.getOrNull() }
        return PassportView(
            dump = dump,
            mrz = dump.file(LdsFile.DG1)?.let { Lds.dg1(it) },
            personal = dump.file(LdsFile.DG11)?.let { Lds.dg11(it) },
            document = dump.file(LdsFile.DG12)?.let { Lds.dg12(it) },
            portraits = decoded.mapNotNull { it.second },
            undecodedPortraits = decoded.filter { it.second == null }.map { it.first.mediaType },
            pictures = decoded.map { PassportPicture(it.first, it.second) },
        )
    }

    /** The file name: the document type and holder name from the zone, never the document number. */
    fun fileName(dump: MrtdDump): String {
        val mrz = dump.file(LdsFile.DG1)?.let { Lds.dg1(it) }
        val kind = if (mrz?.documentCode?.startsWith("P") != false) tr(Res.string.mrtd_kind_passport) else tr(Res.string.mrtd_kind_travel_document)
        val name = mrz?.let { listOf(it.primaryIdentifier, it.secondaryIdentifier).filter { s -> s.isNotEmpty() }.joinToString(" ") }.orEmpty()
        return listOf(kind, name).filter { it.isNotEmpty() }.joinToString(" ") + "." + MrtdDump.FILE_EXTENSION
    }

    /** "YYMMDD" as YYYY-MM-DD, the century chosen so a birth date is in the past and an expiry date near now. */
    fun date(yymmdd: String, expiry: Boolean, currentYear: Int): String =
        diw.wallet.core.document.derived.TravelDocumentFields.date(yymmdd, expiry, currentYear)

    /** YYYYMMDD as YYYY-MM-DD. */
    fun fullDate(s: String?): String? = s?.takeIf { it.length == 8 }?.let { "${it.take(4)}-${it.substring(4, 6)}-${it.substring(6)}" } ?: s

    /**
     * Reads the chip on [reader] with [secret] while the document stays on it, reporting each step in [progress].
     * Failures come back as [SigningException] with the message in the app language.
     */
    suspend fun read(reader: NfcReaderOption, secret: AccessSecret, progress: (String) -> Unit): MrtdDump {
        val message = if (reader.external) tr(Res.string.mrtd_place_on_reader, reader.name) else tr(Res.string.mrtd_hold_phone)
        return try {
            reader.reader.scan(message, tagInteractionFunc = { tag ->
                MrtdReader(NfcCardChannel(tag), secret, progress = { stage, done, total ->
                    progress(when (stage) {
                        MrtdStage.ACCESS -> tr(Res.string.mrtd_stage_access)
                        MrtdStage.CHIP_AUTHENTICATION -> tr(Res.string.mrtd_stage_ca)
                        MrtdStage.READING -> tr(Res.string.mrtd_stage_reading, done + 1, total)
                        MrtdStage.ACTIVE_AUTHENTICATION -> tr(Res.string.mrtd_stage_aa)
                        MrtdStage.DONE -> tr(Res.string.mrtd_stage_done)
                    })
                }).read()
            })
        } catch (e: MrtdException) {
            throw SigningException(e.describe(), e)
        }
    }
}

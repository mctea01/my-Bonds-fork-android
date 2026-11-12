package diw.wallet.core.document.sign

import diw.wallet.core.document.pdf.PdfSignatureAppearance

/**
 * An electronic seal stamped with an OFD signature of Type "Seal" (GB/T 38540 SES_Signature). The seal is either
 * one a seal maker issued ([sealFile], an .esl file holding an SESeal, versions 1 to 5), or one the wallet makes for
 * the signer: a personal seal ([personal]) or an organisation seal named [name] with [picture] (PNG), signed by the
 * signer's own key and so trusted only as far as that key is. It shows on page [page] (0-based, negative from the
 * end) at [position], [widthMm] wide (the height follows the picture).
 */
class OfdSealOptions(
    val page: Int = -1,
    val position: PdfSignatureAppearance.Position = PdfSignatureAppearance.Position.BOTTOM_RIGHT,
    val sealFile: ByteArray? = null,
    val picture: ByteArray? = null,
    val name: String = "",
    val personal: Boolean = true,
    val widthMm: Double? = null,
    /** The seal box as page fractions (left, top) instead of [position], such as from a tap on the preview. */
    val at: Pair<Double, Double>? = null,
)

/**
 * What an electronic seal (SESeal) says: [version] of its header (1 to 3 GM/T 0031-2014, 4 GB/T 38540-2020, 5
 * GM/T 0031-2025), [name], whether it is a personal seal, its validity (epoch seconds), the picture and its size in
 * millimetres, the seal maker's certificate name and how many signer certificates it allows (0: any).
 */
class OfdSealInfo(
    val version: Int,
    val id: String,
    val name: String,
    val personal: Boolean,
    val validFrom: Long?,
    val validTo: Long?,
    val pictureType: String,
    val picture: ByteArray,
    val widthMm: Double,
    val heightMm: Double,
    val maker: String?,
    val signers: Int,
)

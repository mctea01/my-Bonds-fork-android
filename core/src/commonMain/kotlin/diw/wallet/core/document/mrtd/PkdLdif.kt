package diw.wallet.core.document.mrtd

import kotlin.io.encoding.Base64

/**
 * The binary entries of an ICAO PKD download (LDIF, RFC 2849): master lists (pkdMasterListContent, the
 * icaopkd-002 file), CA certificates (cACertificate), document signer certificates (userCertificate, the
 * icaopkd-001 and 003 files) and CRLs (certificateRevocationList). The file is scanned line by line, so a large
 * download is not copied into one string; document signers and CRLs are only counted, since they are not anchors.
 */
class PkdLdif(
    val masterLists: List<ByteArray>,
    val caCertificates: List<ByteArray>,
    val documentSigners: Int,
    val crls: Int,
) {
    companion object {
        private const val MASTER_LIST = "pkdmasterlistcontent"
        private const val CA = "cacertificate"
        private const val DSC = "usercertificate"
        private const val CRL = "certificaterevocationlist"
        private val KEPT = setOf(MASTER_LIST, CA)

        /** Whether [bytes] starts like an LDIF file (a version line, a comment or a dn line). */
        fun looksLike(bytes: ByteArray): Boolean {
            val head = bytes.copyOf(minOf(bytes.size, 256)).decodeToString().trimStart('\uFEFF', ' ', '\r', '\n').lowercase()
            return head.startsWith("version:") || head.startsWith("dn:") || head.startsWith("#")
        }

        /** The entries of the LDIF file [bytes]; null when it is not LDIF or a value is not valid base64. */
        fun parse(bytes: ByteArray): PkdLdif? {
            if (!looksLike(bytes)) return null
            val out = KEPT.associateWith { ArrayList<ByteArray>() }
            var signers = 0
            var crls = 0
            var name: String? = null
            val value = StringBuilder()
            fun finish(): Boolean {
                val n = name ?: return true
                name = null
                val der = runCatching { Base64.Default.decode(value.toString()) }.getOrNull() ?: return false
                value.setLength(0)
                if (der.isNotEmpty()) out.getValue(n).add(der)
                return true
            }
            var i = 0
            while (i <= bytes.size) {
                var end = i
                while (end < bytes.size && bytes[end] != '\n'.code.toByte()) end++
                var stop = end
                if (stop > i && bytes[stop - 1] == '\r'.code.toByte()) stop--
                if (stop > i && bytes[i] == ' '.code.toByte()) {
                    // A folded line continues the value before it.
                    if (name != null) value.append(bytes.decodeToString(i + 1, stop).trim())
                } else {
                    if (!finish()) return null
                    if (stop > i && bytes[i] != '#'.code.toByte()) {
                        val line = bytes.decodeToString(i, stop)
                        val colon = line.indexOf(':')
                        if (colon > 0 && colon + 1 < line.length && line[colon + 1] == ':') {
                            val attribute = line.substring(0, colon).substringBefore(';').trim().lowercase()
                            if (attribute == DSC) signers++
                            if (attribute == CRL) crls++
                            if (attribute in KEPT) {
                                name = attribute
                                value.append(line.substring(colon + 2).trim())
                            }
                        }
                    }
                }
                i = end + 1
            }
            if (!finish()) return null
            return PkdLdif(out.getValue(MASTER_LIST), out.getValue(CA), signers, crls)
        }
    }
}

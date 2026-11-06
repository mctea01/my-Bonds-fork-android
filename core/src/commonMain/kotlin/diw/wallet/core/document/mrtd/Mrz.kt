package diw.wallet.core.document.mrtd

/**
 * The machine readable zone of a travel document (ICAO 9303 parts 4 to 6): TD3 (passports, 2 lines of 44), TD2
 * (2 lines of 36) and TD1 (cards, 3 lines of 30). Names keep every component: the given names are split on single
 * fillers and shown in full, so a given name with two parts ("CHE<CHUAN") is never cut to its first part.
 */
data class Mrz(
    val format: Format,
    /** Document code without fillers ("P", "PO", "I", "ID"). */
    val documentCode: String,
    val issuingState: String,
    /** Surname (primary identifier), fillers as spaces. */
    val primaryIdentifier: String,
    /** Given names (secondary identifier), each component as written. */
    val givenNames: List<String>,
    val documentNumber: String,
    val nationality: String,
    /** YYMMDD; unknown parts stay as fillers. */
    val birthDate: String,
    /** "M", "F" or "X" (unspecified, written as a filler). */
    val sex: String,
    /** YYMMDD. */
    val expiryDate: String,
    val optionalData: String,
    /** TD1 has a second optional data field on its second line. */
    val optionalData2: String?,
    /** Every check digit of the zone matches. */
    val checkDigitsValid: Boolean,
    /** The check digits that do not match, by field ("document_number", "birth_date", ...). */
    val failedChecks: List<String>,
    /** The name field ran to the end of the line, so the names may have been truncated by the issuer. */
    val nameMayBeTruncated: Boolean,
    val lines: List<String>,
) {
    enum class Format(val lineLength: Int, val lineCount: Int) { TD1(30, 3), TD2(36, 2), TD3(44, 2) }

    /** All given names joined with spaces. */
    val secondaryIdentifier: String get() = givenNames.joinToString(" ")

    /** "SURNAME, GIVEN NAMES" as printed on the data page. */
    val fullName: String get() = listOf(primaryIdentifier, secondaryIdentifier).filter { it.isNotEmpty() }.joinToString(", ")

    /** The access key of this document (BAC and PACE with the MRZ). */
    val accessKey: MrzKey get() = MrzKey(documentNumber, birthDate, expiryDate)

    /** The zone as one string, as DG1 stores it. */
    val text: String get() = lines.joinToString("")

    companion object {
        /** Character value for check digits: digits as such, A to Z as 10 to 35, filler as 0. */
        private fun value(c: Char): Int = when (c) {
            in '0'..'9' -> c - '0'
            in 'A'..'Z' -> c - 'A' + 10
            '<' -> 0
            else -> throw IllegalArgumentException("MRZ character not allowed: $c")
        }

        /** The ICAO 9303 check digit (weights 7, 3, 1). */
        fun checkDigit(s: String): Char {
            var sum = 0
            for ((i, c) in s.withIndex()) sum += value(c) * WEIGHTS[i % 3]
            return '0' + sum % 10
        }

        private val WEIGHTS = intArrayOf(7, 3, 1)

        private fun ok(field: String, check: Char): Boolean =
            runCatching { checkDigit(field) == check || (check == '<' && field.all { it == '<' }) }.getOrDefault(false)

        /** Normalises OCR or typed text: upper case, common OCR confusions in fillers, no spaces. */
        fun normalize(line: String): String = line.trim().uppercase()
            .replace(' ', '<').replace('«', '<').replace('‹', '<').replace('(', '<').replace('[', '<')
            .filter { it in 'A'..'Z' || it in '0'..'9' || it == '<' }

        /** Parses the zone from its lines, or from DG1's single string; null when it is not a known layout. */
        fun parse(text: String): Mrz? {
            val raw = text.lines().map { normalize(it) }.filter { it.isNotEmpty() }
            val joined = raw.joinToString("")
            val lines = when {
                raw.size == 3 && raw.all { it.length == 30 } -> raw
                raw.size == 2 && raw.all { it.length == 44 } -> raw
                raw.size == 2 && raw.all { it.length == 36 } -> raw
                joined.length == 90 -> joined.chunked(30)
                joined.length == 88 -> joined.chunked(44)
                joined.length == 72 -> joined.chunked(36)
                else -> return null
            }
            return runCatching {
                when (lines.first().length) {
                    30 -> td1(lines)
                    36 -> td2or3(lines, Format.TD2)
                    else -> td2or3(lines, Format.TD3)
                }
            }.getOrNull()
        }

        private fun clean(s: String) = s.trimEnd('<').replace('<', ' ').trim()

        /** Primary and secondary identifiers: split once on a double filler, given names on single fillers. */
        private fun names(field: String): Triple<String, List<String>, Boolean> {
            val truncated = field.last() != '<'
            val idx = field.indexOf("<<")
            val primary = if (idx < 0) field else field.substring(0, idx)
            val secondary = if (idx < 0) "" else field.substring(idx + 2)
            val given = secondary.trimEnd('<').split('<').filter { it.isNotEmpty() }
            return Triple(clean(primary), given, truncated)
        }

        private fun td2or3(l: List<String>, format: Format): Mrz {
            val a = l[0]
            val b = l[1]
            val (primary, given, truncated) = names(a.substring(5))
            val failed = ArrayList<String>()
            var number = b.substring(0, 9)
            var numberCheck = b[9]
            var optional = if (format == Format.TD3) b.substring(28, 42) else b.substring(28, 35)
            // A document number longer than 9 characters continues in the optional data (TD2 only in practice).
            if (numberCheck == '<' && format == Format.TD2) {
                val rest = optional.trimEnd('<')
                if (rest.isNotEmpty()) {
                    number += rest.dropLast(1)
                    numberCheck = rest.last()
                    optional = ""
                }
            }
            if (!ok(number, numberCheck)) failed.add("document_number")
            if (!ok(b.substring(13, 19), b[19])) failed.add("birth_date")
            if (!ok(b.substring(21, 27), b[27])) failed.add("expiry_date")
            val composite: String
            if (format == Format.TD3) {
                if (!ok(b.substring(28, 42), b[42])) failed.add("personal_number")
                composite = b.substring(0, 10) + b.substring(13, 20) + b.substring(21, 43)
                if (!ok(composite, b[43])) failed.add("composite")
            } else {
                composite = b.substring(0, 10) + b.substring(13, 20) + b.substring(21, 35)
                if (!ok(composite, b[35])) failed.add("composite")
            }
            return Mrz(
                format = format,
                documentCode = a.substring(0, 2).trimEnd('<'),
                issuingState = a.substring(2, 5).trimEnd('<'),
                primaryIdentifier = primary,
                givenNames = given,
                documentNumber = number.trimEnd('<'),
                nationality = b.substring(10, 13).trimEnd('<'),
                birthDate = b.substring(13, 19),
                sex = b[20].let { if (it == '<') "X" else it.toString() },
                expiryDate = b.substring(21, 27),
                optionalData = clean(optional),
                optionalData2 = null,
                checkDigitsValid = failed.isEmpty(),
                failedChecks = failed,
                nameMayBeTruncated = truncated,
                lines = l,
            )
        }

        private fun td1(l: List<String>): Mrz {
            val a = l[0]
            val b = l[1]
            val (primary, given, truncated) = names(l[2])
            val failed = ArrayList<String>()
            var number = a.substring(5, 14)
            var numberCheck = a[14]
            var optional = a.substring(15, 30)
            if (numberCheck == '<') {
                val rest = optional.trimEnd('<').takeWhile { it != '<' }
                if (rest.isNotEmpty()) {
                    number += rest.dropLast(1)
                    numberCheck = rest.last()
                    optional = optional.substring(rest.length)
                }
            }
            if (!ok(number, numberCheck)) failed.add("document_number")
            if (!ok(b.substring(0, 6), b[6])) failed.add("birth_date")
            if (!ok(b.substring(8, 14), b[14])) failed.add("expiry_date")
            val composite = a.substring(5, 30) + b.substring(0, 7) + b.substring(8, 15) + b.substring(18, 29)
            if (!ok(composite, b[29])) failed.add("composite")
            return Mrz(
                format = Format.TD1,
                documentCode = a.substring(0, 2).trimEnd('<'),
                issuingState = a.substring(2, 5).trimEnd('<'),
                primaryIdentifier = primary,
                givenNames = given,
                documentNumber = number.trimEnd('<'),
                nationality = b.substring(15, 18).trimEnd('<'),
                birthDate = b.substring(0, 6),
                sex = b[7].let { if (it == '<') "X" else it.toString() },
                expiryDate = b.substring(8, 14),
                optionalData = clean(optional),
                optionalData2 = clean(b.substring(18, 29)),
                checkDigitsValid = failed.isEmpty(),
                failedChecks = failed,
                nameMayBeTruncated = truncated,
                lines = l,
            )
        }

        /**
         * The zone lines found in OCR text: the first run of lines that parses with valid check digits, or the
         * first that parses at all when none is fully valid.
         */
        fun find(ocr: String): Mrz? {
            val candidates = ocr.lines().map { normalize(it) }.filter { it.length >= 28 }
            var fallback: Mrz? = null
            for (count in listOf(2, 3)) for (i in 0..candidates.size - count) {
                val group = candidates.subList(i, i + count).map { fit(it) }
                val m = parse(group.joinToString("\n")) ?: continue
                if (m.checkDigitsValid) return m
                if (fallback == null) fallback = m
            }
            return fallback
        }

        /** An OCR line one or two characters off a known length, padded or cut to it. */
        private fun fit(line: String): String {
            for (n in listOf(44, 36, 30)) if (line.length in n - 2..n + 2) return line.padEnd(n, '<').take(n)
            return line
        }
    }
}

/**
 * The part of the zone that unlocks the chip (BAC, PACE with the MRZ): document number, date of birth and date of
 * expiry. It can be typed from the data page without the whole zone.
 */
data class MrzKey(val documentNumber: String, val birthDate: String, val expiryDate: String) {
    init {
        require(documentNumber.isNotEmpty() && documentNumber.all { it in 'A'..'Z' || it in '0'..'9' || it == '<' }) { "document number" }
        require(birthDate.length == 6 && birthDate.all { it.isDigit() || it == '<' }) { "birth date YYMMDD" }
        require(expiryDate.length == 6 && expiryDate.all { it.isDigit() }) { "expiry date YYMMDD" }
    }

    /** The MRZ information the keys are derived from: number, birth and expiry, each with its check digit. */
    val information: String get() {
        val number = documentNumber.padEnd(9, '<')
        return number + Mrz.checkDigit(number) + birthDate + Mrz.checkDigit(birthDate) + expiryDate + Mrz.checkDigit(expiryDate)
    }

    companion object {
        /** From typed fields; dates as YYMMDD or YYYYMMDD (or with separators). */
        fun of(documentNumber: String, birthDate: String, expiryDate: String): MrzKey {
            fun date(s: String): String {
                val d = s.filter { it.isDigit() }
                return if (d.length == 8) d.substring(2) else d
            }
            return MrzKey(Mrz.normalize(documentNumber).trimEnd('<'), date(birthDate), date(expiryDate))
        }
    }
}

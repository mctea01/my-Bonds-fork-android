package diw.wallet.core.document.mrtd

/**
 * The machine readable zone of a travel document (ICAO 9303 parts 4 to 6): TD3 (passports, 2 lines of 44), TD2
 * (2 lines of 36) and TD1 (cards, 3 lines of 30). Names keep every component: the given names are split on single
 * fillers and shown in full, so a given name with two parts ("CHE<CHUAN") is never cut to its first part.
 *
 * The exit-entry permit cards of mainland China (document codes starting with C, such as CT for the travel permit
 * for Taiwan residents) use 3 lines of 30 in their own layout ([Format.CN_PERMIT]): line 1 holds the document
 * number, issue count, expiry, sex and birth date, each with an ICAO check digit; line 2 starts with the holder's
 * Chinese name as GB 2312 bytes written with A to P for the hex digits; line 3 holds the romanised name. The rest
 * of lines 2 and 3 is kept as optional data without interpretation.
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
    /** TD1 has a second optional data field on its second line; the permit layout keeps the end of lines 2 and 3. */
    val optionalData2: String?,
    /** Every check digit of the zone matches. */
    val checkDigitsValid: Boolean,
    /** The check digits that do not match, by field ("document_number", "birth_date", ...). */
    val failedChecks: List<String>,
    /** The name field ran to the end of the line, so the names may have been truncated by the issuer. */
    val nameMayBeTruncated: Boolean,
    val lines: List<String>,
    /** How many times the permit has been issued (permit layout only). */
    val issueCount: String? = null,
) {
    enum class Format(val lineLength: Int, val lineCount: Int) { TD1(30, 3), TD2(36, 2), TD3(44, 2), CN_PERMIT(30, 3) }

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
                    30 -> if (isCnPermit(lines)) cnPermit(lines) else td1(lines)
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

        /**
         * A mainland China permit card: a document code starting with C and the check digits of the document
         * number, expiry and birth date valid where that layout puts them (an ICAO TD1 zone puts other fields there).
         */
        private fun isCnPermit(l: List<String>): Boolean {
            val a = l[0]
            return a[0] == 'C' && a[1] in 'A'..'Z' && a[22] in "MF<" &&
                checkOk(a.substring(2, 11), a[11]) && checkOk(a.substring(15, 21), a[21]) && checkOk(a.substring(23, 29), a[29])
        }

        private fun checkOk(field: String, check: Char): Boolean = runCatching { checkDigit(field) == check }.getOrDefault(false)

        private fun cnPermit(l: List<String>): Mrz {
            val a = l[0]
            val (primary, given, _) = names(l[2].substring(0, 26))
            val failed = ArrayList<String>()
            if (!ok(a.substring(2, 11), a[11])) failed.add("document_number")
            if (!ok(a.substring(12, 14), a[14])) failed.add("issue_count")
            if (!ok(a.substring(15, 21), a[21])) failed.add("expiry_date")
            if (!ok(a.substring(23, 29), a[29])) failed.add("birth_date")
            return Mrz(
                format = Format.CN_PERMIT,
                documentCode = a.substring(0, 2),
                issuingState = "CHN",
                primaryIdentifier = primary,
                givenNames = given,
                documentNumber = a.substring(2, 11).trimEnd('<'),
                nationality = "",
                birthDate = a.substring(23, 29),
                sex = a[22].let { if (it == '<') "X" else it.toString() },
                expiryDate = a.substring(15, 21),
                optionalData = "",
                optionalData2 = listOf(l[1].substring(16), l[2].substring(26)).map(::clean).filter { it.isNotEmpty() }.joinToString(" "),
                checkDigitsValid = failed.isEmpty(),
                failedChecks = failed,
                nameMayBeTruncated = l[2][25] != '<',
                lines = l,
                issueCount = a.substring(12, 14).trimStart('0').ifEmpty { "0" },
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

        /**
         * The zone in camera OCR text, only when every check digit holds: OCR confusions are corrected by position
         * first (O for 0 in dates and check digits, 0 for O in country codes and names), then the document number is
         * tried as read and with its letters that look like digits read as digits. A partial read returns null, so a
         * caller keeps scanning frames until one is complete.
         */
        fun recognize(ocr: String): Mrz? {
            // OCR puts stray spaces between characters and sometimes reads fillers as spaces: both readings are tried.
            for (spaces in listOf("", "<")) recognizeLines(ocr.lines().map { normalize(it.replace(" ", spaces)) })?.let { return it }
            return null
        }

        private fun recognizeLines(lines: List<String>): Mrz? {
            val candidates = lines.filter { it.length >= 28 }.map { fit(it) }
            for (count in listOf(2, 3)) for (i in 0..candidates.size - count) {
                val group = candidates.subList(i, i + count)
                if (group.map { it.length }.toSet().size != 1) continue
                for (fixed in corrected(group)) {
                    val m = parse(fixed.joinToString("\n")) ?: continue
                    if (m.checkDigitsValid) return m
                }
            }
            return null
        }

        private val TO_DIGIT = mapOf('O' to '0', 'Q' to '0', 'D' to '0', 'U' to '0', 'I' to '1', 'L' to '1', 'Z' to '2', 'S' to '5', 'B' to '8', 'G' to '6', 'T' to '7')
        private val TO_LETTER = mapOf('0' to 'O', '1' to 'I', '2' to 'Z', '5' to 'S', '8' to 'B', '6' to 'G')

        private fun String.digitsAt(range: IntRange): String =
            mapIndexed { i, c -> if (i in range) TO_DIGIT[c] ?: c else c }.joinToString("")

        private fun String.lettersAt(range: IntRange): String =
            mapIndexed { i, c -> if (i in range) TO_LETTER[c] ?: c else c }.joinToString("")

        /** The group with positional corrections, the document number as read and with digit look-alikes as digits. */
        private fun corrected(l: List<String>): List<List<String>> {
            val n = l[0].length
            val fixed: List<String>
            val number: Pair<Int, IntRange>
            when {
                n == 30 && l.size == 3 && l[0][0] == 'C' && l[0][1] != '<' -> {
                    // Permit layout: line 1 holds the number, issue count, expiry, sex and birth date.
                    fixed = listOf(l[0].lettersAt(0..1).digitsAt(11..21).digitsAt(23..29), l[1], l[2].lettersAt(0..29))
                    number = 0 to 2..10
                }
                n == 30 && l.size == 3 -> {
                    fixed = listOf(l[0].lettersAt(0..4).digitsAt(14..14), l[1].digitsAt(0..6).digitsAt(8..14).lettersAt(15..17).digitsAt(29..29), l[2].lettersAt(0..29))
                    number = 0 to 5..13
                }
                (n == 44 || n == 36) && l.size == 2 -> {
                    val last = n - 1
                    fixed = listOf(l[0].lettersAt(0..n - 1), l[1].digitsAt(9..9).lettersAt(10..12).digitsAt(13..19).digitsAt(21..27).digitsAt(last..last))
                    number = 1 to 0..8
                }
                else -> return listOf(l)
            }
            val (line, range) = number
            val asDigits = fixed.toMutableList().also { it[line] = it[line].digitsAt(range.first + 1..range.last) }
            return listOf(fixed, asDigits).distinct()
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

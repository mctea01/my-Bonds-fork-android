package diw.wallet.core.profile.bonds

import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.JsonPrimitive

/**
 * The two values MyData asks for again and again (Bonds MyDataAutofillProfile): the national ID number and the
 * birth date (Gregorian yyyyMMdd, as MyData's sign-in hint writes it). The holder saves them on purpose; the wallet
 * fills them into recognised inputs of mydata.nat.gov.tw pages only and tries the ID number on MyData PDFs.
 */
object MyDataProfile {
    const val HOST = "mydata.nat.gov.tw"

    private val letterCodes = intArrayOf(10, 11, 12, 13, 14, 15, 16, 17, 34, 18, 19, 20, 21, 22, 35, 23, 24, 25, 26, 27, 28, 29, 32, 30, 31, 33)

    /** A Taiwan national ID number with a correct check digit (letter, 1 or 2, eight digits). */
    fun isValidId(value: String): Boolean {
        val id = value.trim().uppercase()
        if (id.length != 10 || id[0] !in 'A'..'Z' || id[1] !in "12" || id.drop(2).any { it !in '0'..'9' }) return false
        val code = letterCodes[id[0] - 'A']
        var sum = code / 10 + (code % 10) * 9
        for (i in 1..8) sum += (id[i] - '0') * (9 - i)
        sum += id[9] - '0'
        return sum % 10 == 0
    }

    fun normalizeId(value: String): String = value.trim().uppercase()

    /**
     * A birth date as yyyyMMdd: eight Gregorian digits, or seven 民國 digits (yyyMMdd); separators are ignored.
     * Null when it is not a real date or lies after [today] (yyyyMMdd).
     */
    fun normalizeBirthDate(value: String, today: String): String? {
        val d = value.filter { it.isDigit() }
        val gregorian = when (d.length) {
            7 -> (d.take(3).toInt() + 1911).toString().padStart(4, '0') + d.drop(3)
            8 -> d
            else -> return null
        }
        val date = runCatching { LocalDate(gregorian.take(4).toInt(), gregorian.substring(4, 6).toInt(), gregorian.substring(6).toInt()) }.getOrNull()
            ?: return null
        return gregorian.takeIf { date.year >= 1900 && it <= today }
    }

    /**
     * Script filling the ID number and birth date into empty, enabled text inputs whose id, name, placeholder,
     * aria-label or label mentions them, with input and change events so the site's own checks still run; it returns
     * how many inputs it filled. The page is never given anything else.
     */
    fun autofillScript(idNumber: String, birthDate: String): String {
        val id = JsonPrimitive(idNumber).toString()
        val birth = JsonPrimitive(birthDate).toString()
        return """
            (() => {
              const values = { id: $id, birth: $birth };
              let filled = 0;
              for (const input of document.querySelectorAll('input')) {
                if (input.disabled || input.readOnly || ['hidden','password','file','checkbox','radio'].includes(input.type)) continue;
                const labels = input.labels ? Array.from(input.labels).map(l => l.innerText) : [];
                const field = input.closest('.form-group, .form-item, .field, .row');
                const fieldLabel = (field && field.querySelector('label')) ? field.querySelector('label').innerText : '';
                const hint = [input.id, input.name, input.placeholder, input.getAttribute('aria-label'), ...labels, fieldLabel]
                  .filter(Boolean).join(' ').toLowerCase();
                let value = null;
                if (/生日|出生|birth|yyyy.?mm.?dd|19880101|0770101/.test(hint)) value = values.birth;
                else if (/身分證|身份證|統一編號|national.?id|citizen.?id|pid/.test(hint)) value = values.id;
                if (!value || input.value) continue;
                const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                if (setter && setter.set) setter.set.call(input, value); else input.value = value;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.dispatchEvent(new Event('change', { bubbles: true }));
                filled++;
              }
              return filled;
            })();
        """.trimIndent()
    }
}

package diw.testservers.fixtures

import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * A Taiwan official letter (函) in the electronic document XML of the 文書處理手冊 (DTD 104_2_utf8.dtd): sender,
 * date and number, speed, subject, explanation paragraphs, recipients and copies. The wallet writes the file (.di)
 * for the holder to keep or sign with XAdES; sending through the document exchange needs an agency account.
 */
data class OfficialLetter(
    val sender: String,
    val senderCode: String = "",
    val address: String = "",
    val contact: String = "",
    val recipient: String,
    val subject: String,
    /** Explanation items, numbered 一、二、… */
    val explanations: List<String> = emptyList(),
    val wordPrefix: String = "",
    val serial: String = "",
    val speed: String = "普通件",
    val attachments: String = "",
    val copies: List<String> = emptyList(),
    val date: Instant = Clock.System.now(),
) {
    /** ROC calendar date in the Asia/Taipei zone, as written on letters (中華民國115年10月11日). */
    fun rocDate(): Pair<Int, String> {
        val d = date.toLocalDateTime(TimeZone.of("Asia/Taipei")).date
        val year = d.year - 1911
        return year to "中華民國${year}年${d.month.ordinal + 1}月${d.day}日"
    }

    fun toXml(): ByteArray {
        val (year, dateText) = rocDate()
        val sb = StringBuilder()
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        sb.append("<!DOCTYPE 函 SYSTEM \"104_2_utf8.dtd\">\n")
        sb.append("<函>\n")
        sb.append("<發文機關><全銜>").append(esc(sender)).append("</全銜><機關代碼>").append(esc(senderCode)).append("</機關代碼></發文機關>\n")
        sb.append("<函類別 代碼=\"函\"/>\n")
        sb.append("<地址>").append(esc(address)).append("</地址>\n")
        sb.append("<聯絡方式>").append(esc(contact)).append("</聯絡方式>\n")
        sb.append("<受文者><全銜>").append(esc(recipient)).append("</全銜></受文者>\n")
        sb.append("<發文日期><年月日>").append(dateText).append("</年月日></發文日期>\n")
        sb.append("<發文字號><字>").append(esc(wordPrefix)).append("</字><文號><年度>").append(year)
            .append("</年度><流水號>").append(esc(serial)).append("</流水號></文號></發文字號>\n")
        sb.append("<速別 代碼=\"").append(esc(speed)).append("\"/>\n")
        sb.append("<密等及解密條件或保密期限><密等/><解密條件或保密期限/></密等及解密條件或保密期限>\n")
        sb.append("<附件><文字>").append(esc(attachments)).append("</文字></附件>\n")
        sb.append("<主旨><文字>").append(esc(subject)).append("</文字></主旨>\n")
        if (explanations.isNotEmpty()) {
            sb.append("<段落 段名=\"說明：\">\n")
            explanations.forEachIndexed { i, text ->
                sb.append("<條列 序號=\"").append(chineseNumber(i + 1)).append("、\"><文字>").append(esc(text)).append("</文字></條列>\n")
            }
            sb.append("</段落>\n")
        }
        sb.append("<正本><全銜>").append(esc(recipient)).append("</全銜></正本>\n")
        if (copies.isNotEmpty()) {
            sb.append("<副本>")
            copies.forEach { sb.append("<全銜>").append(esc(it)).append("</全銜>") }
            sb.append("</副本>\n")
        }
        sb.append("</函>\n")
        return sb.toString().encodeToByteArray()
    }

    companion object {
        val SPEEDS = listOf("最速件", "速件", "普通件")

        fun esc(s: String): String = buildString {
            for (c in s) when (c) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                else -> if (c.code < 0x20 && c != '\n' && c != '\t') append(' ') else append(c)
            }
        }

        /** 1 to 99 in Chinese numerals, as letters number their items. */
        fun chineseNumber(n: Int): String {
            val digits = "零一二三四五六七八九"
            require(n in 1..99)
            return when {
                n < 10 -> digits[n].toString()
                n == 10 -> "十"
                n < 20 -> "十" + digits[n % 10]
                n % 10 == 0 -> digits[n / 10] + "十"
                else -> digits[n / 10] + "十" + digits[n % 10]
            }
        }
    }
}

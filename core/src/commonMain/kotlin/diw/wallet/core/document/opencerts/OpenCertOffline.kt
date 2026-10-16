package diw.wallet.core.document.opencerts

import kotlinx.datetime.LocalDate
import kotlinx.datetime.TimeZone
import kotlinx.datetime.UtcOffset
import kotlinx.datetime.asTimeZone
import kotlinx.datetime.toLocalDateTime
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Instant

/**
 * Shows an OpenCerts certificate without the network. The page has no scripts and loads nothing: a Content Security
 * Policy allows inline styles and data: images only, and template tabs are plain CSS.
 *
 * - The templates of OpenCerts' demo renderer (demo-renderer.opencerts.io: GOVTECH_DEMO, OPENCERTS_DEMO,
 *   TESTIMONIALS, TESTIMONIALS2, CERTIFICATE_OF_AWARD, any other name falling back to the default as that renderer
 *   does) are laid out here the way that renderer lays them out. Logos and background pictures belong to their owners
 *   and are not built in: their names are printed instead.
 * - Any other certificate is laid out from its content ([OpenAttestationDocument.view]): recipient, main fields,
 *   signatories, transcript, pictures and other fields. It is the wallet's layout, not the issuer's.
 */
object OpenCertOffline {
    /** Hosts whose templates are built in. */
    val BUILT_IN_HOSTS = setOf("demo-renderer.opencerts.io")

    private val DEMO_TEMPLATES = setOf("GOVTECH_DEMO", "OPENCERTS_DEMO", "TESTIMONIALS", "TESTIMONIALS2", "CERTIFICATE_OF_AWARD")

    /** The offline page; [builtIn] is true when it follows the issuer's own templates. */
    class Page(val html: String, val builtIn: Boolean, val tabs: List<String>)

    /** Whether [doc] names a renderer whose templates are built in. */
    fun hasBuiltInTemplate(doc: OpenAttestationDocument): Boolean = builtInHost(doc.templateUrl)

    private fun builtInHost(url: String?): Boolean {
        val host = url?.trim()?.let { Regex("^https://([A-Za-z0-9.-]+)(?::\\d+)?(/.*)?$").matchEntire(it)?.groupValues?.get(1) } ?: return false
        return host.lowercase() in BUILT_IN_HOSTS
    }

    fun page(doc: OpenAttestationDocument): Page {
        if (builtInHost(doc.templateUrl)) {
            val d = Data(subjectData(doc), doc.v3)
            val name = templateName(doc)
            val tabs = when (if (name in DEMO_TEMPLATES) name else "GOVTECH_DEMO") {
                "OPENCERTS_DEMO" -> listOf("Certificate" to demoCertificate(d, govtech = false), "Transcript" to demoTranscript(d, govtech = false), "Media" to media())
                "TESTIMONIALS" -> listOf("Testimonial" to testimonial(d))
                "TESTIMONIALS2" -> listOf("Testimonial" to testimonial2(d))
                "CERTIFICATE_OF_AWARD" -> certificateOfAward(d)?.let { listOf("Certificate Of Award" to it) }
                else -> listOf("Certificate" to demoCertificate(d, govtech = true), "Transcript" to demoTranscript(d, govtech = true), "Media" to media())
            }
            if (tabs != null) return Page(html(tabs, NOTE_BUILT_IN), true, tabs.map { it.first })
        }
        val tabs = listOf("證書內容" to generic(doc.view()))
        return Page(html(tabs, NOTE_GENERIC), false, tabs.map { it.first })
    }

    private const val NOTE_BUILT_IN = "離線顯示：依 OpenCerts 範例顯示程式的樣式排版，標誌與背景圖以文字代替。查驗結果以錢包的檢查為準。"
    private const val NOTE_GENERIC = "離線顯示：錢包依證書內容排版，不是發證機構的樣式。查驗結果以錢包的檢查為準。"

    private fun templateName(doc: OpenAttestationDocument): String? {
        val t = (if (doc.v3) (doc.data["openAttestationMetadata"] as? JsonObject)?.get("template") else doc.data["\$template"]) as? JsonObject
        return (t?.get("name") as? JsonPrimitive)?.contentOrNull
    }

    /**
     * What the demo templates read (their getDocumentData): the credential subject with issuedOn from validFrom or
     * issuanceDate for version 3 and W3C documents, the unsalted data for version 2.
     */
    private fun subjectData(doc: OpenAttestationDocument): JsonObject {
        if (!doc.v3) return doc.data
        val subject = doc.data["credentialSubject"].let { (it as? JsonArray)?.firstOrNull() ?: it } as? JsonObject ?: JsonObject(emptyMap())
        val issued = subject["issuedOn"] ?: doc.data["validFrom"] ?: doc.data["issuanceDate"] ?: return subject
        return JsonObject(subject + ("issuedOn" to issued))
    }

    /** lodash get on the document data: "a.b[0].c". */
    private class Data(val root: JsonObject, val v3: Boolean) {
        fun el(path: String): JsonElement? {
            var cur: JsonElement? = root
            for (part in Regex("[^.\\[\\]]+").findAll(path).map { it.value }) {
                cur = when (val c = cur) {
                    is JsonObject -> c[part]
                    is JsonArray -> part.toIntOrNull()?.let { c.getOrNull(it) }
                    else -> null
                }
            }
            return cur
        }

        fun text(path: String): String? = (el(path) as? JsonPrimitive)?.contentOrNull

        fun t(path: String): String = esc(text(path) ?: "")

        /** An image source: data: images only, so the page loads nothing. */
        fun img(path: String, css: String = "", alt: String = ""): String = image(text(path), css, alt)
    }

    // ---------------------------------------------------------------- demo templates

    private fun demoCertificate(d: Data, govtech: Boolean): String {
        val dated = d.text("issuedOn")?.let { isoDate(it) }?.let { "Dated ${two(it.day)}/${two(it.month.ordinal + 1)}/${it.year}" } ?: ""
        return """
<div class="oc-cert">
  <section class="center">
    <div class="spacer"><div class="logo-text oc-logo">OpenCerts</div></div>
    <div class="spacer text-md"><i>This is to certify that</i></div>
    <div class="spacer text-lg"><b>${d.t("recipient.name")}</b></div>
    <div class="spacer text-md"><i>has successfully completed the</i></div>
    <div class="spacer text-lg">OpenCerts Demo</div>
    ${if (govtech) "<div class=\"spacer text-md\"><i>certification through training administered by</i></div><div class=\"logo-text\">GovTech Singapore</div>" else ""}
  </section>
  <section class="row end">
    <div class="col center text-sm">
      ${d.img("additionalData.certSignatories[0].signature", "max-width:230px;width:100%", "Signature")}
      <hr>
      <div><b>${d.t("additionalData.certSignatories[0].name")}</b><br>${d.t("additionalData.certSignatories[0].position")}, ${d.t("additionalData.certSignatories[0].organisation")}</div>
    </div>
    <div class="col"></div>
    <div class="col text-sm right">${esc(dated)}</div>
  </section>
</div>"""
    }

    private fun demoTranscript(d: Data, govtech: Boolean): String {
        val rows = (d.el("transcript") as? JsonArray).orEmpty().mapNotNull { it as? JsonObject }
        fun cell(o: JsonObject, k: String) = esc((o[k] as? JsonPrimitive)?.contentOrNull ?: "")
        val table = if (rows.isEmpty()) "" else """
  <div class="cert-title"><b>Transcript</b></div>
  <table class="transcript"><tr><th>Course Code</th><th>Name</th><th>Grade</th><th>Units</th><th>Semester</th></tr>
  ${rows.joinToString("") { r -> "<tr><td>${cell(r, "courseCode")}</td><td>${cell(r, "name")}</td><td>${cell(r, "grade")}</td><td>${cell(r, "courseCredit")}</td><td>${cell(r, "semester")}</td></tr>" }}
  </table>"""
        fun line(label: String, value: String) = "<div class=\"kv\"><span>$label</span><span>:&nbsp; $value</span></div>"
        return """
<div class="oc-transcript">
  <div class="cert-title"><b>${d.t("name")}</b></div>
  <div class="row transcript-head">
    <div class="col">
      ${line("NAME", d.t("recipient.name"))}${line("COURSE", d.t("recipient.course"))}${line("NRIC/FIN", d.t("recipient.nric"))}${line("STUDENT ID", d.t("additionalData.studentId"))}
    </div>
    <div class="col">
      ${line("DOCUMENT ID", d.t("id"))}${line("DATE OF ISSUANCE", esc(monthYear(d.text("issuedOn"))))}${line("DATE OF ADMISSION", esc(monthYear(d.text("admissionDate"))))}${line("DATE OF GRADUATION", esc(monthYear(d.text("graduationDate"))))}
    </div>
  </div>
  $table
  <div class="row end">
    <div class="col">${if (govtech) "<div class=\"logo-text\">GovTech Singapore</div>" else ""}</div>
    <div class="col"></div>
    <div class="col center transcript-sign">
      ${d.img("additionalData.certSignatories[0].signature", "width:100%")}
      <hr>
      <div><b>${d.t("additionalData.certSignatories[0].name")}</b><br>${d.t("additionalData.certSignatories[0].position")}, ${d.t("additionalData.certSignatories[0].organisation")}</div>
    </div>
  </div>
</div>"""
    }

    private fun media(): String =
        "<div class=\"a4 pad\"><p>這個分頁是發證機構放在 YouTube 的介紹影片，需要網路，請改用「以發證機構樣式顯示」開啟。</p></div>"

    private const val MOE_BAND = "MINISTRY OF EDUCATION "

    private fun testimonial(d: Data): String {
        val band = "<div class=\"band\">${MOE_BAND.repeat(23).trim()}</div>"
        return """
<div class="a4 moe">
  <div class="moe-head center"><div class="logo-text">Ministry of Education crest</div><div class="title">Ministry of Education</div><div class="sub-title">Republic of Singapore</div></div>
  <div class="center moe-body">
    <div class="certificate">School Graduate Certificate</div>
    <div class="upper">The certificate is awarded to</div>
    <div class="recipient">${d.t("recipient.name")}</div>
    <div>Identification No: ${d.t("recipient.studentId")}</div>
    <div class="institute">${d.t("testimonial.instituteName")}</div>
    <div class="year">Year of Graduation: ${esc(d.text("testimonial.achievementDate")?.split("-")?.firstOrNull() ?: "")}</div>
    <div class="information"><div>This School Graduation Certificates provides a hlistic qualitative</div><div>assessment of the student's personal qualities, academic and co-curricular</div><div>development upon completion of the student's pre-university education.</div></div>
    <div class="row around">
      <div class="seal">${d.img("referee.seal", "width:4cm")}</div>
      <div class="signature">${d.img("referee.signature", "width:6cm;border-bottom:2px solid #b6b7b2;margin-bottom:0.25cm")}<div>${d.t("referee.designation")}</div></div>
    </div>
  </div>
  <div class="gold"></div>
</div>
<div class="a4 moe">
  <div class="row between moe-head2">
    <div><div class="type">Testimonial</div><div class="institute-sm">${d.t("testimonial.instituteName")}</div></div>
    <div class="center"><div class="logo-text">Ministry of Education crest</div><div class="title-sm">Ministry of Education</div><div class="sub-title-sm">Republic of Singapore</div></div>
  </div>
  $band
  <div class="content">${safeHtml(d.text("content") ?: "")}</div>
  $band
</div>"""
    }

    private fun testimonial2(d: Data): String {
        val date = d.text("issuedOn")?.let { isoDate(it) }?.let { "${it.day} ${MONTHS[it.month.ordinal]} ${it.year}" } ?: ""
        return """
<div class="a4">
  <div class="banner"><span class="logo-text">Header picture of the issuer</span></div>
  <div class="pad">
    <p class="date">${esc(date)}</p>
    <div class="content">${safeHtml(d.text("content") ?: "")}</div>
    <div>
      <div>${d.img("referee.signature", "width:100px")}</div>
      <div>${d.t("referee.name")}</div>
      <div>${d.t("referee.designation")}</div>
      <div>Mobile: ${d.t("referee.mobile")}</div>
      <div>Email: ${d.t("referee.email")}</div>
    </div>
  </div>
  <div class="address">${d.t("referee.address")}</div>
</div>"""
    }

    /** Null when the document lacks what the template requires (the demo renderer then shows nothing). */
    private fun certificateOfAward(d: Data): String? {
        val required = listOf("name", "recipient.name", "award.achievementArea", "award.instituteName", "signature.signature", "signature.name", "signature.designation")
        if (required.any { d.text(it) == null }) return null
        return """
<div class="a4">
  <div class="award-head"><span class="logo-text">Ministry of Education Singapore</span><span class="logo-text">Citizens' Consultative Committees</span></div>
  <div class="center award-body">
    <div class="certificate upper">${d.t("name")}</div>
    <div>is presented to</div>
    <div class="recipient upper">${d.t("recipient.name")}</div>
    <div>of</div>
    <div class="achievement upper">${d.t("award.achievementArea")}<br>in<br>${d.t("award.instituteName")}</div>
    <div class="information">for demonstrating leadership qualities, service to community and schools,<br>excellence in non-academic activities, and<br>good conduct</div>
    <div class="signature">${d.img("signature.signature", "width:6cm;border-bottom:2px solid #b6b7b2;margin-bottom:0.5cm", d.text("signature.name") ?: "signature")}<div class="upper">${d.t("signature.name")}<br>${d.t("signature.designation")}</div></div>
  </div>
  <div class="pad-x">ABC123456</div>
</div>"""
    }

    // ---------------------------------------------------------------- the wallet's own layout

    @OptIn(ExperimentalEncodingApi::class)
    private fun generic(v: OpenCertView): String = buildString {
        append("<div class=\"a4 pad generic\">")
        v.issuers.mapNotNull { it.name }.distinct().takeIf { it.isNotEmpty() }?.let { append("<div class=\"issuer\">").append(esc(it.joinToString("、"))).append("</div>") }
        v.images.firstOrNull { it.first == "標誌" }?.let { append(image(dataUrl(it.second), "max-height:2.5cm;max-width:60%")) }
        append("<h1>").append(esc(v.title ?: "OpenCerts 證書")).append("</h1>")
        fun table(title: String?, rows: List<Pair<String, String>>) {
            if (rows.isEmpty()) return
            title?.let { append("<h2>").append(esc(it)).append("</h2>") }
            append("<table class=\"fields\">")
            rows.forEach { (k, value) -> append("<tr><th>").append(esc(k)).append("</th><td>").append(esc(value)).append("</td></tr>") }
            append("</table>")
        }
        table("受領人", v.recipient)
        table("證書內容", v.main)
        if (v.transcript.isNotEmpty()) {
            append("<h2>成績單</h2><div class=\"scroll\"><table class=\"transcript\"><tr>")
            v.transcriptColumns.forEach { append("<th>").append(esc(it)).append("</th>") }
            append("</tr>")
            v.transcript.forEach { row -> append("<tr>"); row.forEach { append("<td>").append(esc(it)).append("</td>") }; append("</tr>") }
            append("</table></div>")
        }
        table("其他欄位", v.other)
        val pictures = v.images.filter { it.first != "標誌" }
        if (pictures.isNotEmpty()) {
            append("<h2>圖片</h2>")
            pictures.forEach { (name, bytes) -> append("<figure>").append(image(dataUrl(bytes), "max-width:100%;max-height:6cm")).append("<figcaption>").append(esc(name)).append("</figcaption></figure>") }
        }
        if (v.signatories.isNotEmpty()) {
            append("<div class=\"signatories\">")
            v.signatories.forEach { s ->
                append("<div class=\"signatory\">")
                s.image?.let { append(image(dataUrl(it), "max-width:5cm;max-height:2.5cm")) }
                append("<hr><b>").append(esc(s.name ?: "")).append("</b><br>")
                append(esc(listOfNotNull(s.position, s.organisation).joinToString(", ")))
                append("</div>")
            }
            append("</div>")
        }
        if (v.attachments.isNotEmpty()) {
            append("<h2>附件</h2><ul>")
            v.attachments.forEach { append("<li>").append(esc(it.name)).append("</li>") }
            append("</ul><p class=\"hint\">附件可在證書頁面存入文件或匯出。</p>")
        }
        append("</div>")
    }

    // ---------------------------------------------------------------- page

    private fun html(tabs: List<Pair<String, String>>, note: String): String = buildString {
        append("<!doctype html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\">")
        append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">")
        append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
        append("<title>").append(esc(tabs.first().first)).append("</title><style>").append(CSS)
        // One rule per tab: the checked radio shows its panel and marks its label.
        tabs.indices.forEach { i ->
            append("#t$i:checked~.panels #p$i{display:block}#t$i:checked~.tabs label[for=t$i]{background:#3f51b5;border-color:#3f51b5;color:#fff}")
        }
        append("</style></head><body><div class=\"note\">").append(esc(note)).append("</div>")
        tabs.indices.forEach { i -> append("<input type=\"radio\" name=\"tab\" id=\"t$i\"").append(if (i == 0) " checked" else "").append(">") }
        if (tabs.size > 1) {
            append("<div class=\"tabs\">")
            tabs.forEachIndexed { i, (label, _) -> append("<label for=\"t$i\">").append(esc(label)).append("</label>") }
            append("</div>")
        } else append("<div class=\"tabs\"></div>")
        append("<div class=\"panels\">")
        tabs.forEachIndexed { i, (_, body) -> append("<div class=\"panel\" id=\"p$i\">").append(body).append("</div>") }
        append("</div></body></html>")
    }

    private val CSS = """
body{margin:0;background:#fff;color:#1b1b1f;font-family:"Source Sans Pro",-apple-system,"Segoe UI",Roboto,"Noto Sans TC","PingFang TC","Microsoft JhengHei",sans-serif;line-height:1.5}
input[name=tab]{display:none}.panel{display:none}
.note{font-size:13px;color:#5d5e66;padding:8px 12px;background:#f3f3fa}
.tabs{display:flex;flex-wrap:wrap;gap:6px;padding:8px}
.tabs label{border:1px solid #c5c6d0;border-radius:16px;padding:6px 12px;font-size:14px;cursor:pointer}
.center{text-align:center}.right{text-align:right}.upper{text-transform:uppercase}
.row{display:flex;flex-wrap:wrap}.col{flex:1 1 0;min-width:0;padding:0 8px}.end{align-items:center}.around{justify-content:space-around}.between{justify-content:space-between;align-items:flex-end}
.logo-text{display:inline-block;border:1px dashed #9a9aa5;color:#5d5e66;padding:6px 12px;font-size:14px;border-radius:4px}
.oc-logo{font-size:28px;font-weight:bold;color:#324353;border-style:solid}
.oc-cert{max-width:297mm;margin:0 auto;border:10px solid #324353;padding:16px;background:linear-gradient(160deg,#fff 0%,#eef3f8 100%)}
.spacer{margin:24px}.text-sm{font-size:12px}.text-md{font-size:16px}.text-lg{font-size:24px}
@media (min-width:1024px){.spacer{margin:48px}.text-sm{font-size:21px}.text-md{font-size:26px}.text-lg{font-size:34px}}
.oc-transcript{max-width:1140px;margin:0 auto;padding:8px;background:#fafafa}
.cert-title{font-size:20px;padding:8px 3%}
.transcript-head{padding:3% 2%;font-size:14px}.kv{display:flex}.kv span:first-child{flex:1}.kv span:last-child{flex:1}
table.transcript{width:100%;border-collapse:collapse;font-size:14px;margin:8px 0}
table.transcript th,table.transcript td{border-bottom:1px solid #ddd;padding:4px;text-align:left;vertical-align:top}
.transcript-sign{padding-top:5%;font-size:14px}
.a4{background:#fff;max-width:21cm;min-height:29.7cm;margin:1cm auto;border:1px solid #d3d3d3;border-radius:5px;box-shadow:0 0 5px rgba(0,0,0,.1);position:relative}
.pad{padding:1cm 2cm}.pad-x{padding:0 2cm;height:2cm}
.moe{background:linear-gradient(176deg,#fff 0%,#f0fcff 100%)}
.moe-head{background:#fff;padding-top:1cm;height:7cm;border-bottom:1px solid #999c97}.moe-head .title{font-size:1.2rem;font-weight:bold;margin-top:12px}.moe-head .sub-title{font-size:1.1rem;font-weight:bold}
.moe-body .certificate{font-size:2rem;font-weight:bold;color:#80764f;margin:1.5cm 0}.moe-body .recipient{margin-top:1.5cm}.moe-body .institute{margin-bottom:.75cm}.moe-body .year,.moe-body .information{margin-bottom:1.5cm}
.gold{height:1cm;background:radial-gradient(circle,#a48b61 0%,#74644b 100%)}
.moe-head2{padding:0 2cm .5cm;background:#fff;min-height:4.5cm}.moe-head2 .type{font-size:1.2rem}.moe-head2 .institute-sm{font-size:.9rem}.title-sm{font-size:1.1rem;font-weight:bold}.sub-title-sm{font-size:.9rem;font-weight:bold}
.band{height:.5cm;background:radial-gradient(circle,#a48b61 0%,#74644b 100%);color:#fff;overflow:hidden;white-space:nowrap;font-size:.5rem;display:flex;align-items:center;justify-content:center}
.content{padding:1cm 2cm;text-align:justify}
.banner{height:5cm;background:linear-gradient(90deg,#e8eef7,#c9d6ea);display:flex;align-items:center;justify-content:center}
.date{padding:1cm 0}.address{background:#0072c6;color:#fff;min-height:1cm;margin:0 1cm 1cm;padding:0 1cm;display:flex;align-items:center}
.award-head{background:linear-gradient(90deg,#fff 0%,#b4bff5 100%);display:flex;align-items:center;justify-content:space-between;padding:0 2cm;height:3.5cm;border-bottom:1px solid #999c97}
.award-body{padding:0 2cm}.award-body .certificate{font-size:2rem;font-weight:bold;margin:1.5cm 0}.award-body .recipient{font-size:1.5rem;font-weight:bold;margin:.5cm 0}.award-body .achievement{margin-top:.5cm;margin-bottom:1.5cm}.award-body .information{margin:1.5cm 0}.award-body .signature{line-height:2rem}
.generic h1{font-size:24px;margin:12px 0}.generic h2{font-size:17px;margin:20px 0 6px;color:#3f51b5}.generic .issuer{color:#5d5e66;font-size:14px}
table.fields{border-collapse:collapse;width:100%;font-size:14px}table.fields th{text-align:left;font-weight:normal;color:#5d5e66;width:35%;padding:4px 8px 4px 0;vertical-align:top}table.fields td{padding:4px 0;word-break:break-word}
.scroll{overflow-x:auto}figure{margin:8px 0}figcaption{font-size:12px;color:#5d5e66}
.signatories{display:flex;flex-wrap:wrap;gap:24px;margin-top:24px}.signatory{min-width:5cm;font-size:14px}
.hint{font-size:13px;color:#5d5e66}
@media (max-width:600px){.a4{margin:8px;min-height:0}.pad{padding:16px}.content{padding:16px}.pad-x{padding:0 16px}.moe-head2,.award-head{padding-left:16px;padding-right:16px}.award-body{padding:0 16px}}
@media print{.note,.tabs{display:none}}
"""

    // ---------------------------------------------------------------- helpers

    private val MONTHS = listOf("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December")

    private fun two(n: Int) = n.toString().padStart(2, '0')

    /** The calendar date of an ISO date or date-time, as written (its own offset). */
    private fun isoDate(s: String): LocalDate? = runCatching { LocalDate.parse(s.trim().take(10)) }.getOrNull()

    /** "MMM YYYY" in Singapore time, upper case, as the demo transcript shows dates. */
    private fun monthYear(s: String?): String {
        if (s.isNullOrBlank()) return ""
        val date = runCatching { Instant.parse(s.trim()).toLocalDateTime(SINGAPORE).date }.getOrNull() ?: isoDate(s) ?: return ""
        return MONTHS[date.month.ordinal].take(3).uppercase() + " " + date.year
    }

    private val SINGAPORE: TimeZone = UtcOffset(hours = 8).asTimeZone()

    fun esc(s: String): String = buildString(s.length) {
        for (c in s) when (c) {
            '&' -> append("&amp;")
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '"' -> append("&quot;")
            '\'' -> append("&#39;")
            else -> append(c)
        }
    }

    private val DATA_IMAGE = Regex("^data:image/(png|jpe?g|gif|webp|svg\\+xml|bmp);base64,[A-Za-z0-9+/=\\s]+$", RegexOption.IGNORE_CASE)

    private fun image(src: String?, css: String = "", alt: String = ""): String {
        val s = src?.trim() ?: return ""
        if (!DATA_IMAGE.matches(s)) return ""
        return "<img src=\"${esc(s)}\" style=\"${esc(css)}\" alt=\"${esc(alt)}\">"
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun dataUrl(bytes: ByteArray): String {
        val type = when {
            bytes.size > 3 && bytes[0] == 0x89.toByte() && bytes[1] == 'P'.code.toByte() -> "png"
            bytes.size > 2 && bytes[0] == 0xFF.toByte() && bytes[1] == 0xD8.toByte() -> "jpeg"
            bytes.size > 3 && bytes[0] == 'G'.code.toByte() && bytes[1] == 'I'.code.toByte() -> "gif"
            bytes.size > 12 && bytes.copyOfRange(8, 12).decodeToString() == "WEBP" -> "webp"
            bytes.decodeToString(0, minOf(bytes.size, 256)).let { "<svg" in it || "<?xml" in it } -> "svg+xml"
            else -> "png"
        }
        return "data:image/$type;base64," + Base64.encode(bytes)
    }

    /**
     * Issuer HTML (testimonial content) without active content: scripts, frames, embedded objects, forms, styles that
     * could reach out, event handlers and script URLs are removed. The page's policy forbids scripts and remote loads
     * in any case; this keeps the markup inert where the policy is not honoured.
     */
    fun safeHtml(html: String): String {
        var s = html
        s = Regex("<(script|style|iframe|object|embed|form|link|meta|base|svg|math|template)\\b[^>]*>.*?</\\1\\s*>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)).replace(s, "")
        s = Regex("<(script|style|iframe|object|embed|form|link|meta|base|svg|math|template|input|button|textarea|select)\\b[^>]*>", RegexOption.IGNORE_CASE).replace(s, "")
        s = Regex("</(script|style|iframe|object|embed|form|svg|math|template|textarea|select|button)\\s*>", RegexOption.IGNORE_CASE).replace(s, "")
        s = Regex("\\s(on[a-z]+|style|srcset|formaction|xlink:href)\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)", RegexOption.IGNORE_CASE).replace(s, "")
        // Links and images keep only safe targets: https links and data: images.
        s = Regex("\\s(href|src|action|background|poster)\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)", RegexOption.IGNORE_CASE).replace(s) { m ->
            val value = m.groupValues[2].trim('"', '\'').trim()
            val ok = when (m.groupValues[1].lowercase()) {
                "href" -> value.startsWith("https://", true)
                "src" -> DATA_IMAGE.matches(value)
                else -> false
            }
            if (ok) " ${m.groupValues[1].lowercase()}=\"${esc(value)}\"" else ""
        }
        return s
    }
}

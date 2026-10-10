package diw.wallet.app

import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.util.DiwJson
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.multipaz.cbor.Cbor
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.X509Cert
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.revocation.RevocationStatus
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/** Technical details of a stored credential for the optional details view, as label and value pairs. */
object CredentialDetails {
    /** Specifications the credential was issued under: protocol, format and anything recorded during issuance. */
    fun specs(r: IssuanceRecord): List<String> {
        val protocol = if (r.specs.any { it.startsWith("OpenID4VCI") }) null else "OpenID4VCI 1.0"
        val format = when (r.format) {
            "mso_mdoc" -> "ISO/IEC 18013-5 mdoc"
            "dc+sd-jwt" -> "SD-JWT VC"
            "vc+sd-jwt" -> "SD-JWT VC draft (vc+sd-jwt)"
            else -> r.format
        }
        return listOfNotNull(protocol, format) + r.specs
    }

    fun issuance(r: IssuanceRecord): List<Pair<String, String>> = buildList {
        add("發行端" to r.credentialIssuer)
        add("設定 ID" to r.configurationId)
        add("格式" to r.format)
        r.vct?.let { add("vct" to it) }
        r.docType?.let { add("docType" to it) }
        add("規格" to specs(r).joinToString("、"))
        add("領取時間" to time(r.issuedAt))
        add("信任等級" to r.tier)
        r.environment?.let { add("信任環境" to it) }
        r.anchorName?.let { add("信任錨點" to it) }
        r.reasons.forEach { add("信任判斷" to it) }
        r.keyStorage?.let { add("金鑰保護" to it) }
        r.notificationId?.let { add("notification_id" to it) }
    }

    suspend fun credential(c: Credential): List<Pair<String, String>> = buildList {
        add("憑證 ID" to c.identifier)
        add("已使用次數" to c.usageCount.toString())
        // Multipaz records the epoch as validFrom when the credential gives no start.
        add("有效期間" to (if (c.validFrom.epochSeconds > 0) "${c.validFrom} 至 ${c.validUntil}" else "至 ${c.validUntil}"))
        if (c is SecureAreaBoundCredential) {
            add("金鑰位置" to c.secureArea.displayName)
            runCatching { c.secureArea.getKeyInfo(c.alias) }.getOrNull()?.let {
                add("金鑰演算法" to it.algorithm.name)
                add("金鑰曲線" to it.publicKey.curve.name)
            }
        }
        when (c) {
            is SdJwtVcCredential -> addAll(sdJwt(c.issuerProvidedData.decodeToString()))
            is MdocCredential -> addAll(mdoc(c.issuerProvidedData.toByteArray()))
            else -> {}
        }
    }

    private fun sdJwt(compact: String): List<Pair<String, String>> = buildList {
        val parts = compact.split('~')
        val jws = parts[0].split('.')
        val header = runCatching { DiwJson.parseToJsonElement(jws[0].fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
        val payload = runCatching { DiwJson.parseToJsonElement(jws[1].fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
        header?.let { h ->
            listOf("alg", "typ", "kid", "jku").forEach { k -> h.text(k)?.let { add("簽章標頭 $k" to it) } }
            (h["x5c"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }?.forEachIndexed { i, der ->
                runCatching { X509Cert(ByteString(der.fromBase64())) }.getOrNull()?.let { addAll(cert("x5c[$i]", it)) }
            }
        }
        payload?.let { p ->
            listOf("iss", "sub", "vct", "_sd_alg").forEach { k -> p.text(k)?.let { add(k to it) } }
            listOf("iat", "nbf", "exp").forEach { k -> (p[k] as? JsonPrimitive)?.longOrNull?.let { add(k to time(it)) } }
            ((p["status"] as? JsonObject)?.get("status_list") as? JsonObject)?.let { s ->
                add("狀態清單" to "${s.text("uri")} #${s["idx"]}")
            }
            ((p["cnf"] as? JsonObject)?.get("jwk") as? JsonObject)?.let { j -> add("持有者金鑰" to "${j.text("kty")} ${j.text("crv") ?: ""}".trim()) }
        }
        add("選擇性揭露項目數" to parts.drop(1).count { it.isNotEmpty() && '.' !in it }.toString())
    }

    private fun mdoc(issuerSigned: ByteArray): List<Pair<String, String>> = buildList {
        val signed = runCatching { Cbor.decode(issuerSigned) }.getOrNull() ?: return@buildList
        val auth = runCatching { signed["issuerAuth"].asCoseSign1 }.getOrNull() ?: return@buildList
        auth.protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_ALG)]?.asNumber?.toInt()?.let { id ->
            add("簽章演算法" to (runCatching { Algorithm.fromCoseAlgorithmIdentifier(id).name }.getOrNull() ?: id.toString()))
        }
        auth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]?.asX509CertChain?.certificates
            ?.forEachIndexed { i, c -> addAll(cert("x5chain[$i]", c)) }
        val mso = runCatching { MobileSecurityObject.fromDataItem(Cbor.decode(Cbor.decode(auth.payload!!).asTagged.asBstr)) }.getOrNull()
            ?: return@buildList
        add("MSO 版本" to mso.version)
        add("docType" to mso.docType)
        add("摘要演算法" to mso.digestAlgorithm.name)
        add("簽發時間" to mso.signedAt.toString())
        add("有效起日" to mso.validFrom.toString())
        add("有效迄日" to mso.validUntil.toString())
        mso.expectedUpdate?.let { add("預計更新" to it.toString()) }
        add("持有者金鑰" to mso.deviceKey.curve.name)
        when (val s = mso.revocationStatus) {
            is RevocationStatus.StatusList -> add("狀態清單" to "${s.uri} #${s.idx}")
            null -> {}
            else -> add("撤銷狀態機制" to (s::class.simpleName ?: "unknown"))
        }
    }

    /** Technical details of a presentation request for the consent screen. */
    fun request(req: ValidatedAuthorizationRequest): List<Pair<String, String>> = buildList {
        val v = req.verifier
        add("規格" to "OpenID4VP 1.0、DCQL" + if (req.responseMode.dcApi) "、Digital Credentials API" else "")
        add("client_id" to v.clientId.raw)
        if (v.effectiveClientId != v.clientId.raw) add("回應綁定的 client_id" to v.effectiveClientId)
        add("response_mode" to req.responseMode.wire)
        req.responseUri?.let { add("response_uri" to it) }
        add("nonce" to req.nonce)
        req.state?.let { add("state" to it) }
        if (req.expectedOrigins.isNotEmpty()) add("expected_origins" to req.expectedOrigins.joinToString())
        v.certificateChain?.certificates?.forEachIndexed { i, c -> addAll(cert("憑證[$i]", c)) }
        v.trust.reasons.forEach { add("信任判斷" to it) }
        req.verifierInfo.forEach { add("verifier_info" to it.format + if (it.credentialIds.isEmpty()) "" else "（${it.credentialIds.joinToString()}）") }
        req.clientMetadata?.keys?.takeIf { it.isNotEmpty() }?.let { add("client_metadata" to it.joinToString()) }
        add("DCQL 查詢" to req.dcqlQuery.toString())
    }

    private fun cert(name: String, c: X509Cert): List<Pair<String, String>> = listOf(
        "$name 主體" to c.subject.name,
        "$name 簽發者" to c.issuer.name,
        "$name 有效期間" to "${c.validityNotBefore} 至 ${c.validityNotAfter}",
    )

    private fun JsonObject.text(k: String): String? = (this[k] as? JsonPrimitive)?.content

    private fun time(epochSeconds: Long): String = Instant.fromEpochSeconds(epochSeconds).toString()
}

package diw.wallet.app

import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.W3cStatusEntry
import diw.wallet.core.w3c.W3cEncoding
import diw.wallet.core.w3c.W3cVcCredential
import diw.wallet.core.util.DiwJson
import diw.wallet.core.x509.displaySubject
import diw.wallet.core.x509.subjectAltNames
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.decodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.multipaz.asn1.ASN1
import org.multipaz.asn1.ASN1ObjectIdentifier
import org.multipaz.asn1.ASN1Sequence
import org.multipaz.asn1.ASN1TagClass
import org.multipaz.asn1.ASN1TaggedObject
import org.multipaz.cbor.Cbor
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.credential.Credential
import org.multipaz.credential.SecureAreaBoundCredential
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509KeyUsage
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.revocation.RevocationStatus
import org.multipaz.sdjwt.credential.SdJwtVcCredential
import org.multipaz.util.fromBase64
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import kotlin.time.Clock
import kotlin.time.Instant

/** One line of a details view; a row with [certs] opens the certificate view at [certIndex]. */
data class DetailRow(val label: String, val value: String, val certs: List<X509Cert> = emptyList(), val certIndex: Int = 0)

data class DetailSection(val title: String, val rows: List<DetailRow>)

/** Technical details of credentials, requests, status lists and certificates, grouped for the details views. */
object CredentialDetails {
    private val pretty = Json { prettyPrint = true }

    /** Format with its wire name, e.g. "SD-JWT VC（dc+sd-jwt）". */
    fun formatName(format: String): String = when (format) {
        "mso_mdoc" -> "ISO/IEC 18013-5 mdoc（mso_mdoc）"
        "dc+sd-jwt" -> "SD-JWT VC（dc+sd-jwt）"
        "vc+sd-jwt" -> "SD-JWT VC 草案（vc+sd-jwt）"
        "jwt_vc_json" -> "W3C VC，JWT（jwt_vc_json）"
        "jwt_vc_json-ld" -> "W3C VC，JWT 與 JSON-LD（jwt_vc_json-ld）"
        "ldp_vc" -> "W3C VC，Data Integrity（ldp_vc）"
        "jwt_vc" -> "W3C VC，JWT（jwt_vc，舊版草案）"
        else -> format
    }

    /** Format of a stored credential; TWDIW issues W3C credentials in SD-JWT under the vc+sd-jwt name. */
    fun formatName(r: IssuanceRecord): String =
        if (r.profile == "twdiw" && r.format == "vc+sd-jwt") "W3C VC，SD-JWT（vc+sd-jwt，TWDIW）" else formatName(r.format)

    /** Short format name for the credential list. */
    fun formatLabel(format: String): String = when (format) {
        "mso_mdoc" -> "mdoc"
        "dc+sd-jwt", "vc+sd-jwt" -> "SD-JWT VC"
        "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc", "jwt_vc" -> "W3C VC"
        else -> format
    }

    fun formatLabel(r: IssuanceRecord): String = if (r.profile == "twdiw") "W3C VC SD-JWT" else formatLabel(r.format)

    /** Specifications the credential was issued under: the protocol and anything recorded during issuance. */
    fun specs(r: IssuanceRecord): List<String> {
        val ownProtocol = r.profile == "msvid" || r.specs.any { it.startsWith("OpenID4VCI") }
        return listOfNotNull(if (ownProtocol) null else "OpenID4VCI 1.0") + r.specs
    }

    fun keyStorageName(wire: String): String = KeyProtection.entries.firstOrNull { it.wire == wire }?.displayName ?: wire

    suspend fun credential(r: IssuanceRecord?, c: Credential?): List<DetailSection> {
        val parsed = when (c) {
            is SdJwtVcCredential -> sdJwt(c.issuerProvidedData.decodeToString())
            is MdocCredential -> mdoc(c.issuerProvidedData.toByteArray())
            is W3cVcCredential -> w3c(c)
            else -> Parsed()
        }
        return listOf(
            DetailSection("發證資訊", buildList {
                r?.let {
                    add(DetailRow("發行端", it.credentialIssuer))
                    add(DetailRow("設定 ID", it.configurationId))
                    add(DetailRow("格式", formatName(it)))
                    it.vct?.let { v -> add(DetailRow("類型（vct）", v)) }
                    it.docType?.let { v -> add(DetailRow("類型（docType）", v)) }
                    add(DetailRow("規格", specs(it).joinToString("、")))
                    add(DetailRow("領取時間", time(it.issuedAt)))
                    it.notificationId?.let { v -> add(DetailRow("notification_id", v)) }
                }
                c?.let {
                    add(DetailRow("憑證 ID", it.identifier))
                    add(DetailRow("已使用次數", it.usageCount.toString()))
                }
            }),
            DetailSection("信任判斷", buildList {
                r?.let {
                    add(DetailRow("信任等級", it.tier))
                    it.environment?.let { v -> add(DetailRow("信任環境", v)) }
                    it.anchorName?.let { v -> add(DetailRow("信任錨點", v)) }
                    it.reasons.forEach { v -> add(DetailRow("判斷依據", v)) }
                }
            }),
            DetailSection("發行者簽章", parsed.signature + chainRows(parsed.chain)),
            DetailSection("有效期間", buildList {
                c?.let {
                    val from = if (it.validFrom.epochSeconds > 0) "${time(it.validFrom)} 至 " else "至 "
                    add(DetailRow("憑證有效期間", from + time(it.validUntil)))
                }
                addAll(parsed.validity)
            }),
            DetailSection("狀態清單", parsed.status),
            DetailSection("持有者金鑰", buildList {
                addAll(parsed.holderKey)
                if (c is SecureAreaBoundCredential) {
                    add(DetailRow("金鑰位置", c.secureArea.displayName))
                    runCatching { c.secureArea.getKeyInfo(c.alias) }.getOrNull()?.let {
                        add(DetailRow("簽章演算法", it.algorithm.name))
                    }
                    add(DetailRow("私鑰", "只存在金鑰位置內，無法匯出或顯示"))
                }
                if (c is W3cVcCredential) {
                    c.holderDid?.let { add(DetailRow("持有者 DID", it)) }
                    c.secureArea?.let { add(DetailRow("金鑰位置", it.displayName)) }
                    if (c.sharedKey) add(DetailRow("金鑰用途", "此服務的所有憑證共用同一把持有者金鑰（如官方皮夾的做法）"))
                    if (!c.keyBound) add(DetailRow("持有者綁定", "無（持有即可出示的憑證）"))
                    else add(DetailRow("私鑰", "只存在金鑰位置內，無法匯出或顯示"))
                }
                r?.keyStorage?.let { add(DetailRow("金鑰保護", keyStorageName(it))) }
            }),
            DetailSection("其他", parsed.other),
        ).filter { it.rows.isNotEmpty() }
    }

    private class Parsed(
        val signature: List<DetailRow> = emptyList(),
        val chain: List<X509Cert> = emptyList(),
        val validity: List<DetailRow> = emptyList(),
        val status: List<DetailRow> = emptyList(),
        val holderKey: List<DetailRow> = emptyList(),
        val other: List<DetailRow> = emptyList(),
    )

    private suspend fun sdJwt(compact: String): Parsed {
        val parts = compact.split('~')
        val jws = parts[0].split('.')
        val header = runCatching { DiwJson.parseToJsonElement(jws[0].fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
        val payload = runCatching { DiwJson.parseToJsonElement(jws[1].fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
        val chain = (header?.get("x5c") as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }
            ?.mapNotNull { runCatching { X509Cert(ByteString(it.fromBase64())) }.getOrNull() }.orEmpty()
        val signature = buildList {
            header?.text("alg")?.let { add(DetailRow("演算法（alg）", it)) }
            header?.text("typ")?.let { add(DetailRow("類型（typ）", it)) }
            header?.text("kid")?.let { add(DetailRow("金鑰 ID（kid）", it)) }
            header?.text("jku")?.let { add(DetailRow("金鑰集位置（jku）", it)) }
            payload?.text("iss")?.let { add(DetailRow("發行者（iss）", it)) }
        }
        val validity = listOf("iat" to "簽發時間（iat）", "nbf" to "生效時間（nbf）", "exp" to "到期時間（exp）").mapNotNull { (k, label) ->
            (payload?.get(k) as? JsonPrimitive)?.longOrNull?.let { DetailRow(label, time(it)) }
        }
        val statusList = (payload?.get("status") as? JsonObject)?.get("status_list") as? JsonObject
        val status = statusList?.let { statusReference(it.text("uri"), (it["idx"] as? JsonPrimitive)?.longOrNull) }.orEmpty()
        val jwk = (payload?.get("cnf") as? JsonObject)?.get("jwk") as? JsonObject
        val holderKey = jwk?.let { keyRows(runCatching { EcPublicKey.fromJwk(it) }.getOrNull(), it.text("kty")) }.orEmpty()
        val other = buildList {
            payload?.text("sub")?.let { add(DetailRow("主體（sub）", it)) }
            payload?.text("_sd_alg")?.let { add(DetailRow("揭露摘要演算法（_sd_alg）", it)) }
            add(DetailRow("選擇性揭露項目數", parts.drop(1).count { it.isNotEmpty() && '.' !in it }.toString()))
        }
        return Parsed(signature, chain, validity, status, holderKey, other)
    }

    /** W3C credentials: the JOSE header and claims of the JWT or SD-JWT, or the Data Integrity proof, plus credentialStatus. */
    private suspend fun w3c(c: W3cVcCredential): Parsed {
        val vc = runCatching { c.credentialJson() }.getOrNull()
        val status = vc?.let { W3cStatusEntry.parseAll(it) }.orEmpty().flatMap { e ->
            listOf(
                DetailRow("機制", e.type),
                DetailRow("用途（statusPurpose）", e.purpose),
                DetailRow("清單位置", e.listUrl),
                DetailRow("索引", e.index.toString()),
            )
        }
        val types = DetailRow("W3C 類型", c.types.joinToString())
        if (c.encoding == W3cEncoding.JSON_LD) {
            val proofs = when (val p = vc?.get("proof")) {
                is JsonObject -> listOf(p)
                is JsonArray -> p.filterIsInstance<JsonObject>()
                else -> emptyList()
            }
            val signature = proofs.flatMap { p ->
                listOfNotNull(
                    p.text("type")?.let { DetailRow("證明類型", it) },
                    p.text("cryptosuite")?.let { DetailRow("密碼套件（cryptosuite）", it) },
                    p.text("verificationMethod")?.let { DetailRow("驗證方法", it) },
                    p.text("created")?.let { DetailRow("建立時間", it) },
                )
            }
            val validity = listOfNotNull(
                vc?.text("validFrom")?.let { DetailRow("生效時間（validFrom）", it) },
                vc?.text("issuanceDate")?.let { DetailRow("簽發時間（issuanceDate）", it) },
                vc?.text("validUntil")?.let { DetailRow("到期時間（validUntil）", it) },
                vc?.text("expirationDate")?.let { DetailRow("到期時間（expirationDate）", it) },
            )
            return Parsed(signature, emptyList(), validity, status, emptyList(), listOf(types))
        }
        val base = sdJwt(c.raw)
        return Parsed(base.signature, base.chain, base.validity, status + base.status, base.holderKey, listOf(types) + base.other)
    }

    private suspend fun mdoc(issuerSigned: ByteArray): Parsed {
        val signed = runCatching { Cbor.decode(issuerSigned) }.getOrNull() ?: return Parsed()
        val auth = runCatching { signed["issuerAuth"].asCoseSign1 }.getOrNull() ?: return Parsed()
        val signature = buildList {
            auth.protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_ALG)]?.asNumber?.toInt()?.let { id ->
                add(DetailRow("演算法", runCatching { Algorithm.fromCoseAlgorithmIdentifier(id).name }.getOrNull() ?: id.toString()))
            }
        }
        val chain = auth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]?.asX509CertChain?.certificates.orEmpty()
        val mso = runCatching { MobileSecurityObject.fromDataItem(Cbor.decode(Cbor.decode(auth.payload!!).asTagged.asBstr)) }.getOrNull()
            ?: return Parsed(signature, chain)
        val validity = buildList {
            add(DetailRow("簽發時間（signed）", time(mso.signedAt)))
            add(DetailRow("生效時間（validFrom）", time(mso.validFrom)))
            add(DetailRow("到期時間（validUntil）", time(mso.validUntil)))
            mso.expectedUpdate?.let { add(DetailRow("預計更新（expectedUpdate）", time(it))) }
        }
        val status = when (val s = mso.revocationStatus) {
            is RevocationStatus.StatusList -> statusReference(s.uri, s.idx.toLong())
            null -> emptyList()
            else -> listOf(DetailRow("狀態機制", s::class.simpleName ?: "unknown"))
        }
        val other = listOf(
            DetailRow("MSO 版本", mso.version),
            DetailRow("docType", mso.docType),
            DetailRow("摘要演算法", mso.digestAlgorithm.name),
        )
        return Parsed(signature, chain, validity, status, keyRows(mso.deviceKey, "EC"), other)
    }

    private fun statusReference(uri: String?, idx: Long?): List<DetailRow> = listOfNotNull(
        DetailRow("機制", "Token Status List"),
        uri?.let { DetailRow("清單位置（uri）", it) },
        idx?.let { DetailRow("索引（idx）", it.toString()) },
    )

    /** Key type and JWK thumbprint (RFC 7638) instead of the raw key coordinates. */
    private suspend fun keyRows(key: EcPublicKey?, kty: String?): List<DetailRow> {
        if (key == null) return listOfNotNull(kty?.let { DetailRow("公鑰類型", it) })
        val thumbprint = runCatching { key.toJwkThumbprint(Algorithm.SHA256).toByteArray().toBase64Url() }.getOrNull()
        return listOfNotNull(
            DetailRow("公鑰類型", "${kty ?: "EC"} ${key.curve.name}"),
            thumbprint?.let { DetailRow("公鑰指紋（JWK SHA-256）", it) },
        )
    }

    private fun chainRows(chain: List<X509Cert>): List<DetailRow> = chain.mapIndexed { i, c ->
        val label = when {
            i == 0 -> "簽署憑證"
            i == chain.lastIndex && c.subject == c.issuer -> "根憑證"
            else -> "中繼憑證 ${i}"
        }
        DetailRow(label, c.displaySubject(), chain, i)
    }

    /** Parsed status after a status query, by the Token Status List terms. */
    fun status(s: CredentialStatus): List<DetailSection> {
        if (s.w3cEntries.isNotEmpty() || s.label != null) return w3cStatus(s)
        val value = s.code?.let { "${s.specName}（0x${it.toString(16).uppercase().padStart(2, '0')}）" }
        val token = s.list
        return listOf(
            DetailSection("狀態查詢結果", buildList {
                value?.let { add(DetailRow("狀態值", it)) }
                add(DetailRow("意義", statusMeaning(s.code) ?: (s.detail ?: "無法取得")))
                s.uri?.let { add(DetailRow("清單位置（uri）", it)) }
                s.index?.let { add(DetailRow("索引（idx）", it.toString())) }
                add(DetailRow("查詢時間", time(s.checkedAt)))
                add(DetailRow("清單簽章", assuranceText(s.assurance)))
                s.environment?.let { add(DetailRow("信任環境", it.id)) }
            }),
            DetailSection("狀態清單權杖", buildList {
                token?.let { t ->
                    add(DetailRow("每項位元數（bits）", t.bitsPerItem.toString()))
                    add(DetailRow("簽發時間（iat）", time(t.issuedAt)))
                    t.expiresAt?.let { add(DetailRow("到期時間（exp）", time(it))) }
                    t.ttl?.let { add(DetailRow("快取秒數（ttl）", it.toString())) }
                    t.anchorName?.let { add(DetailRow("信任錨點", it)) }
                    addAll(chainRows(t.signer))
                }
            }),
        ).filter { it.rows.isNotEmpty() }
    }

    /** W3C status lists: each credentialStatus entry by its statusPurpose and value as the specification names them. */
    private fun w3cStatus(s: CredentialStatus): List<DetailSection> {
        val overall = DetailSection("狀態查詢結果", buildList {
            s.label?.let { add(DetailRow("狀態", it)) }
            add(DetailRow("意義", stateMeaning(s.state)))
            s.detail?.let { add(DetailRow("說明", it)) }
            add(DetailRow("查詢時間", time(s.checkedAt)))
            add(DetailRow("清單簽章", assuranceText(s.assurance)))
            s.environment?.let { add(DetailRow("信任環境", it.id)) }
        })
        val entries = s.w3cEntries.mapIndexed { i, e ->
            DetailSection("狀態項目 ${i + 1}（${e.entry.purpose}）", buildList {
                add(DetailRow("機制", e.entry.type))
                add(DetailRow("狀態", e.label))
                e.value?.let { add(DetailRow("值", "0x" + it.toString(16).uppercase())) }
                add(DetailRow("意義", stateMeaning(e.state)))
                add(DetailRow("清單位置", e.entry.listUrl))
                add(DetailRow("索引", e.entry.index.toString()))
                add(DetailRow("清單簽章", assuranceText(e.assurance)))
                e.detail?.let { add(DetailRow("說明", it)) }
            })
        }
        return listOf(overall) + entries
    }

    /** How far the list's signature ties it to the issuer. */
    fun assuranceText(a: diw.wallet.core.status.StatusAssurance): String = when (a) {
        diw.wallet.core.status.StatusAssurance.TRUSTED -> "已驗證（金鑰綁定發行端或信任錨點）"
        diw.wallet.core.status.StatusAssurance.TLS_ONLY -> "已驗證，但金鑰只經 HTTPS 確認（jku 無法對應發行端）"
        diw.wallet.core.status.StatusAssurance.UNVERIFIED -> "未驗證"
    }

    fun stateMeaning(state: org.multipaz.revocation.RevocationCheckState): String = when (state) {
        org.multipaz.revocation.RevocationCheckState.VALID -> "有效"
        org.multipaz.revocation.RevocationCheckState.INVALID -> "無效（已撤銷）"
        org.multipaz.revocation.RevocationCheckState.SUSPENDED -> "暫停"
        else -> "無法判斷"
    }

    /** Short translation of a Token Status List value. */
    fun statusMeaning(code: Int?): String? = when (code) {
        null -> null
        0 -> "有效"
        1 -> "無效（已撤銷）"
        2 -> "暫停"
        3, in 12..15 -> "發行端自訂狀態"
        else -> "規格保留值"
    }

    /** Technical details of a presentation request for the consent screen. */
    fun request(req: ValidatedAuthorizationRequest): List<DetailSection> {
        val v = req.verifier
        val chain = v.certificateChain?.certificates.orEmpty()
        return listOf(
            DetailSection("請求", buildList {
                // The specification the request actually follows; OpenID4VP 1.0 with DCQL unless the request is older.
                val spec = req.specs.ifEmpty { listOf("OpenID4VP 1.0", "DCQL") } + if (req.responseMode.dcApi) listOf("Digital Credentials API") else emptyList()
                add(DetailRow("規格", spec.distinct().joinToString("、")))
                add(DetailRow("回應方式（response_mode）", req.responseMode.wire))
                req.responseUri?.let { add(DetailRow("回應位置（response_uri）", it)) }
                add(DetailRow("nonce", req.nonce))
                req.state?.let { add(DetailRow("state", it)) }
                if (req.expectedOrigins.isNotEmpty()) add(DetailRow("expected_origins", req.expectedOrigins.joinToString()))
                req.origin?.let { add(DetailRow("呼叫來源", it)) }
            }),
            DetailSection("驗證端身分", buildList {
                add(DetailRow("client_id", v.clientId.raw))
                if (v.effectiveClientId != v.clientId.raw) add(DetailRow("回應綁定的 client_id", v.effectiveClientId))
                v.trust.reasons.forEach { add(DetailRow("判斷依據", it)) }
                req.verifierInfo.forEach {
                    add(DetailRow("verifier_info", it.format + if (it.credentialIds.isEmpty()) "" else "（${it.credentialIds.joinToString()}）"))
                }
                req.clientMetadata?.keys?.takeIf { it.isNotEmpty() }?.let { add(DetailRow("client_metadata", it.joinToString())) }
                addAll(chainRows(chain))
            }),
            when {
                req.presentationDefinition != null -> DetailSection("要求內容（Presentation Exchange）",
                    listOf(DetailRow("presentation_definition", pretty.encodeToString(JsonElement.serializer(), req.presentationDefinition!!))))
                req.dcqlQuery.isNotEmpty() -> DetailSection("要求內容（DCQL）", listOf(DetailRow("查詢", pretty.encodeToString(JsonElement.serializer(), req.dcqlQuery))))
                else -> DetailSection("要求內容", emptyList())
            },
        ).filter { it.rows.isNotEmpty() }
    }

    /** X.509 certificate fields, grouped like common certificate viewers. */
    fun certificate(c: X509Cert): List<DetailSection> {
        val now = Clock.System.now()
        val state = when {
            now < c.validityNotBefore -> "尚未生效"
            now > c.validityNotAfter -> "已過期"
            else -> "有效期間內"
        }
        val san = runCatching { c.subjectAltNames() }.getOrNull()
        val known = setOf(OID_SKI, OID_AKI, OID_KEY_USAGE, OID_BASIC_CONSTRAINTS, OID_SAN, OID_EKU, OID_CRL_DP, OID_AIA)
        val extensions = runCatching { c.extensions }.getOrNull().orEmpty()
        return listOf(
            DetailSection("主體與簽發者", listOf(
                DetailRow("主體", c.subject.name),
                DetailRow("簽發者", c.issuer.name),
                DetailRow("自簽", if (c.subject == c.issuer) "是" else "否"),
            )),
            DetailSection("基本資訊", listOf(
                DetailRow("版本", "v${c.version + 1}"),
                DetailRow("序號", hex(c.serialNumber.value)),
                DetailRow("生效時間", time(c.validityNotBefore)),
                DetailRow("到期時間", time(c.validityNotAfter)),
                DetailRow("目前狀態", state),
                DetailRow("簽章演算法", runCatching { c.signatureAlgorithm.name }.getOrNull() ?: c.signatureAlgorithmOid),
            )),
            DetailSection("公鑰", listOfNotNull(
                runCatching { c.ecPublicKey.curve.name }.getOrNull()?.let { DetailRow("演算法與曲線", "EC $it") },
                runCatching { c.subjectKeyIdentifier }.getOrNull()?.let { DetailRow("主體金鑰識別碼", hex(it)) },
            )),
            DetailSection("擴充欄位", buildList {
                runCatching { c.keyUsage }.getOrNull()?.takeIf { it.isNotEmpty() }?.let { ku ->
                    add(DetailRow("金鑰用途", ku.sortedBy { it.bitNumber }.joinToString("、") { KEY_USAGE_NAMES[it] ?: it.description }))
                }
                runCatching { c.basicConstraints }.getOrNull()?.let { (ca, path) ->
                    add(DetailRow("基本限制", if (ca) "CA" + (path?.let { "，路徑長度 $it" } ?: "") else "非 CA"))
                }
                extendedKeyUsage(c)?.let { add(DetailRow("延伸金鑰用途", it)) }
                san?.let { s ->
                    if (s.dnsNames.isNotEmpty()) add(DetailRow("主體別名 DNS", s.dnsNames.joinToString()))
                    if (s.uris.isNotEmpty()) add(DetailRow("主體別名 URI", s.uris.joinToString()))
                    if (s.emails.isNotEmpty()) add(DetailRow("主體別名 Email", s.emails.joinToString()))
                }
                runCatching { c.authorityKeyIdentifier }.getOrNull()?.let { add(DetailRow("簽發者金鑰識別碼", hex(it))) }
                uris(c, OID_CRL_DP)?.let { add(DetailRow("CRL 發布點", it)) }
                uris(c, OID_AIA)?.let { add(DetailRow("授權資訊存取", it)) }
                extensions.filter { it.oid !in known }.forEach {
                    val name = EXTENSION_NAMES[it.oid]?.let { n -> "$n（${it.oid}）" } ?: it.oid
                    add(DetailRow("其他擴充", name + if (it.isCritical) "，關鍵" else ""))
                }
            }),
            DetailSection("指紋", listOf(DetailRow("SHA-256", hex(PlatformCrypto.sha256(c.encoded.toByteArray()))))),
        ).filter { it.rows.isNotEmpty() }
    }

    private fun extendedKeyUsage(c: X509Cert): String? {
        val bytes = c.getExtensionValue(OID_EKU) ?: return null
        val seq = runCatching { ASN1.decode(bytes) as? ASN1Sequence }.getOrNull() ?: return null
        return seq.elements.filterIsInstance<ASN1ObjectIdentifier>().joinToString("、") { EKU_NAMES[it.oid] ?: it.oid }.ifEmpty { null }
    }

    /** URIs (GeneralName tag 6) anywhere inside an extension, e.g. CRL distribution points and authority information access. */
    private fun uris(c: X509Cert, oid: String): String? {
        val bytes = c.getExtensionValue(oid) ?: return null
        val out = mutableListOf<String>()
        fun walk(o: Any?) {
            when (o) {
                is ASN1Sequence -> o.elements.forEach { walk(it) }
                is ASN1TaggedObject -> if (o.cls == ASN1TagClass.CONTEXT_SPECIFIC && o.tag == 6) {
                    out += o.content.decodeToString()
                } else runCatching { ASN1.decodeMultiple(o.content) }.getOrNull()?.forEach { walk(it) }
            }
        }
        runCatching { walk(ASN1.decode(bytes)) }
        return out.joinToString().ifEmpty { null }
    }

    private const val OID_SKI = "2.5.29.14"
    private const val OID_KEY_USAGE = "2.5.29.15"
    private const val OID_SAN = "2.5.29.17"
    private const val OID_BASIC_CONSTRAINTS = "2.5.29.19"
    private const val OID_CRL_DP = "2.5.29.31"
    private const val OID_AKI = "2.5.29.35"
    private const val OID_EKU = "2.5.29.37"
    private const val OID_AIA = "1.3.6.1.5.5.7.1.1"

    private val EXTENSION_NAMES = mapOf(
        "2.5.29.18" to "簽發者別名",
        "2.5.29.32" to "憑證政策",
        "2.5.29.30" to "名稱限制",
        "2.5.29.36" to "政策限制",
        "1.3.6.1.5.5.7.1.3" to "合格憑證聲明",
        "1.3.6.1.5.5.7.48.1.5" to "OCSP 免檢查",
    )

    private val KEY_USAGE_NAMES = mapOf(
        X509KeyUsage.DIGITAL_SIGNATURE to "數位簽章（digitalSignature）",
        X509KeyUsage.NON_REPUDIATION to "不可否認（nonRepudiation）",
        X509KeyUsage.KEY_ENCIPHERMENT to "金鑰加密（keyEncipherment）",
        X509KeyUsage.DATA_ENCIPHERMENT to "資料加密（dataEncipherment）",
        X509KeyUsage.KEY_AGREEMENT to "金鑰協商（keyAgreement）",
        X509KeyUsage.KEY_CERT_SIGN to "簽發憑證（keyCertSign）",
        X509KeyUsage.CRL_SIGN to "簽發 CRL（cRLSign）",
        X509KeyUsage.ENCIPHER_ONLY to "僅加密（encipherOnly）",
        X509KeyUsage.DECIPHER_ONLY to "僅解密（decipherOnly）",
    )

    private val EKU_NAMES = mapOf(
        "1.3.6.1.5.5.7.3.1" to "伺服器驗證",
        "1.3.6.1.5.5.7.3.2" to "用戶端驗證",
        "1.3.6.1.5.5.7.3.3" to "程式碼簽署",
        "1.3.6.1.5.5.7.3.4" to "電子郵件保護",
        "1.3.6.1.5.5.7.3.8" to "時間戳記",
        "1.3.6.1.5.5.7.3.9" to "OCSP 簽署",
        "1.0.18013.5.1.2" to "mdoc 文件簽署（DS）",
        "1.0.18013.5.1.6" to "mdoc 讀取端驗證",
        "1.0.18013.5.1.7" to "mdoc IACA",
        "1.0.18013.5.1.8" to "mdoc 讀取端 CA",
    )

    private fun hex(b: ByteArray): String = b.joinToString(":") { (it.toInt() and 0xff).toString(16).uppercase().padStart(2, '0') }

    private fun JsonObject.text(k: String): String? = (this[k] as? JsonPrimitive)?.content

    private fun time(epochSeconds: Long): String = Instant.fromEpochSeconds(epochSeconds).toString()

    /** Instants to the second; sub-second digits add nothing to the views. */
    private fun time(i: Instant): String = time(i.epochSeconds)
}

package diw.wallet.app

import diw.wallet.app.res.*
import diw.wallet.app.res.Res
import diw.wallet.core.jose.PlatformCrypto
import diw.wallet.core.oid4vci.IssuanceRecord
import diw.wallet.core.oid4vp.ValidatedAuthorizationRequest
import diw.wallet.core.profile.bonds.MoicaSignedCredential
import diw.wallet.core.profile.bonds.MoicaVerification
import diw.wallet.core.status.CredentialStatus
import diw.wallet.core.status.W3cStatusEntry
import diw.wallet.core.w3c.SdJwtDisclosures
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
        "mso_mdoc" -> tr(Res.string.fmt_mso_mdoc)
        "dc+sd-jwt" -> tr(Res.string.fmt_dc_sd_jwt)
        "vc+sd-jwt" -> tr(Res.string.fmt_vc_sd_jwt)
        "jwt_vc_json" -> tr(Res.string.fmt_jwt_vc_json)
        "jwt_vc_json-ld" -> tr(Res.string.fmt_jwt_vc_json_ld)
        "ldp_vc" -> tr(Res.string.fmt_ldp_vc)
        "jwt_vc" -> tr(Res.string.fmt_jwt_vc)
        else -> format
    }

    /** Format of a stored credential; TWDIW issues W3C credentials in SD-JWT under the vc+sd-jwt name. */
    fun formatName(r: IssuanceRecord): String =
        if (r.profile == "twdiw" && r.format == "vc+sd-jwt") tr(Res.string.fmt_twdiw) else formatName(r.format)

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
        // Microsoft Verified ID and credentials the wallet makes itself are not issued over OpenID4VCI.
        val ownProtocol = r.profile == "msvid" || r.profile == FilesModel.PROFILE || r.specs.any { it.startsWith("OpenID4VCI") }
        // Cards issued before the fix recorded TWDIW for any W3C or DID-keyed credential; only TWDIW sessions keep it.
        val recorded = if (r.profile == "twdiw") r.specs else r.specs.filter { it != "TWDIW" }
        return listOfNotNull(if (ownProtocol) null else "OpenID4VCI 1.0") + recorded
    }

    fun clientAuthName(method: String): String = when (method) {
        "attest_jwt_client_auth" -> tr(Res.string.auth_attest)
        "private_key_jwt" -> tr(Res.string.auth_private_key)
        "none" -> tr(Res.string.auth_public)
        else -> method
    }

    fun tokenTypeName(type: String): String =
        if (type.equals("DPoP", true)) tr(Res.string.token_dpop) else tr(Res.string.token_unbound, type)

    fun keyStorageName(wire: String): String = KeyProtection.entries.firstOrNull { it.wire == wire }?.displayName ?: wire

    suspend fun credential(r: IssuanceRecord?, c: Credential?): List<DetailSection> {
        val parsed = when (c) {
            is SdJwtVcCredential -> sdJwt(c.issuerProvidedData.decodeToString())
            is MdocCredential -> mdoc(c.issuerProvidedData.toByteArray())
            is W3cVcCredential -> w3c(c)
            else -> Parsed()
        }
        return listOf(
            DetailSection(tr(Res.string.cd_issuance), buildList {
                r?.let {
                    add(DetailRow(tr(Res.string.role_issuer), it.credentialIssuer))
                    add(DetailRow(tr(Res.string.cd_configuration_id), it.configurationId))
                    add(DetailRow(tr(Res.string.credential_format), formatName(it)))
                    it.vct?.let { v -> add(DetailRow(tr(Res.string.cd_type_vct), v)) }
                    it.docType?.let { v -> add(DetailRow(tr(Res.string.cd_type_doctype), v)) }
                    add(DetailRow(tr(Res.string.credential_specs), specs(it).joinToString(tr(Res.string.sep_list))))
                    it.clientAuthentication?.let { v -> add(DetailRow(tr(Res.string.cd_client_auth), clientAuthName(v))) }
                    it.tokenType?.let { v -> add(DetailRow(tr(Res.string.cd_access_token), tokenTypeName(v))) }
                    add(DetailRow(tr(Res.string.cd_received_at), time(it.issuedAt)))
                    it.notificationId?.let { v -> add(DetailRow("notification_id", v)) }
                }
                c?.let {
                    add(DetailRow(tr(Res.string.cd_credential_id), it.identifier))
                    add(DetailRow(tr(Res.string.cd_usage_count), it.usageCount.toString()))
                }
            }),
            DetailSection(tr(Res.string.cd_trust), buildList {
                r?.let {
                    add(DetailRow(tr(Res.string.cd_trust_level), it.tier))
                    it.environment?.let { v -> add(DetailRow(tr(Res.string.cd_trust_env), v)) }
                    it.anchorName?.let { v -> add(DetailRow(tr(Res.string.cd_trust_anchor), v)) }
                    it.reasons.forEach { v -> add(DetailRow(tr(Res.string.cd_reason), v)) }
                }
            }),
            DetailSection(tr(Res.string.cd_issuer_signature), parsed.signature + chainRows(parsed.chain)),
            DetailSection(tr(Res.string.reader_validity), buildList {
                c?.let {
                    val from = if (it.validFrom.epochSeconds > 0) tr(Res.string.cd_from_to, time(it.validFrom)) else tr(Res.string.cd_to)
                    add(DetailRow(tr(Res.string.cd_cert_validity), from + time(it.validUntil)))
                }
                addAll(parsed.validity)
            }),
            DetailSection(tr(Res.string.role_status_list), parsed.status),
            DetailSection(tr(Res.string.cd_holder_key), buildList {
                addAll(parsed.holderKey)
                if (c is SecureAreaBoundCredential) {
                    add(DetailRow(tr(Res.string.cd_key_location), c.secureArea.displayName))
                    runCatching { c.secureArea.getKeyInfo(c.alias) }.getOrNull()?.let {
                        add(DetailRow(tr(Res.string.cd_sig_alg), it.algorithm.name))
                    }
                    add(DetailRow(tr(Res.string.cd_private_key), tr(Res.string.cd_private_key_value)))
                }
                if (c is W3cVcCredential) {
                    c.holderDid?.let { add(DetailRow(tr(Res.string.cd_holder_did), it)) }
                    c.secureArea?.let { add(DetailRow(tr(Res.string.cd_key_location), it.displayName)) }
                    if (c.sharedKey) add(DetailRow(tr(Res.string.cd_key_use), tr(Res.string.cd_shared_key)))
                    if (!c.keyBound) add(DetailRow(tr(Res.string.cd_holder_binding), tr(Res.string.cd_no_binding)))
                    else add(DetailRow(tr(Res.string.cd_private_key), tr(Res.string.cd_private_key_value)))
                }
                r?.keyStorage?.let { add(DetailRow(tr(Res.string.credential_key_protection), keyStorageName(it))) }
            }),
            DetailSection(tr(Res.string.cd_other), parsed.other),
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
            header?.text("alg")?.let { add(DetailRow(tr(Res.string.cd_alg), it)) }
            header?.text("typ")?.let { add(DetailRow(tr(Res.string.cd_typ), it)) }
            header?.text("kid")?.let { add(DetailRow(tr(Res.string.cd_kid), it)) }
            header?.text("jku")?.let { add(DetailRow(tr(Res.string.cd_jku), it)) }
            payload?.text("iss")?.let { add(DetailRow(tr(Res.string.cd_iss), it)) }
        }
        val validity = listOf("iat" to tr(Res.string.cd_iat), "nbf" to tr(Res.string.cd_nbf), "exp" to tr(Res.string.cd_exp)).mapNotNull { (k, label) ->
            (payload?.get(k) as? JsonPrimitive)?.longOrNull?.let { DetailRow(label, time(it)) }
        }
        val statusList = (payload?.get("status") as? JsonObject)?.get("status_list") as? JsonObject
        val status = statusList?.let { statusReference(it.text("uri"), (it["idx"] as? JsonPrimitive)?.longOrNull) }.orEmpty()
        val jwk = (payload?.get("cnf") as? JsonObject)?.get("jwk") as? JsonObject
        val holderKey = jwk?.let { keyRows(runCatching { EcPublicKey.fromJwk(it) }.getOrNull(), it.text("kty")) }.orEmpty()
        val other = buildList {
            payload?.text("sub")?.let { add(DetailRow(tr(Res.string.cd_sub), it)) }
            payload?.text("_sd_alg")?.let { add(DetailRow(tr(Res.string.cd_sd_alg), it)) }
            add(DetailRow(tr(Res.string.cd_disclosure_count), parts.drop(1).count { it.isNotEmpty() && '.' !in it }.toString()))
        }
        return Parsed(signature, chain, validity, status, holderKey, other)
    }

    /** W3C credentials: the JOSE header and claims of the JWT or SD-JWT, or the Data Integrity proof, plus credentialStatus. */
    private suspend fun w3c(c: W3cVcCredential): Parsed {
        val vc = runCatching { c.credentialJson() }.getOrNull()
        val status = vc?.let { W3cStatusEntry.parseAll(it) }.orEmpty().flatMap { e ->
            listOf(
                DetailRow(tr(Res.string.cd_mechanism), e.type),
                DetailRow(tr(Res.string.cd_status_purpose), e.purpose),
                DetailRow(tr(Res.string.cd_list_location), e.listUrl),
                DetailRow(tr(Res.string.cd_index), e.index.toString()),
            )
        }
        val types = DetailRow(tr(Res.string.cd_w3c_type), c.types.joinToString())
        if (c.encoding == W3cEncoding.JSON_LD) {
            val proofs = when (val p = vc?.get("proof")) {
                is JsonObject -> listOf(p)
                is JsonArray -> p.filterIsInstance<JsonObject>()
                else -> emptyList()
            }
            val signature = proofs.flatMap { p ->
                listOfNotNull(
                    p.text("type")?.let { DetailRow(tr(Res.string.cd_proof_type), it) },
                    p.text("cryptosuite")?.let { DetailRow(tr(Res.string.cd_cryptosuite), it) },
                    p.text("verificationMethod")?.let { DetailRow(tr(Res.string.cd_verification_method), it) },
                    p.text("created")?.let { DetailRow(tr(Res.string.cd_created), it) },
                )
            }
            val validity = listOfNotNull(
                vc?.text("validFrom")?.let { DetailRow(tr(Res.string.cd_valid_from), it) },
                vc?.text("issuanceDate")?.let { DetailRow(tr(Res.string.cd_issuance_date), it) },
                vc?.text("validUntil")?.let { DetailRow(tr(Res.string.cd_valid_until), it) },
                vc?.text("expirationDate")?.let { DetailRow(tr(Res.string.cd_expiration_date), it) },
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
                add(DetailRow(tr(Res.string.cd_algorithm), runCatching { Algorithm.fromCoseAlgorithmIdentifier(id).name }.getOrNull() ?: id.toString()))
            }
        }
        val chain = auth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]?.asX509CertChain?.certificates.orEmpty()
        val mso = runCatching { MobileSecurityObject.fromDataItem(Cbor.decode(Cbor.decode(auth.payload!!).asTagged.asBstr)) }.getOrNull()
            ?: return Parsed(signature, chain)
        val validity = buildList {
            add(DetailRow(tr(Res.string.cd_signed), time(mso.signedAt)))
            add(DetailRow(tr(Res.string.cd_valid_from), time(mso.validFrom)))
            add(DetailRow(tr(Res.string.cd_valid_until), time(mso.validUntil)))
            mso.expectedUpdate?.let { add(DetailRow(tr(Res.string.cd_expected_update), time(it))) }
        }
        val status = when (val s = mso.revocationStatus) {
            is RevocationStatus.StatusList -> statusReference(s.uri, s.idx.toLong())
            null -> emptyList()
            else -> listOf(DetailRow(tr(Res.string.cd_status_mechanism), s::class.simpleName ?: "unknown"))
        }
        val other = listOf(
            DetailRow(tr(Res.string.cd_mso_version), mso.version),
            DetailRow("docType", mso.docType),
            DetailRow(tr(Res.string.cd_digest_alg), mso.digestAlgorithm.name),
        )
        return Parsed(signature, chain, validity, status, keyRows(mso.deviceKey, "EC"), other)
    }

    private fun statusReference(uri: String?, idx: Long?): List<DetailRow> = listOfNotNull(
        DetailRow(tr(Res.string.cd_mechanism), "Token Status List"),
        uri?.let { DetailRow(tr(Res.string.cd_list_uri), it) },
        idx?.let { DetailRow(tr(Res.string.cd_list_idx), it.toString()) },
    )

    /** Key type and JWK thumbprint (RFC 7638) instead of the raw key coordinates. */
    private suspend fun keyRows(key: EcPublicKey?, kty: String?): List<DetailRow> {
        if (key == null) return listOfNotNull(kty?.let { DetailRow(tr(Res.string.cd_key_type), it) })
        val thumbprint = runCatching { key.toJwkThumbprint(Algorithm.SHA256).toByteArray().toBase64Url() }.getOrNull()
        return listOfNotNull(
            DetailRow(tr(Res.string.cd_key_type), "${kty ?: "EC"} ${key.curve.name}"),
            thumbprint?.let { DetailRow(tr(Res.string.cd_jwk_thumbprint), it) },
        )
    }

    private fun chainRows(chain: List<X509Cert>): List<DetailRow> = chain.mapIndexed { i, c ->
        val label = when {
            i == 0 -> tr(Res.string.reader_issuer_cert_signer)
            i == chain.lastIndex && c.subject == c.issuer -> tr(Res.string.certificate_trust_root_label)
            else -> tr(Res.string.cd_intermediate_n, i)
        }
        DetailRow(label, c.displaySubject(), chain, i)
    }

    /** Parsed status after a status query, by the Token Status List terms. */
    fun status(s: CredentialStatus): List<DetailSection> {
        if (s.w3cEntries.isNotEmpty() || s.label != null) return w3cStatus(s)
        val value = s.code?.let { tr(Res.string.cd_status_hex, s.specName.toString(), it.toString(16).uppercase().padStart(2, '0')) }
        val token = s.list
        return listOf(
            DetailSection(tr(Res.string.cd_status_result), buildList {
                value?.let { add(DetailRow(tr(Res.string.cd_status_value), it)) }
                add(DetailRow(tr(Res.string.cd_meaning), statusMeaning(s.code) ?: (s.detail ?: tr(Res.string.cd_unavailable))))
                s.uri?.let { add(DetailRow(tr(Res.string.cd_list_uri), it)) }
                s.index?.let { add(DetailRow(tr(Res.string.cd_list_idx), it.toString())) }
                add(DetailRow(tr(Res.string.cd_queried_at), time(s.checkedAt)))
                add(DetailRow(tr(Res.string.cd_list_signature), assuranceText(s.assurance)))
                s.environment?.let { add(DetailRow(tr(Res.string.cd_trust_env), it.id)) }
            }),
            DetailSection(tr(Res.string.cd_status_list_token), buildList {
                token?.let { t ->
                    add(DetailRow(tr(Res.string.cd_bits), t.bitsPerItem.toString()))
                    add(DetailRow(tr(Res.string.cd_iat), time(t.issuedAt)))
                    t.expiresAt?.let { add(DetailRow(tr(Res.string.cd_exp), time(it))) }
                    t.ttl?.let { add(DetailRow(tr(Res.string.cd_ttl), it.toString())) }
                    t.anchorName?.let { add(DetailRow(tr(Res.string.cd_trust_anchor), it)) }
                    addAll(chainRows(t.signer))
                }
            }),
        ).filter { it.rows.isNotEmpty() }
    }

    /** W3C status lists: each credentialStatus entry by its statusPurpose and value as the specification names them. */
    private fun w3cStatus(s: CredentialStatus): List<DetailSection> {
        val overall = DetailSection(tr(Res.string.cd_status_result), buildList {
            s.label?.let { add(DetailRow(tr(Res.string.field_status), it)) }
            add(DetailRow(tr(Res.string.cd_meaning), stateMeaning(s.state)))
            s.detail?.let { add(DetailRow(tr(Res.string.cd_note), it)) }
            add(DetailRow(tr(Res.string.cd_queried_at), time(s.checkedAt)))
            add(DetailRow(tr(Res.string.cd_list_signature), assuranceText(s.assurance)))
            s.environment?.let { add(DetailRow(tr(Res.string.cd_trust_env), it.id)) }
        })
        val entries = s.w3cEntries.mapIndexed { i, e ->
            DetailSection(tr(Res.string.cd_status_entry, i + 1, e.entry.purpose), buildList {
                add(DetailRow(tr(Res.string.cd_mechanism), e.entry.type))
                add(DetailRow(tr(Res.string.field_status), e.label))
                e.value?.let { add(DetailRow(tr(Res.string.cd_value), "0x" + it.toString(16).uppercase())) }
                add(DetailRow(tr(Res.string.cd_meaning), stateMeaning(e.state)))
                add(DetailRow(tr(Res.string.cd_list_location), e.entry.listUrl))
                add(DetailRow(tr(Res.string.cd_index), e.entry.index.toString()))
                add(DetailRow(tr(Res.string.cd_list_signature), assuranceText(e.assurance)))
                e.detail?.let { add(DetailRow(tr(Res.string.cd_note), it)) }
            })
        }
        return listOf(overall) + entries
    }

    /** How far the list's signature ties it to the issuer. */
    fun assuranceText(a: diw.wallet.core.status.StatusAssurance): String = when (a) {
        diw.wallet.core.status.StatusAssurance.TRUSTED -> tr(Res.string.cd_list_verified)
        diw.wallet.core.status.StatusAssurance.TLS_ONLY -> tr(Res.string.cd_list_https)
        diw.wallet.core.status.StatusAssurance.UNVERIFIED -> tr(Res.string.cd_list_unverified)
    }

    fun stateMeaning(state: org.multipaz.revocation.RevocationCheckState): String = when (state) {
        org.multipaz.revocation.RevocationCheckState.VALID -> tr(Res.string.cd_state_valid)
        org.multipaz.revocation.RevocationCheckState.INVALID -> tr(Res.string.cd_state_invalid)
        org.multipaz.revocation.RevocationCheckState.SUSPENDED -> tr(Res.string.cd_state_suspended)
        else -> tr(Res.string.cd_state_unknown)
    }

    /** Short translation of a Token Status List value. */
    fun statusMeaning(code: Int?): String? = when (code) {
        null -> null
        0 -> tr(Res.string.cd_state_valid)
        1 -> tr(Res.string.cd_state_invalid)
        2 -> tr(Res.string.cd_state_suspended)
        3, in 12..15 -> tr(Res.string.cd_state_issuer)
        else -> tr(Res.string.cd_state_reserved)
    }

    /** Technical details of a presentation request for the consent screen. */
    fun request(req: ValidatedAuthorizationRequest): List<DetailSection> {
        val v = req.verifier
        val chain = v.certificateChain?.certificates.orEmpty()
        return listOf(
            DetailSection(tr(Res.string.cd_request), buildList {
                // The specification the request actually follows; OpenID4VP 1.0 with DCQL unless the request is older.
                val spec = req.specs.ifEmpty { listOf("OpenID4VP 1.0", "DCQL") } + if (req.responseMode.dcApi) listOf("Digital Credentials API") else emptyList()
                add(DetailRow(tr(Res.string.credential_specs), spec.distinct().joinToString(tr(Res.string.sep_list))))
                add(DetailRow(tr(Res.string.cd_response_mode), req.responseMode.wire))
                req.responseUri?.let { add(DetailRow(tr(Res.string.cd_response_uri), it)) }
                add(DetailRow("nonce", req.nonce))
                req.state?.let { add(DetailRow("state", it)) }
                if (req.expectedOrigins.isNotEmpty()) add(DetailRow("expected_origins", req.expectedOrigins.joinToString()))
                req.origin?.let { add(DetailRow(tr(Res.string.cd_origin), it)) }
            }),
            DetailSection(tr(Res.string.cd_verifier_identity), buildList {
                add(DetailRow("client_id", v.clientId.raw))
                if (v.effectiveClientId != v.clientId.raw) add(DetailRow(tr(Res.string.cd_bound_client_id), v.effectiveClientId))
                v.trust.reasons.forEach { add(DetailRow(tr(Res.string.cd_reason), it)) }
                req.verifierInfo.forEach {
                    add(DetailRow("verifier_info", it.format + if (it.credentialIds.isEmpty()) "" else tr(Res.string.parenthesized, it.credentialIds.joinToString())))
                }
                req.clientMetadata?.keys?.takeIf { it.isNotEmpty() }?.let { add(DetailRow("client_metadata", it.joinToString())) }
                addAll(chainRows(chain))
            }),
            when {
                req.presentationDefinition != null -> DetailSection(tr(Res.string.cd_request_pe),
                    listOf(DetailRow("presentation_definition", pretty.encodeToString(JsonElement.serializer(), req.presentationDefinition!!))))
                req.dcqlQuery.isNotEmpty() -> DetailSection(tr(Res.string.cd_request_dcql), listOf(DetailRow(tr(Res.string.cd_query), pretty.encodeToString(JsonElement.serializer(), req.dcqlQuery))))
                else -> DetailSection(tr(Res.string.cd_request_content), emptyList())
            },
        ).filter { it.rows.isNotEmpty() }
    }

    /** X.509 certificate fields, grouped like common certificate viewers. */
    /**
     * A Bonds vc+moica card (national ID card, derived document card): the check just made, the credential, the
     * cardholder's signature with the citizen certificate, the issuer JWS and the disclosures with their digests.
     * [labels] names the claims.
     */
    fun moica(card: MoicaSignedCredential, check: Result<MoicaVerification>?, labels: Map<String, String>): List<DetailSection> {
        val c = runCatching { card.credential() }.getOrNull() ?: JsonObject(emptyMap())
        val payload = runCatching { card.payload.fromBase64Url() }.getOrNull() ?: ByteArray(0)
        val cert = runCatching { X509Cert(ByteString(card.certificate.fromBase64())) }.getOrNull()
        val committed = (c["_sd"] as? JsonArray)?.size
        val disclosures = card.disclosures.mapNotNull { runCatching { SdJwtDisclosures.decode(it) }.getOrNull() }
        fun list(k: String) = (c[k] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }?.joinToString(tr(Res.string.sep_list)) ?: c.text(k)
        val subject = c["credentialSubject"] as? JsonObject
        return listOf(
            DetailSection(tr(Res.string.cd_check_result), when {
                check == null -> listOf(DetailRow(tr(Res.string.field_status), tr(Res.string.cd_checking)))
                check.isSuccess -> check.getOrThrow().let { v ->
                    listOf(
                        DetailRow(tr(Res.string.cd_result), tr(Res.string.cd_moica_passed) + if (v.nameChecked) tr(Res.string.cd_name_match) else ""),
                        DetailRow(tr(Res.string.cd_cardholder), v.cardholderName),
                        DetailRow(tr(Res.string.cd_cert_serial), v.certificateSerialHex),
                        DetailRow(tr(Res.string.cd_disclosable), "${v.claims.size}" + if (v.withheldClaims > 0) tr(Res.string.cd_withheld, v.withheldClaims) else ""),
                    )
                }
                else -> listOf(DetailRow(tr(Res.string.cd_result), tr(Res.string.cd_failed) + (check.exceptionOrNull()?.message ?: tr(Res.string.cd_unknown_reason))))
            }),
            DetailSection(tr(Res.string.cd_credential_content), listOfNotNull(
                list("type")?.let { DetailRow(tr(Res.string.credential_type), it) },
                list("@context")?.let { DetailRow("@context", it) },
                c.text("issuer")?.let { DetailRow(tr(Res.string.oa_issuer), it) },
                subject?.text("id")?.let { DetailRow(tr(Res.string.cd_subject_id), it) },
                c.text("validFrom")?.let { DetailRow(tr(Res.string.cd_valid_from), it) },
                DetailRow(tr(Res.string.cd_valid_until), c.text("validUntil") ?: tr(Res.string.state_not_set)),
                committed?.let { DetailRow(tr(Res.string.cd_sd_commitments), tr(Res.string.cd_sd_count, it) + if (c["_sd_alg"] == null) tr(Res.string.cd_no_sd_alg) else "") },
                DetailRow("payload", tr(Res.string.cd_payload_size, payload.size)),
                DetailRow("payload SHA-256", hexPlain(PlatformCrypto.sha256(payload))),
            )),
            DetailSection(tr(Res.string.cd_moica_signature), listOfNotNull(
                DetailRow(tr(Res.string.cd_signature_structure), card.tbsConstruction),
                DetailRow(tr(Res.string.cd_signed_string), MoicaSignedCredential.TBS_PREFIX + hexPlain(PlatformCrypto.sha256(payload))),
                DetailRow(tr(Res.string.cd_sig_alg), tr(Res.string.cd_rs256)),
                DetailRow(tr(Res.string.cd_signature_value), tr(Res.string.cd_bytes, runCatching { card.signature.fromBase64().size }.getOrDefault(0))),
                cert?.let { DetailRow(tr(Res.string.reader_issuer_cert_signer), it.subject.name, listOf(it)) },
                cert?.let { DetailRow(tr(Res.string.cd_cert_issuer), it.issuer.name) },
                cert?.let { DetailRow(tr(Res.string.cd_cert_validity_period), tr(Res.string.range_from_to, time(it.validityNotBefore), time(it.validityNotAfter))) },
            )),
            DetailSection(tr(Res.string.cd_issuer_jws), card.issuerJws?.let { jws ->
                val header = runCatching { DiwJson.parseToJsonElement(jws.substringBefore('.').fromBase64Url().decodeToString()) as JsonObject }.getOrNull()
                listOfNotNull(
                    header?.text("alg")?.let { DetailRow(tr(Res.string.cd_algorithm), it) },
                    header?.text("typ")?.let { DetailRow("typ", it) },
                    header?.text("cty")?.let { DetailRow("cty", it) },
                    header?.text("kid")?.let { DetailRow(tr(Res.string.cd_key_kid), it) },
                    DetailRow(tr(Res.string.cd_covers), tr(Res.string.cd_same_bytes)),
                )
            } ?: listOf(DetailRow("issuerJWS", tr(Res.string.cd_old_bonds)))),
            DetailSection(tr(Res.string.cd_disclosures), disclosures.map { d ->
                DetailRow(d.name?.let { labels[it] ?: it } ?: tr(Res.string.cd_no_name), tr(Res.string.cd_hash) + d.digest)
            }),
        ).filter { it.rows.isNotEmpty() }
    }

    private fun hexPlain(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    fun certificate(c: X509Cert): List<DetailSection> {
        val now = Clock.System.now()
        val state = when {
            now < c.validityNotBefore -> tr(Res.string.cert_not_yet)
            now > c.validityNotAfter -> tr(Res.string.cert_expired)
            else -> tr(Res.string.cert_in_validity)
        }
        val san = runCatching { c.subjectAltNames() }.getOrNull()
        val known = setOf(OID_SKI, OID_AKI, OID_KEY_USAGE, OID_BASIC_CONSTRAINTS, OID_SAN, OID_EKU, OID_CRL_DP, OID_AIA)
        val extensions = runCatching { c.extensions }.getOrNull().orEmpty()
        return listOf(
            DetailSection(tr(Res.string.cert_subject_issuer), listOf(
                DetailRow(tr(Res.string.cert_subject), c.subject.name),
                DetailRow(tr(Res.string.cert_issuer), c.issuer.name),
                DetailRow(tr(Res.string.cert_self_signed), if (c.subject == c.issuer) tr(Res.string.answer_yes) else tr(Res.string.answer_no)),
            )),
            DetailSection(tr(Res.string.cert_basic), listOf(
                DetailRow(tr(Res.string.oa_version), "v${c.version + 1}"),
                DetailRow(tr(Res.string.cert_serial), hex(c.serialNumber.value)),
                DetailRow(tr(Res.string.cert_not_before), time(c.validityNotBefore)),
                DetailRow(tr(Res.string.cert_not_after), time(c.validityNotAfter)),
                DetailRow(tr(Res.string.cert_state), state),
                DetailRow(tr(Res.string.cd_sig_alg), if (c.signatureAlgorithmOid == SM3_WITH_SM2) tr(Res.string.cert_sm2_alg)
                    else runCatching { c.signatureAlgorithm.name }.getOrNull() ?: c.signatureAlgorithmOid),
            )),
            DetailSection(tr(Res.string.cert_public_key), listOfNotNull(
                (runCatching { c.ecPublicKey.curve.name }.getOrNull()?.let { "EC $it" }
                    ?: if (c.signatureAlgorithmOid == SM3_WITH_SM2) tr(Res.string.cert_sm2) else null)?.let { DetailRow(tr(Res.string.cert_alg_curve), it) },
                runCatching { c.subjectKeyIdentifier }.getOrNull()?.let { DetailRow(tr(Res.string.cert_ski), hex(it)) },
            )),
            DetailSection(tr(Res.string.cert_extensions), buildList {
                runCatching { c.keyUsage }.getOrNull()?.takeIf { it.isNotEmpty() }?.let { ku ->
                    add(DetailRow(tr(Res.string.cd_key_use), ku.sortedBy { it.bitNumber }.joinToString(tr(Res.string.sep_list)) { KEY_USAGE_NAMES[it] ?: it.description }))
                }
                runCatching { c.basicConstraints }.getOrNull()?.let { (ca, path) ->
                    add(DetailRow(tr(Res.string.cert_basic_constraints), if (ca) "CA" + (path?.let { tr(Res.string.cert_path_len, it) } ?: "") else tr(Res.string.cert_not_ca)))
                }
                extendedKeyUsage(c)?.let { add(DetailRow(tr(Res.string.cert_eku), it)) }
                san?.let { s ->
                    if (s.dnsNames.isNotEmpty()) add(DetailRow(tr(Res.string.cert_san_dns), s.dnsNames.joinToString()))
                    if (s.uris.isNotEmpty()) add(DetailRow(tr(Res.string.cert_san_uri), s.uris.joinToString()))
                    if (s.emails.isNotEmpty()) add(DetailRow(tr(Res.string.cert_san_email), s.emails.joinToString()))
                }
                runCatching { c.authorityKeyIdentifier }.getOrNull()?.let { add(DetailRow(tr(Res.string.cert_aki), hex(it))) }
                uris(c, OID_CRL_DP)?.let { add(DetailRow(tr(Res.string.cert_crl_dp), it)) }
                uris(c, OID_AIA)?.let { add(DetailRow(tr(Res.string.cert_aia), it)) }
                extensions.filter { it.oid !in known }.forEach {
                    val name = EXTENSION_NAMES[it.oid]?.let { n -> tr(Res.string.files_group_count, n, it.oid) } ?: it.oid
                    add(DetailRow(tr(Res.string.cert_other_ext), name + if (it.isCritical) tr(Res.string.cert_critical) else ""))
                }
            }),
            DetailSection(tr(Res.string.cert_fingerprint), listOf(DetailRow("SHA-256", hex(PlatformCrypto.sha256(c.encoded.toByteArray()))))),
        ).filter { it.rows.isNotEmpty() }
    }

    private fun extendedKeyUsage(c: X509Cert): String? {
        val bytes = c.getExtensionValue(OID_EKU) ?: return null
        val seq = runCatching { ASN1.decode(bytes) as? ASN1Sequence }.getOrNull() ?: return null
        return seq.elements.filterIsInstance<ASN1ObjectIdentifier>().joinToString(tr(Res.string.sep_list)) { EKU_NAMES[it.oid] ?: it.oid }.ifEmpty { null }
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
    /** SM3withSM2, the signature of Chinese national algorithm (GM/T) certificates. */
    private const val SM3_WITH_SM2 = "1.2.156.10197.1.501"

    private val EXTENSION_NAMES = mapOf(
        "2.5.29.18" to tr(Res.string.cert_ian),
        "2.5.29.32" to tr(Res.string.cert_policies),
        "2.5.29.30" to tr(Res.string.cert_name_constraints),
        "2.5.29.36" to tr(Res.string.cert_policy_constraints),
        "1.3.6.1.5.5.7.1.3" to tr(Res.string.cert_qc),
        "1.3.6.1.5.5.7.48.1.5" to tr(Res.string.cert_ocsp_nocheck),
    )

    private val KEY_USAGE_NAMES = mapOf(
        X509KeyUsage.DIGITAL_SIGNATURE to tr(Res.string.ku_digital_signature),
        X509KeyUsage.NON_REPUDIATION to tr(Res.string.ku_non_repudiation),
        X509KeyUsage.KEY_ENCIPHERMENT to tr(Res.string.ku_key_encipherment),
        X509KeyUsage.DATA_ENCIPHERMENT to tr(Res.string.ku_data_encipherment),
        X509KeyUsage.KEY_AGREEMENT to tr(Res.string.ku_key_agreement),
        X509KeyUsage.KEY_CERT_SIGN to tr(Res.string.ku_key_cert_sign),
        X509KeyUsage.CRL_SIGN to tr(Res.string.ku_crl_sign),
        X509KeyUsage.ENCIPHER_ONLY to tr(Res.string.ku_encipher_only),
        X509KeyUsage.DECIPHER_ONLY to tr(Res.string.ku_decipher_only),
    )

    private val EKU_NAMES = mapOf(
        "1.3.6.1.5.5.7.3.1" to tr(Res.string.eku_server),
        "1.3.6.1.5.5.7.3.2" to tr(Res.string.eku_client),
        "1.3.6.1.5.5.7.3.3" to tr(Res.string.eku_code),
        "1.3.6.1.5.5.7.3.4" to tr(Res.string.eku_email),
        "1.3.6.1.5.5.7.3.8" to tr(Res.string.role_timestamp),
        "1.3.6.1.5.5.7.3.9" to tr(Res.string.eku_ocsp),
        "1.0.18013.5.1.2" to tr(Res.string.eku_mdoc_ds),
        "1.0.18013.5.1.6" to tr(Res.string.eku_mdoc_reader),
        "1.0.18013.5.1.7" to "mdoc IACA",
        "1.0.18013.5.1.8" to tr(Res.string.eku_mdoc_reader_ca),
    )

    private fun hex(b: ByteArray): String = b.joinToString(":") { (it.toInt() and 0xff).toString(16).uppercase().padStart(2, '0') }

    private fun JsonObject.text(k: String): String? = (this[k] as? JsonPrimitive)?.content

    private fun time(epochSeconds: Long): String = Instant.fromEpochSeconds(epochSeconds).toString()

    /** Instants to the second; sub-second digits add nothing to the views. */
    private fun time(i: Instant): String = time(i.epochSeconds)
}

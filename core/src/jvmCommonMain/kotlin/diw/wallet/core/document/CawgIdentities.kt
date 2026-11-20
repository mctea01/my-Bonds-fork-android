package diw.wallet.core.document

import diw.wallet.core.did.DidDocument
import diw.wallet.core.document.c2pa.C2paCbor
import diw.wallet.core.document.c2pa.C2paCose
import diw.wallet.core.document.c2pa.C2paIdentity
import diw.wallet.core.document.c2pa.C2paManifest
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.c2pa.C2paStatus
import diw.wallet.core.document.c2pa.C2paStore
import diw.wallet.core.document.c2pa.C2paVerifiedIdentity
import diw.wallet.core.document.c2pa.C2paWriter
import diw.wallet.core.document.c2pa.JumbfSuperbox
import diw.wallet.core.i18n.ct
import diw.wallet.core.jose.verifySignature
import diw.wallet.core.status.W3cStatusEntry
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import diw.wallet.core.util.ProtocolException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.CertificatePolicies
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.revocation.RevocationCheckState
import java.math.BigInteger
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import kotlin.time.Instant

/** COSE_Sign1 signature checks shared by C2PA claim signatures and CAWG identity assertions. */
internal object CoseCrypto {
    /** Algorithms C2PA 13.2 allows: ES256/384/512, PS256/384/512, Ed25519. */
    val ALLOWED = setOf(-7, -35, -36, -37, -38, -39, -8)

    /** Verifies a COSE signature (ECDSA raw r||s, RSASSA-PSS or Ed25519) with the key of [signer]. */
    fun verify(algorithm: Int?, signature: ByteArray, toBeSigned: ByteArray, signer: X509CertificateHolder): Boolean {
        val key = JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(signer).publicKey
        val (name, sig) = when (algorithm) {
            -7 -> "SHA256withECDSA" to der(signature)
            -35 -> "SHA384withECDSA" to der(signature)
            -36 -> "SHA512withECDSA" to der(signature)
            -37, -38, -39 -> "RSASSA-PSS" to signature
            -8 -> "Ed25519" to signature
            else -> return false
        }
        val s = Signature.getInstance(name, Bc.provider)
        when (algorithm) {
            -37 -> s.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            -38 -> s.setParameter(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1))
            -39 -> s.setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
        }
        s.initVerify(key)
        s.update(toBeSigned)
        return runCatching { s.verify(sig) }.getOrDefault(false)
    }

    private fun der(raw: ByteArray): ByteArray {
        val half = raw.size / 2
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(0, half))))
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(half, raw.size))))
        return DERSequence(v).encoded
    }

    fun algorithmName(alg: Int?): String? = when (alg) {
        -7 -> "ES256"; -35 -> "ES384"; -36 -> "ES512"; -37 -> "PS256"; -38 -> "PS384"; -39 -> "PS512"; -8 -> "EdDSA"
        else -> alg?.let { "COSE $it" }
    }

    /**
     * What a v2 time stamp (sigTst2) of a COSE signature may cover: the countersignature structure over the CBOR
     * byte string of the signature (C2PA 10.3.2.5, as c2pa-rs writes it), over the bare signature value, or the value.
     */
    fun v2Covered(cose: C2paCose): List<ByteArray> = listOf(
        C2paManifests.counterSigned(cose.protectedBytes, C2paCbor.bstr(cose.signature)),
        C2paManifests.counterSigned(cose.protectedBytes, cose.signature),
        cose.signature,
    )
}

/**
 * Validates CAWG identity assertions (identity assertion 1.3): the CBOR structure and padding, the referenced
 * assertions and the hard binding, then the signature by its sig_type: X.509 (cawg.x509.cose, chains judged with
 * [TrustRole.DOCUMENT] and the CAWG trust model) or an identity claims aggregation credential (a W3C VC in a
 * COSE_Sign1 signed by the aggregator's DID). Results use the CAWG status codes with the assertion label as url.
 */
internal class CawgIdentities(private val pki: PkiSupport, private val checks: CmsChecks, private val trust: DocumentTrustSource) {

    private class Result(val label: String) {
        val statuses = ArrayList<C2paStatus>()
        val detail = ArrayList<String>()
        fun ok(code: String, explanation: String? = null) { statuses += C2paStatus(code, label, true, explanation) }
        fun fail(code: String, explanation: String? = null) { statuses += C2paStatus(code, label, false, explanation) }
        fun info(code: String, explanation: String? = null) { statuses += C2paStatus(code, label, false, explanation, informational = true) }
        val failures: List<C2paStatus> get() = statuses.filter { !it.success && !it.informational }
    }

    /** Every identity assertion of [m]; [claimTimestamp] is the claim signature's time stamp, the fallback time of signing. */
    suspend fun validate(store: C2paStore, m: C2paManifest, claimTimestamp: TimestampInfo?, now: Instant): List<C2paIdentity> =
        C2paManifests.identityBoxes(m).map { validate(store, m, it, claimTimestamp, now) }

    private suspend fun validate(store: C2paStore, m: C2paManifest, box: JumbfSuperbox, claimTimestamp: TimestampInfo?, now: Instant): C2paIdentity {
        val label = box.label ?: C2paWriter.IDENTITY_LABEL
        val r = Result(label)
        val parsed = parse(box)
        if (parsed == null) {
            r.fail("cawg.identity.cbor.invalid", ct("core_cawg_cbor_invalid"))
            return C2paIdentity("", emptyList(), signature = Check.FAIL, label = label, statuses = r.statuses)
        }
        val (payload, signature, pads) = parsed
        val sigType = (payload.getText("sig_type") as? Tstr)?.value ?: ""
        val roles = (payload.getText("role") as? CborArray)?.items.orEmpty().mapNotNull { (it as? Tstr)?.value }
        if (pads.any { p -> p.any { it != 0.toByte() } }) r.fail("cawg.identity.pad.invalid", ct("core_cawg_pad_invalid"))

        val refs = (payload.getText("referenced_assertions") as CborArray).items.mapNotNull { C2paManifests.hashedUri(it) }
        checkReferences(store, m, refs, r)

        val base = C2paIdentity(sigType, emptyList(), label = label, roles = roles, referenced = refs.map { it.url.substringAfterLast('/') })
        val result = when (sigType) {
            C2paWriter.X509_SIG_TYPE -> x509(payload, signature, r, base, claimTimestamp, now)
            ICA_SIG_TYPE -> aggregation(payload, signature, r, base, claimTimestamp, now)
            else -> {
                r.fail("cawg.identity.sig_type.unknown", ct("core_cawg_sig_type_unknown", sigType))
                base
            }
        }
        // Valid when nothing failed but the trust in the named actor; trusted when that holds too.
        val failures = r.failures
        val trustOnly = failures.all { it.code in TRUST_CODES }
        if (failures.isEmpty() && result.trusted) r.ok("cawg.identity.trusted")
        else if (trustOnly) r.ok("cawg.identity.well-formed")
        val check = when {
            failures.isEmpty() && result.trusted -> Check.PASS
            trustOnly -> Check.WARN
            else -> Check.FAIL
        }
        return result.copy(signature = check, statuses = r.statuses, detail = result.detail + r.detail, trusted = check == Check.PASS)
    }

    /** signer_payload, signature and the pads of the identity assertion, or null when its CBOR breaks the schema. */
    private fun parse(box: JumbfSuperbox): Triple<DataItem, ByteArray, List<ByteArray>>? = runCatching {
        val d = Cbor.decode(box.content("cbor") ?: return null) as? CborMap ?: return null
        val payload = d.getText("signer_payload") as? CborMap ?: return null
        if (payload.getText("referenced_assertions") !is CborArray || payload.getText("sig_type") !is Tstr) return null
        payload.getText("role")?.let { role -> if (role !is CborArray || role.items.any { it !is Tstr }) return null }
        val signature = (d.getText("signature") as? Bstr)?.value ?: return null
        val pad1 = (d.getText("pad1") as? Bstr)?.value ?: return null
        val pad2 = d.getText("pad2")?.let { (it as? Bstr)?.value ?: return null }
        Triple(payload as DataItem, signature, listOfNotNull(pad1, pad2))
    }.getOrNull()

    /**
     * Each reference must be an assertion of this claim or of a claim reached through its ingredients, with the same
     * hash; no reference twice; the manifest's own hard binding among them.
     */
    private fun checkReferences(store: C2paStore, m: C2paManifest, refs: List<diw.wallet.core.document.c2pa.C2paHashedUri>, r: Result) {
        val claimed = HashSet<String>()
        val seen = HashSet<String>()
        fun collect(manifest: C2paManifest) {
            if (!seen.add(manifest.label)) return
            manifest.assertionRefs.forEach { claimed += C2paManifests.absolute(manifest, it.url) + "|" + DocCryptoUtil.hex(it.hash) }
            C2paManifests.ingredients(store, manifest).mapNotNull { it.manifest?.let(store::manifest) }.forEach(::collect)
        }
        collect(m)
        val absolute = refs.map { C2paManifests.absolute(m, it.url) }
        if (absolute.size != absolute.toSet().size) r.fail("cawg.identity.assertion.duplicate", ct("core_cawg_duplicate"))
        refs.forEachIndexed { i, ref ->
            val box = store.resolve(ref.url, m)
            val matches = box != null && DocCrypto.digest(C2paManifests.jcaHash(ref.algorithm ?: m.algorithm), box.hashedBytes).contentEquals(ref.hash)
            if (!matches || (absolute[i] + "|" + DocCryptoUtil.hex(ref.hash)) !in claimed) {
                r.fail("cawg.identity.assertion.mismatch", ct("core_cawg_reference_mismatch", ref.url))
            }
        }
        val hard = C2paManifests.signedAssertions(m).firstOrNull { b -> HARD_BINDINGS.any { b.label?.startsWith(it) == true } }
        val hardUrl = hard?.let { C2paManifests.absolute(m, "self#jumbf=c2pa.assertions/${it.label}") }
        val referencedBindings = absolute.filter { u -> HARD_BINDINGS.any { u.substringAfterLast('/').startsWith(it) } }
        when {
            referencedBindings.isEmpty() -> r.fail("cawg.identity.hard_binding_missing", ct("core_cawg_hard_binding_missing"))
            hardUrl == null || hardUrl !in referencedBindings -> r.fail("cawg.identity.hard_binding_incorrect", ct("core_cawg_hard_binding_incorrect"))
        }
    }

    // ---------------------------------------------------------------- cawg.x509.cose

    private suspend fun x509(payload: DataItem, signature: ByteArray, r: Result, base: C2paIdentity, claimTimestamp: TimestampInfo?, now: Instant): C2paIdentity {
        val cose = runCatching { C2paManifests.cose(signature) }.getOrNull() ?: run {
            r.fail("cawg.x509.signature.mismatch", ct("core_c2pa_identity_unreadable"))
            return base
        }
        if (cose.algorithm !in CoseCrypto.ALLOWED) {
            r.fail("cawg.x509.algorithm.unsupported", ct("core_cawg_alg_unsupported", CoseCrypto.algorithmName(cose.algorithm) ?: "-"))
            return base
        }
        val holders = cose.chain.mapNotNull { Bc.holder(it) }
        val signer = holders.firstOrNull() ?: run {
            r.fail("cawg.x509.credential.untrusted", ct("core_c2pa_no_x5chain"))
            return base
        }
        // The payload is the core deterministic CBOR of signer_payload (CAWG 8.2); the stored order and the c2pa-rs
        // field order are tried as well, since validators re-encode it.
        val candidates = listOfNotNull(cose.payload, Cbor.encode(payload), deterministic(payload), c2paRsOrder(payload)).distinctBy { it.toList() }
        val valid = candidates.any { CoseCrypto.verify(cose.algorithm, cose.signature, C2paManifests.toBeSigned(cose.protectedBytes, it), signer) }
        if (valid) r.ok("cawg.x509.signature.validated") else r.fail("cawg.x509.signature.mismatch", ct("core_cawg_signature_mismatch"))

        // Time of signing: the assertion's own v2 time stamp, else the claim signature's.
        if (cose.timestamps.any { it.first == "sigTst" }) r.info("cawg.x509.time_stamp.malformed", ct("core_cawg_v1_timestamp"))
        val own = cose.timestamps.filter { it.first == "sigTst2" }
        val timestamp = when {
            own.size > 1 -> { r.info("cawg.x509.time_stamp.malformed", ct("core_cawg_many_timestamps")); null }
            own.size == 1 -> timestamp(own.single().second, CoseCrypto.v2Covered(cose), r, "cawg.x509")
            else -> null
        } ?: claimTimestamp?.takeIf { it.trusted }

        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val info = checks.evaluate(
            SignatureFormat.CAWG_X509, base.label ?: C2paWriter.IDENTITY_LABEL, CoseCrypto.algorithmName(cose.algorithm), signer, holders,
            if (valid) Check.PASS else Check.FAIL, null, timestamp, cose.ocsps, emptyList(), now, problems, notes, role = TrustRole.DOCUMENT,
        )
        val chainTrusted = info.trust?.let { "UNKNOWN_ANCHOR" !in it.labels && it.tier != "T4" } == true
        if (chainTrusted) r.ok("cawg.x509.credential.trusted", info.trust?.anchorName) else r.fail("cawg.x509.credential.untrusted", ct("core_c2pa_identity_untrusted"))

        val revocation = pki.revocation(signer, pki.buildChain(signer, holders).getOrNull(1), cose.ocsps, emptyList())
        val reference = timestamp?.time ?: now.epochSeconds
        when {
            revocation == null -> r.info("cawg.x509.ocsp.skipped", ct("core_cawg_ocsp_skipped"))
            revocation.revoked && (revocation.at == null || revocation.at <= reference) -> r.fail("cawg.identity.credential_revoked", revocation.reason)
            else -> r.ok("cawg.x509.ocsp.not_revoked", revocation.source)
        }
        val at = timestamp?.let { Instant.fromEpochSeconds(it.time) } ?: now
        val inside = pki.buildChain(signer, holders).all { PkiSupport.validAt(it, at) }
        if (!inside) r.fail("cawg.x509.signature.outside_validity", ct("core_cawg_outside_validity"))
        else if (timestamp == null) r.ok("cawg.x509.signature.inside_validity")

        // The CAWG trust model: id-kp-documentSigning, or (until 31 March 2027) S/MIME individual or organization
        // validated certificates with id-kp-emailProtection.
        val profile = cawgProfile(signer, timestamp, now)
        if (!profile) r.detail.add(ct("core_cawg_profile_missing"))
        val names = listOfNotNull(pki.cn(signer.subject), Bc.org(signer)).distinct()
        return base.copy(
            names = names,
            issuer = pki.cn(signer.issuer),
            x509 = info,
            trusted = chainTrusted && profile && valid,
        )
    }

    private fun cawgProfile(signer: X509CertificateHolder, timestamp: TimestampInfo?, now: Instant): Boolean {
        val ekus = runCatching {
            ExtendedKeyUsage.getInstance(signer.getExtension(Extension.extendedKeyUsage)?.parsedValue ?: return false).usages.map { it.id }
        }.getOrDefault(emptyList())
        if (DOCUMENT_SIGNING in ekus) return true
        if (EMAIL_PROTECTION !in ekus) return false
        val policies = runCatching {
            CertificatePolicies.getInstance(signer.getExtension(Extension.certificatePolicies)?.parsedValue ?: return false).policyInformation.map { it.policyIdentifier.id }
        }.getOrDefault(emptyList())
        if (policies.none { it in SMIME_POLICIES }) return false
        val issued = timestamp?.takeIf { it.trusted }?.time
        return now <= INTERIM_END || (issued != null && issued <= INTERIM_END.epochSeconds)
    }

    /** A sigTst2 token checked against the countersignature forms; null when it does not pass (codes say why). */
    private suspend fun timestamp(token: ByteArray, covered: List<ByteArray>, r: Result, prefix: String): TimestampInfo? {
        val tok = CmsChecks.tokenOf(token)
        val tries = covered.map { checks.timestamp(tok, it) }
        val best = tries.firstOrNull { it.imprint == Check.PASS } ?: tries.first()
        return when {
            best.signature != Check.PASS || best.imprint != Check.PASS -> {
                if (prefix == "cawg.ica") r.fail("cawg.ica.time_stamp.invalid", best.problems.firstOrNull()) else r.info("$prefix.time_stamp.mismatch", best.problems.firstOrNull())
                null
            }
            !best.trusted -> {
                if (prefix == "cawg.ica") r.fail("cawg.ica.time_stamp.invalid", best.tsa) else r.info("$prefix.time_stamp.untrusted", best.tsa)
                null
            }
            else -> {
                if (prefix == "cawg.ica") r.ok("cawg.ica.time_stamp.validated", best.tsa)
                else { r.ok("$prefix.time_stamp.trusted", best.tsa); r.ok("$prefix.time_stamp.validated", best.tsa) }
                best
            }
        }
    }

    // ---------------------------------------------------------------- cawg.identity_claims_aggregation

    private suspend fun aggregation(payload: DataItem, signature: ByteArray, r: Result, base: C2paIdentity, claimTimestamp: TimestampInfo?, now: Instant): C2paIdentity {
        val cose = runCatching { C2paManifests.cose(signature) }.getOrNull() ?: run {
            r.fail("cawg.ica.invalid_cose_sign1", ct("core_c2pa_identity_unreadable"))
            return base
        }
        if (cose.algorithm !in CoseCrypto.ALLOWED) r.fail("cawg.ica.invalid_alg", ct("core_cawg_alg_unsupported", CoseCrypto.algorithmName(cose.algorithm) ?: "-"))
        val contentType = runCatching { (Cbor.decode(cose.protectedBytes) as CborMap).items.entries.firstOrNull { (k, _) -> (k as? CborInt)?.asNumber == 3L }?.value as? Tstr }.getOrNull()?.value
        if (contentType != "application/vc") r.fail("cawg.ica.invalid_content_type", ct("core_cawg_content_type", contentType ?: "-"))

        val vc = cose.payload?.let { runCatching { DiwJson.parseToJsonElement(it.decodeToString()) as? JsonObject }.getOrNull() }
        if (vc == null || vc["@context"] == null || "VerifiableCredential" !in texts(vc["type"]) || vc["credentialSubject"] !is JsonObject || vc["issuer"] == null) {
            r.fail("cawg.ica.invalid_verifiable_credential", ct("core_cawg_vc_invalid"))
            return base
        }
        val subject = vc["credentialSubject"] as JsonObject
        val issuer = (vc["issuer"] as? JsonObject)?.text("id") ?: vc.text("issuer")
        val did = issuer?.takeIf { it.startsWith("did:") }
        if (did == null) r.fail("cawg.ica.invalid_issuer", ct("core_cawg_issuer_not_did", issuer ?: "-"))

        // The aggregator's key from its DID document's assertionMethod.
        var trusted = false
        var issuerTrust: TrustSummary? = null
        if (did != null) {
            val doc: DidDocument? = try {
                trust.resolveDid(did)
            } catch (e: ProtocolException) {
                if (e.code == "unsupported_did") r.fail("cawg.ica.did_unsupported_method", did.split(':').take(2).joinToString(":"))
                else r.fail("cawg.ica.did_unavailable", e.message)
                null
            } catch (e: Exception) {
                r.fail("cawg.ica.did_unavailable", e.message)
                null
            }
            if (doc != null) {
                val methods = doc.methods.filter { it.id in doc.assertionMethodIds || doc.assertionMethodIds.any { a -> it.id.endsWith(a.substringAfter('#', a)) && a.startsWith("#") } }
                if (methods.isEmpty()) r.fail("cawg.ica.invalid_did_document", ct("core_cawg_no_assertion_method"))
                else {
                    val alg = joseAlg(cose.algorithm)
                    val tbs = C2paManifests.toBeSigned(cose.protectedBytes, cose.payload!!)
                    val ok = alg != null && methods.any { mth -> runCatching { verifySignature(alg, mth.key, tbs, cose.signature) }.getOrDefault(false) }
                    if (!ok) r.fail("cawg.ica.signature_mismatch", ct("core_cawg_signature_mismatch"))
                }
            }
            val decision = runCatching { trust.decideDid(did, TrustRole.ISSUER) }.getOrNull()
            issuerTrust = decision?.let { TrustSummary.of(it) }
            trusted = decision != null && !PkiSupport.unknownAnchor(decision)
            if (!trusted) r.fail("cawg.ica.untrusted_issuer", ct("core_cawg_issuer_untrusted", did))
        }

        // v2 time stamp of the credential (v1 sigTst is ignored).
        val own = cose.timestamps.filter { it.first == "sigTst2" }
        val icaTime = own.firstOrNull()?.let { timestamp(it.second, CoseCrypto.v2Covered(cose), r, "cawg.ica") }

        // Validity range against now, the claim's time stamp and the credential's own time stamp.
        val references = listOfNotNull(now, claimTimestamp?.takeIf { it.trusted }?.let { Instant.fromEpochSeconds(it.time) }, icaTime?.let { Instant.fromEpochSeconds(it.time) })
        val validFrom = vc.text("validFrom") ?: vc.text("issuanceDate")
        val validUntil = vc.text("validUntil") ?: vc.text("expirationDate")
        if (validFrom == null) r.fail("cawg.ica.valid_from.missing", ct("core_cawg_valid_from_missing"))
        else {
            val from = runCatching { Instant.parse(validFrom) }.getOrNull()
            if (from == null || references.any { from > it }) r.fail("cawg.ica.valid_from.invalid", validFrom)
        }
        validUntil?.let { u ->
            val until = runCatching { Instant.parse(u) }.getOrNull()
            if (until == null || references.any { until < it }) r.fail("cawg.ica.valid_until.invalid", u)
        }

        // Revocation through credentialStatus.
        if (vc["credentialStatus"] != null && issuer != null) {
            val supported = W3cStatusEntry.parseAll(vc).filter { it.purpose == "revocation" }
            if (supported.isEmpty()) r.fail("cawg.ica.revocation.unsupported", ct("core_cawg_revocation_unsupported"))
            else {
                val status = runCatching { trust.w3cStatus(vc, issuer) }.getOrNull()
                when (status?.state) {
                    RevocationCheckState.VALID -> r.ok("cawg.ica.credential.not_revoked")
                    RevocationCheckState.INVALID -> r.fail("cawg.ica.credential.revoked", status.label ?: status.detail)
                    else -> r.fail("cawg.ica.revocation.unavailable", status?.detail)
                }
            }
        }

        // Binding: c2paAsset is the JSON form of signer_payload (byte strings in standard base64).
        val asset = subject["c2paAsset"]
        if (asset == null || asset != C2paManifests.toJson(payload)) r.fail("cawg.ica.signer_payload.mismatch", ct("core_cawg_payload_mismatch"))

        // Verified identities.
        val list = subject["verifiedIdentities"] as? JsonArray
        val identities = list.orEmpty().mapNotNull { verifiedIdentity(it) }
        if (list == null || list.isEmpty()) r.fail("cawg.ica.verified_identities.missing", ct("core_cawg_identities_missing"))
        else if (identities.size != list.size || list.any { !validIdentity(it) }) r.fail("cawg.ica.verified_identities.invalid", ct("core_cawg_identities_invalid"))

        val credentialFailures = r.failures.filter { it.code.startsWith("cawg.ica.") && it.code != "cawg.ica.untrusted_issuer" }
        if (credentialFailures.isEmpty() && trusted) r.ok("cawg.ica.credential_valid")
        val names = identities.mapNotNull { v ->
            val who = v.name ?: v.username ?: v.address ?: v.uri ?: return@mapNotNull null
            who + (v.providerName?.let { ct("core_parenthesized", it) } ?: "")
        }
        return base.copy(
            names = names,
            issuer = issuer,
            verifiedIdentities = identities,
            issuerTrust = issuerTrust,
            validFrom = validFrom,
            validUntil = validUntil,
            trusted = trusted,
        )
    }

    private fun verifiedIdentity(e: JsonElement): C2paVerifiedIdentity? {
        val o = e as? JsonObject ?: return null
        val provider = o["provider"] as? JsonObject
        return C2paVerifiedIdentity(
            type = o.text("type") ?: return null,
            name = o.text("name"),
            username = o.text("username"),
            address = o.text("address"),
            uri = o.text("uri"),
            method = o.text("method"),
            verifiedAt = o.text("verifiedAt"),
            providerId = provider?.text("id"),
            providerName = provider?.let { naturalLanguage(it["name"]) },
        )
    }

    /** The conditions of CAWG 1.3 section 9.1.2.4 on one verifiedIdentities entry. */
    private fun validIdentity(e: JsonElement): Boolean {
        val o = e as? JsonObject ?: return false
        val type = o.text("type")?.takeIf { it.isNotEmpty() } ?: return false
        for (k in listOf("name", "username", "address", "uri", "method")) {
            if (o[k] != null && o.text(k).isNullOrEmpty()) return false
        }
        when (type) {
            "cawg.document_verification" -> if (o.text("name") == null) return false
            "cawg.social_media" -> if (o.text("username") == null || o.text("uri") == null) return false
            "cawg.crypto_wallet" -> if (o.text("address") == null) return false
            "cawg.web_site" -> if (o.text("uri") == null) return false
        }
        if (runCatching { Instant.parse(o.text("verifiedAt") ?: return false) }.isFailure) return false
        val provider = o["provider"] as? JsonObject ?: return false
        if (naturalLanguage(provider["name"]).isNullOrEmpty()) return false
        return true
    }

    /** A natural language string: a plain string, a value object (@value) or a language map (the first value). */
    private fun naturalLanguage(e: JsonElement?): String? = when (e) {
        is JsonPrimitive -> e.contentOrNull
        is JsonObject -> e.text("@value") ?: e.values.firstNotNullOfOrNull { (it as? JsonPrimitive)?.contentOrNull }
        is JsonArray -> e.firstNotNullOfOrNull { naturalLanguage(it) }
        else -> null
    }

    private fun joseAlg(alg: Int?): String? = when (alg) {
        -7 -> "ES256"; -35 -> "ES384"; -36 -> "ES512"; -37 -> "PS256"; -38 -> "PS384"; -39 -> "PS512"; -8 -> "EdDSA"
        else -> null
    }

    // ---------------------------------------------------------------- encodings of signer_payload

    /** RFC 8949 4.2.1 core deterministic encoding: map keys sorted by their encoded bytes, at every level. */
    private fun deterministic(d: DataItem): ByteArray = when (d) {
        is CborMap -> C2paCbor.concat(listOf(C2paCbor.head(5, d.items.size.toLong())) +
            d.items.entries.map { (k, v) -> Cbor.encode(k) to deterministic(v) }.sortedWith { a, b -> C2paCbor.compareBytes(a.first, b.first) }.flatMap { listOf(it.first, it.second) })
        is CborArray -> C2paCbor.concat(listOf(C2paCbor.head(4, d.items.size.toLong())) + d.items.map(::deterministic))
        is Tagged -> C2paCbor.tag(d.tagNumber, deterministic(d.taggedItem))
        else -> Cbor.encode(d)
    }

    /** The c2pa-rs field order: referenced_assertions (url, alg, hash), sig_type, role. */
    private fun c2paRsOrder(payload: DataItem): ByteArray? = runCatching {
        val refs = (payload.getText("referenced_assertions") as CborArray).items.map { h ->
            val entries = listOf("url", "alg", "hash").mapNotNull { k -> h.getText(k)?.let { C2paCbor.tstr(k) to Cbor.encode(it) } }
            C2paCbor.rawMap(entries)
        }
        val entries = listOfNotNull(
            C2paCbor.tstr("referenced_assertions") to C2paCbor.array(refs),
            payload.getText("sig_type")?.let { C2paCbor.tstr("sig_type") to Cbor.encode(it) },
            payload.getText("role")?.let { C2paCbor.tstr("role") to Cbor.encode(it) },
        )
        C2paCbor.rawMap(entries)
    }.getOrNull()

    private fun DataItem.getText(key: String): DataItem? =
        (this as? CborMap)?.items?.entries?.firstOrNull { (k, _) -> (k as? Tstr)?.value == key }?.value

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

    private fun texts(e: JsonElement?): List<String> = when (e) {
        is JsonArray -> e.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        is JsonPrimitive -> listOfNotNull(e.contentOrNull)
        else -> emptyList()
    }

    companion object {
        const val ICA_SIG_TYPE = "cawg.identity_claims_aggregation"
        private val HARD_BINDINGS = listOf("c2pa.hash.data", "c2pa.hash.boxes", "c2pa.hash.bmff", "c2pa.hash.collection")
        private const val DOCUMENT_SIGNING = "1.3.6.1.5.5.7.3.36"
        private const val EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
        private val SMIME_POLICIES = setOf("2.23.140.1.5.2.2", "2.23.140.1.5.2.3", "2.23.140.1.5.3.2", "2.23.140.1.5.3.3", "2.23.140.1.5.4.2", "2.23.140.1.5.4.3")
        private val INTERIM_END = Instant.parse("2027-03-31T23:59:59Z")

        /** Failure codes that say only that the named actor's credential has no root of trust here. */
        private val TRUST_CODES = setOf("cawg.x509.credential.untrusted", "cawg.ica.untrusted_issuer")
    }
}

package diw.wallet.core.document

import diw.wallet.core.i18n.ct
import diw.wallet.core.document.c2pa.C2paInfo
import diw.wallet.core.document.c2pa.C2paManifest
import diw.wallet.core.document.c2pa.C2paManifestInfo
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.c2pa.C2paStatus
import diw.wallet.core.document.c2pa.C2paStore
import diw.wallet.core.trust.TrustRole
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.time.Instant

/**
 * Verifies the content credentials of a picture: every manifest's COSE claim signature with its certificate chain
 * (judged with [TrustRole.CONTENT], whose built-in anchors are the C2PA trust list) and time stamps, the hashed URIs
 * of the assertions, the active manifest's hard binding over the file, and CAWG identity assertions ([CawgIdentities]).
 * Results use the C2PA and CAWG specifications' status codes.
 */
internal class C2paSignatures(private val pki: PkiSupport, private val checks: CmsChecks, trust: DocumentTrustSource) {
    private val cawg = CawgIdentities(pki, checks, trust)


    suspend fun inspect(store: C2paStore, now: Instant): Pair<C2paInfo, SignatureInfo?> {
        val active = store.active
        var activeSignature: SignatureInfo? = null
        val infos = store.manifests.map { m ->
            val statuses = ArrayList<C2paStatus>()
            val isActive = m === active
            statuses += C2paManifests.assertionStatuses(store, m)
            val binding = if (isActive) C2paManifests.bindingStatus(store, m) else null
            binding?.let { statuses += it }
            val sig = claimSignature(m, statuses, binding, now)
            if (isActive) activeSignature = sig
            C2paManifestInfo(
                label = m.label,
                active = isActive,
                claimVersion = m.claimVersion,
                title = m.claim.text("dc:title"),
                format = m.claim.text("dc:format"),
                generator = C2paManifests.generator(m),
                instanceId = m.claim.text("instanceID"),
                signer = sig?.signerName ?: sig?.signer?.subject,
                signedAt = sig?.timestamp?.takeIf { it.imprint == Check.PASS }?.time,
                actions = C2paManifests.actions(m),
                ingredients = C2paManifests.ingredients(store, m),
                authors = C2paManifests.authors(m),
                identities = cawg.validate(store, m, sig?.timestamp, now),
                training = C2paManifests.training(m),
                assertions = C2paManifests.labels(m),
                statuses = statuses,
            )
        }.sortedByDescending { it.active }
        return C2paInfo(active?.label, infos, store.container) to activeSignature
    }

    private suspend fun claimSignature(m: C2paManifest, statuses: MutableList<C2paStatus>, binding: C2paStatus?, now: Instant): SignatureInfo? {
        val url = C2paManifests.absolute(m, "self#jumbf=c2pa.signature")
        val label = ct("core_c2pa_prefix") + (m.claim.text("dc:title") ?: m.label)
        val cose = m.cose ?: run {
            statuses += C2paStatus("claimSignature.missing", url, false, ct("core_c2pa_no_claim_sig"))
            return checks.failed(SignatureFormat.C2PA, label, ct("core_c2pa_claim_unsigned"))
        }
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val holders = cose.chain.mapNotNull { Bc.holder(it) }
        val signer = holders.firstOrNull()
        // The signature always covers the claim as parsed; an embedded payload that is not that claim is a mismatch.
        val payloadMismatch = cose.payload != null && !cose.payload.contentEquals(m.claimBytes)
        val valid = signer != null && !payloadMismatch && CoseCrypto.verify(cose.algorithm, cose.signature, C2paManifests.toBeSigned(cose.protectedBytes, m.claimBytes), signer)
        val why = when { signer == null -> ct("core_sig_no_signing_cert"); payloadMismatch -> ct("core_c2pa_payload_other"); else -> ct("core_c2pa_claim_sig_invalid") }
        statuses += if (valid) C2paStatus("claimSignature.validated", url, true)
        else C2paStatus("claimSignature.mismatch", url, false, why)
        if (!valid) problems.add(if (signer == null) ct("core_c2pa_no_x5chain") else "C2PA $why")

        val timestamp = cose.timestamps.firstOrNull()?.let { (header, token) ->
            val tok = CmsChecks.tokenOf(token)
            val covered = buildList {
                if (header == "sigTst2") addAll(CoseCrypto.v2Covered(cose))
                add(C2paManifests.counterSigned(cose.protectedBytes, m.claimBytes))
            }
            val tries = covered.map { checks.timestamp(tok, it) }
            tries.firstOrNull { it.imprint == Check.PASS } ?: tries.first()
        }
        if (timestamp != null) {
            statuses += if (timestamp.imprint == Check.PASS && timestamp.signature == Check.PASS) C2paStatus("timeStamp.validated", url, true, timestamp.tsa)
            else C2paStatus("timeStamp.mismatch", url, false, timestamp.problems.firstOrNull())
            statuses += if (timestamp.trusted) C2paStatus("timeStamp.trusted", url, true, timestamp.tsa)
            else C2paStatus("timeStamp.untrusted", url, false, timestamp.tsa)
        }

        val failedHashes = statuses.filter { !it.success && (it.code.endsWith(".mismatch") || it.code == "assertion.missing") && !it.code.startsWith("claimSignature") && !it.code.startsWith("timeStamp") }
        failedHashes.forEach { problems.add(it.explanation ?: it.code) }
        val integrity = when {
            !valid || failedHashes.isNotEmpty() -> Check.FAIL
            binding != null && !binding.success -> { notes.add(binding.explanation ?: ct("core_c2pa_no_hard_binding")); Check.WARN }
            else -> Check.PASS
        }
        notes.add(ct("core_c2pa_generator") + (C2paManifests.generator(m) ?: ct("core_c2pa_unstated_cap")))
        val info = checks.evaluate(
            SignatureFormat.C2PA, label, CoseCrypto.algorithmName(cose.algorithm), signer, holders, integrity, null, timestamp,
            cose.ocsps, emptyList(), now, problems, notes,
            coversWhole = binding?.let { if (it.success) true else if (it.code.endsWith("notChecked")) null else false },
            role = TrustRole.CONTENT,
        )
        info.trust?.let { t ->
            statuses += if ("UNKNOWN_ANCHOR" in t.labels || t.tier == "T4") C2paStatus("signingCredential.untrusted", url, false, ct("core_signing_cert_untrusted"))
            else C2paStatus("signingCredential.trusted", url, true, t.anchorName)
        }
        if (info.certificateValidity == Check.FAIL) statuses += C2paStatus("signingCredential.invalid", url, false, info.problems.lastOrNull())
        return info
    }

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull
}

package diw.wallet.core.document

import diw.wallet.core.document.c2pa.C2paCose
import diw.wallet.core.document.c2pa.C2paIdentity
import diw.wallet.core.document.c2pa.C2paInfo
import diw.wallet.core.document.c2pa.C2paManifest
import diw.wallet.core.document.c2pa.C2paManifestInfo
import diw.wallet.core.document.c2pa.C2paManifests
import diw.wallet.core.document.c2pa.C2paStatus
import diw.wallet.core.document.c2pa.C2paStore
import diw.wallet.core.trust.TrustRole
import diw.wallet.core.util.DiwJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tstr
import java.math.BigInteger
import java.security.PublicKey
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import kotlin.time.Instant

/**
 * Verifies the content credentials of a picture: every manifest's COSE claim signature with its certificate chain
 * (judged with [TrustRole.CONTENT], whose built-in anchors are the C2PA trust list) and time stamps, the hashed URIs
 * of the assertions, the active manifest's hard binding over the file, and CAWG X.509 identity assertions. Results
 * use the C2PA specification's status codes.
 */
internal class C2paSignatures(private val pki: PkiSupport, private val checks: CmsChecks) {

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
                identities = identities(store, m, now),
                training = C2paManifests.training(m),
                assertions = C2paManifests.labels(m),
                statuses = statuses,
            )
        }.sortedByDescending { it.active }
        return C2paInfo(active?.label, infos, store.container) to activeSignature
    }

    private suspend fun claimSignature(m: C2paManifest, statuses: MutableList<C2paStatus>, binding: C2paStatus?, now: Instant): SignatureInfo? {
        val url = C2paManifests.absolute(m, "self#jumbf=c2pa.signature")
        val label = "C2PA：" + (m.claim.text("dc:title") ?: m.label)
        val cose = m.cose ?: run {
            statuses += C2paStatus("claimSignature.missing", url, false, "沒有聲明簽章")
            return checks.failed(SignatureFormat.C2PA, label, "C2PA 聲明沒有簽章")
        }
        val problems = ArrayList<String>()
        val notes = ArrayList<String>()
        val holders = cose.chain.mapNotNull { Bc.holder(it) }
        val signer = holders.firstOrNull()
        // The signature always covers the claim as parsed; an embedded payload that is not that claim is a mismatch.
        val payloadMismatch = cose.payload != null && !cose.payload.contentEquals(m.claimBytes)
        val valid = signer != null && !payloadMismatch && runCatching { verify(cose, C2paManifests.toBeSigned(cose.protectedBytes, m.claimBytes), signer) }.getOrDefault(false)
        val why = when { signer == null -> "簽章沒有附上簽署憑證"; payloadMismatch -> "簽章內嵌的內容不是這份聲明"; else -> "聲明簽章無效" }
        statuses += if (valid) C2paStatus("claimSignature.validated", url, true)
        else C2paStatus("claimSignature.mismatch", url, false, why)
        if (!valid) problems.add(if (signer == null) "C2PA 簽章沒有附上簽署憑證（x5chain）" else "C2PA $why")

        val timestamp = cose.timestamps.firstOrNull()?.let { (header, token) ->
            val tok = CmsChecks.tokenOf(token)
            val covered = buildList {
                if (header == "sigTst2") add(C2paManifests.counterSigned(cose.protectedBytes, cose.signature))
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
            binding != null && !binding.success -> { notes.add(binding.explanation ?: "沒有檢查檔案的硬綁定"); Check.WARN }
            else -> Check.PASS
        }
        notes.add("產生工具：" + (C2paManifests.generator(m) ?: "未說明"))
        val info = checks.evaluate(
            SignatureFormat.C2PA, label, algorithmName(cose.algorithm), signer, holders, integrity, null, timestamp,
            cose.ocsps, emptyList(), now, problems, notes,
            coversWhole = binding?.let { if (it.success) true else if (it.code.endsWith("notChecked")) null else false },
            role = TrustRole.CONTENT,
        )
        info.trust?.let { t ->
            statuses += if ("UNKNOWN_ANCHOR" in t.labels || t.tier == "T4") C2paStatus("signingCredential.untrusted", url, false, "簽署憑證不在信任錨點")
            else C2paStatus("signingCredential.trusted", url, true, t.anchorName)
        }
        if (info.certificateValidity == Check.FAIL) statuses += C2paStatus("signingCredential.invalid", url, false, info.problems.lastOrNull())
        return info
    }

    /** CAWG identity assertions: X.509 signatures are verified; identity claims aggregation is shown as stated. */
    private suspend fun identities(store: C2paStore, m: C2paManifest, now: Instant): List<C2paIdentity> =
        C2paManifests.identityAssertions(m).map { (payload, signature, sigType) ->
            val detail = ArrayList<String>()
            val refs = (payload.getText("referenced_assertions") as? CborArray)?.items.orEmpty().mapNotNull { C2paManifests.hashedUri(it) }
            val refsOk = refs.all { r ->
                val box = store.resolve(r.url, m)
                box != null && DocCrypto.digest(C2paManifests.jcaHash(r.algorithm ?: m.algorithm), box.hashedBytes).contentEquals(r.hash)
            }
            detail.add("綁定 ${refs.size} 個宣告" + if (refsOk) "，雜湊相符" else "，有宣告的雜湊不符")
            val cose = runCatching { C2paManifests.cose(signature) }.getOrNull()
            when {
                cose == null -> C2paIdentity(sigType, emptyList(), signature = Check.FAIL, detail = detail + "無法讀取身分簽章")
                sigType == "cawg.x509.cose" -> {
                    val holders = cose.chain.mapNotNull { Bc.holder(it) }
                    val signer = holders.firstOrNull()
                    val content = cose.payload ?: Cbor.encode(payload)
                    val ok = signer != null && runCatching { verify(cose, C2paManifests.toBeSigned(cose.protectedBytes, content), signer) }.getOrDefault(false)
                    val names = listOfNotNull(signer?.let { pki.cn(it.subject) }, signer?.let { Bc.org(it) }).distinct()
                    if (signer != null) {
                        val decision = pki.decide(TrustRole.CONTENT, pki.buildChain(signer, holders), now)
                        detail.add(if (PkiSupport.unknownAnchor(decision)) "身分憑證不在信任錨點" else "身分憑證信任錨點：${decision.anchorName ?: decision.tier.name}")
                    }
                    C2paIdentity(sigType, names, signer?.let { pki.cn(it.issuer) }, if (ok && refsOk) Check.PASS else Check.FAIL, detail)
                }
                else -> {
                    val vc = cose.payload?.let { runCatching { DiwJson.parseToJsonElement(it.decodeToString()) as? JsonObject }.getOrNull() }
                    val issuer = (vc?.get("issuer") as? JsonObject)?.text("id") ?: vc?.text("issuer")
                    val subject = vc?.get("credentialSubject") as? JsonObject
                    val names = (subject?.get("verifiedIdentities") as? JsonArray).orEmpty().mapNotNull { e ->
                        val o = e as? JsonObject ?: return@mapNotNull null
                        val who = o.text("name") ?: o.text("username") ?: o.text("uri") ?: return@mapNotNull null
                        val provider = (o["provider"] as? JsonObject)?.text("name")
                        who + (provider?.let { "（$it）" } ?: "")
                    }
                    detail.add("身分彙整服務的簽章（$issuer）錢包尚未驗證")
                    C2paIdentity(sigType, names, issuer, Check.NOT_CHECKED, detail)
                }
            }
        }

    /** A COSE signature: ECDSA (raw r||s), RSASSA-PSS or Ed25519, by the COSE algorithm number. */
    private fun verify(cose: C2paCose, toBeSigned: ByteArray, signer: X509CertificateHolder): Boolean {
        val key: PublicKey = JcaX509CertificateConverter().setProvider(Bc.provider).getCertificate(signer).publicKey
        val (name, sig) = when (cose.algorithm) {
            -7 -> "SHA256withECDSA" to der(cose.signature)
            -35 -> "SHA384withECDSA" to der(cose.signature)
            -36 -> "SHA512withECDSA" to der(cose.signature)
            -37, -38, -39 -> "RSASSA-PSS" to cose.signature
            -8 -> "Ed25519" to cose.signature
            else -> return false
        }
        val s = Signature.getInstance(name, Bc.provider)
        when (cose.algorithm) {
            -37 -> s.setParameter(PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))
            -38 -> s.setParameter(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1))
            -39 -> s.setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))
        }
        s.initVerify(key)
        s.update(toBeSigned)
        return s.verify(sig)
    }

    private fun der(raw: ByteArray): ByteArray {
        val half = raw.size / 2
        val v = ASN1EncodableVector()
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(0, half))))
        v.add(ASN1Integer(BigInteger(1, raw.copyOfRange(half, raw.size))))
        return DERSequence(v).encoded
    }

    private fun algorithmName(alg: Int?): String? = when (alg) {
        -7 -> "ES256"; -35 -> "ES384"; -36 -> "ES512"; -37 -> "PS256"; -38 -> "PS384"; -39 -> "PS512"; -8 -> "EdDSA"
        else -> alg?.let { "COSE $it" }
    }

    private fun DataItem.getText(key: String): DataItem? =
        (this as? CborMap)?.items?.entries?.firstOrNull { (k, _) -> (k as? Tstr)?.value == key }?.value

    private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull
}

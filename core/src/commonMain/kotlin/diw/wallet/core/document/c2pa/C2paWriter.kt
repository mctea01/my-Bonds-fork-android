package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.document.DocCryptoUtil
import diw.wallet.core.document.sign.DocumentSigner
import diw.wallet.core.document.sign.RsaPss
import diw.wallet.core.document.sign.SignerKeyType
import diw.wallet.core.document.sign.SigningException
import diw.wallet.core.document.sign.Timestamper
import diw.wallet.core.i18n.ct
import diw.wallet.core.jose.PlatformCrypto
import kotlin.time.Instant

/** IPTC digital source types (http://cv.iptc.org/newscodes/digitalsourcetype/) used by C2PA actions and XMP. */
object DigitalSourceTypes {
    const val BASE = "http://cv.iptc.org/newscodes/digitalsourcetype/"

    /** Made by a generative model (trained on data), whole or in part. */
    val AI_GENERATED = setOf("trainedAlgorithmicMedia", "compositeWithTrainedAlgorithmicMedia")

    /** Made or changed by algorithms that are not described as trained models. */
    val SYNTHETIC = setOf("algorithmicMedia", "compositeSynthetic", "algorithmicallyEnhanced", "dataDrivenMedia")

    /** The codes a creator can declare when signing, in the order shown. */
    val DECLARABLE = listOf(
        "digitalCapture", "computationalCapture", "digitalCreation", "humanEdits", "compositeCapture", "screenCapture",
        "trainedAlgorithmicMedia", "compositeWithTrainedAlgorithmicMedia", "algorithmicallyEnhanced", "algorithmicMedia", "compositeSynthetic",
    )

    /** The code of a full IPTC URI or a bare code. */
    fun code(value: String): String = value.trim().substringAfterLast('/')
}

/** Key order of the CAWG signer_payload as signed. */
enum class SignerPayloadOrder {
    /** RFC 8949 core deterministic encoding, as CAWG identity assertion 1.3 section 8.2 requires. */
    DETERMINISTIC,

    /**
     * The field order of the c2pa-rs SDK (referenced_assertions, sig_type, role), which re-encodes the payload in that
     * order when it verifies. Not the standard encoding; an option for validators built on c2pa-rs.
     */
    C2PA_RS,
}

/** How the signer relates to the file: made it (with its digital source type), or signs it as it was. */
sealed class C2paAuthoring {
    /** c2pa.created with an IPTC digital source type code such as digitalCapture or trainedAlgorithmicMedia. */
    data class Created(val digitalSourceType: String) : C2paAuthoring()

    /** c2pa.opened of the file as it was (its earlier manifest, if any, becomes the parent ingredient). */
    data object Opened : C2paAuthoring()
}

/** What a new manifest records. */
data class C2paSignRequest(
    val title: String,
    val authoring: C2paAuthoring = C2paAuthoring.Opened,
    /** Add a CAWG identity assertion (cawg.x509.cose) signed by the identity signer. */
    val identity: Boolean = true,
    /** CAWG roles of the named actor (cawg.creator, cawg.contributor, cawg.editor...). */
    val roles: List<String> = emptyList(),
    /** cawg.training-mining: null leaves it out, true allows AI training and data mining, false does not. */
    val allowTraining: Boolean? = null,
    val payloadOrder: SignerPayloadOrder = SignerPayloadOrder.DETERMINISTIC,
    val generatorName: String = "DIW MY WALLET",
    val generatorVersion: String? = null,
    val time: Instant,
    /** The validation results of the file's active manifest (for the ingredient's validationResults). */
    val previousResults: List<C2paStatus> = emptyList(),
    /**
     * The hard binding to use where the format allows a choice: [C2paBinding.BOXES] for JPEG, PNG and GIF (JPEG XL
     * uses it by default), [C2paBinding.DATA] for JPEG XL. Null takes the format's default ([C2paFormat.binding]).
     */
    val binding: C2paBinding? = null,
)

/**
 * A signed result: the file with the manifest embedded, or a sidecar manifest store for files that cannot hold one.
 * [sidecarReason] says why a file of a supported container got a sidecar (an encrypted or certified PDF...).
 */
class C2paSigned(val bytes: ByteArray, val sidecar: Boolean, val manifestLabel: String, val container: String, val sidecarReason: String? = null)

/**
 * Writes C2PA 2.x manifests (claim v2, ES256 or PS256 COSE claim signature with an optional sigTst2 time stamp) into
 * every container of [C2paContainers] (JPEG, PNG, WebP, WAV, AVI, GIF, TIFF, DNG, SVG, MP3, FLAC, JPEG XL, BMFF, PDF,
 * ZIP) or as a sidecar store, with the hard binding of the format: a data hash, a box hash (JPEG XL, or on request
 * JPEG, PNG and GIF), a v3 BMFF hash or a ZIP collection hash. It adds a CAWG identity assertion 1.3
 * (cawg.x509.cose) signed by a person's X.509 key. Space for the identity assertion and the claim signature is
 * reserved first and filled with zero padding (pad1/pad2, the COSE pad header), so the binding computed over the
 * final layout stays valid (CAWG 1.3 section 6.3, C2PA 10.4).
 */
object C2paWriter {
    private const val STORE = "6332706100110010800000aa00389b71"
    private const val MANIFEST = "63326d6100110010800000aa00389b71"
    private const val ASSERTIONS = "6332617300110010800000aa00389b71"
    private const val CLAIM = "6332636c00110010800000aa00389b71"
    private const val SIGNATURE = "6332637300110010800000aa00389b71"
    private const val CBOR = "63626f7200110010800000aa00389b71"
    private const val COSE_OVERHEAD = 1024
    private const val TIMESTAMP_RESERVE = 12000
    private const val JPEG_SEGMENT_DATA = 65525
    const val IDENTITY_LABEL = "cawg.identity"
    const val X509_SIG_TYPE = "cawg.x509.cose"

    /** Where a manifest for [bytes] goes: its container, or a sidecar store when it has none or cannot take one. */
    fun formatOf(bytes: ByteArray): C2paFormat {
        val f = C2paContainers.detect(bytes) ?: return C2paFormat.SIDECAR
        return if (C2paContainers.cannotEmbed(bytes, f) == null) f else C2paFormat.SIDECAR
    }

    /**
     * Signs [asset]: [claimSigner] signs the claim (the claim generator's signature), [identitySigner] the CAWG
     * identity assertion when [C2paSignRequest.identity] is set (the same key may sign both). [timestamper] adds a
     * v2 time stamp (sigTst2) to the claim signature, which CAWG validators also use for the identity assertion.
     * [mediaType] is the asset's type for the claim and the ingredient (the detected one when null or generic).
     */
    suspend fun sign(
        asset: ByteArray,
        request: C2paSignRequest,
        claimSigner: DocumentSigner,
        identitySigner: DocumentSigner?,
        timestamper: Timestamper?,
        mediaType: String? = null,
    ): C2paSigned {
        val detected = C2paContainers.detect(asset)
        val reason = detected?.let { C2paContainers.cannotEmbed(asset, it) }
        val format = if (detected == null || reason != null) C2paFormat.SIDECAR else detected
        val sidecar = format == C2paFormat.SIDECAR
        val binding = when {
            sidecar -> C2paBinding.DATA
            request.binding == C2paBinding.BOXES && C2paBoxHash.supports(format) -> C2paBinding.BOXES
            request.binding == C2paBinding.DATA && format.binding == C2paBinding.BOXES -> C2paBinding.DATA
            else -> format.binding
        }
        val existing = if (sidecar) null else runCatching { C2paManifests.read(asset) }.getOrNull()
        val base = if (sidecar) asset else C2paContainers.strip(asset, format)
        val oldManifests = existing?.root?.children.orEmpty().filter { m -> existing!!.manifests.any { it.box === m } }.map { it.rawBytes }
        val parent = existing?.active
        val label = "urn:c2pa:" + uuid()
        val claimKey = CoseKey(claimSigner)
        val idKey = if (request.identity) CoseKey(identitySigner ?: claimSigner) else null
        val format0 = mediaType?.takeUnless { it.isBlank() || it == "application/octet-stream" }
            ?: detected?.let { C2paContainers.mediaType(asset, it) } ?: "application/octet-stream"

        // Assertions that do not depend on the layout.
        val ingredientBox = if (request.authoring is C2paAuthoring.Opened) assertionBox("c2pa.ingredient.v3", ingredient(request, format0, parent)) else null
        val actionsBox = assertionBox("c2pa.actions.v2", actions(request, ingredientBox))
        val trainingBox = request.allowTraining?.let { assertionBox("cawg.training-mining", training(it)) }
        val fixed = listOfNotNull(actionsBox, ingredientBox, trainingBox)

        // The hard binding assertion: its size does not depend on the store, so a placeholder of that size goes in
        // first (the data hash's pad absorbs the widths of its integers).
        val hashLabel = when (binding) {
            C2paBinding.DATA -> "c2pa.hash.data"
            C2paBinding.BOXES -> "c2pa.hash.boxes"
            C2paBinding.BMFF -> "c2pa.hash.bmff.v3"
            C2paBinding.COLLECTION -> "c2pa.hash.collection.data"
        }
        fun bindingCbor(layout: C2paLayout, zero: Boolean): ByteArray = when (binding) {
            C2paBinding.DATA -> {
                val r = layout.region
                val digest = when {
                    zero -> ByteArray(32)
                    sidecar -> DocCrypto.digest("SHA-256", base)
                    else -> DocCrypto.digest("SHA-256", C2paBindings.without(layout.bytes, listOf(r)))
                }
                dataHash(sidecar, r.start, r.length, digest, padFor(sidecar, r.start, r.length))
            }
            C2paBinding.BOXES -> C2paBoxHash.assertionCbor(layout.bytes, format, zero = zero)
            C2paBinding.BMFF -> C2paBmff.assertionCbor(if (zero) ByteArray(32) else C2paBmff.standardHash(layout.bytes))
            C2paBinding.COLLECTION -> C2paZip.assertionCbor(layout.bytes, zero = zero)
        }
        fun embed(store: ByteArray): C2paLayout = try {
            C2paContainers.embed(base, format, store)
        } catch (e: C2paContainerException) {
            throw SigningException(ct("core_c2pa_embed_failed", format.title, e.message ?: ""), e)
        }
        val placeholderHash = if (binding == C2paBinding.DATA) assertionBox(hashLabel, dataHash(sidecar, PLACEHOLDER_INT, PLACEHOLDER_INT, ByteArray(32), HASH_PAD))
            else assertionBox(hashLabel, bindingCbor(embed(store(oldManifests, label, fixed, claim(request, label, fixed, emptyList()), ByteArray(0))), zero = true))
        val idTarget = idKey?.let { identityPlaceholderSize(request, fixed, placeholderHash, it) }
        val idPlaceholder = idTarget?.let { assertionBoxOfSize(IDENTITY_LABEL, it) }
        val sigTarget = claimKey.chainSize + claimKey.maxSignature + COSE_OVERHEAD + if (timestamper != null) TIMESTAMP_RESERVE else 0
        val created0 = fixed + placeholderHash
        val store0 = store(oldManifests, label, created0 + listOfNotNull(idPlaceholder), claim(request, label, created0, listOfNotNull(idPlaceholder)), ByteArray(sigTarget))
        val layout0 = embed(store0)

        // The binding over the final layout.
        val hashBox = assertionBox(hashLabel, bindingCbor(layout0, zero = false))
        if (hashBox.size != placeholderHash.size) throw SigningException(ct("core_c2pa_reserve_exceeded"))
        val created = fixed + hashBox

        // The CAWG identity assertion over the hard binding and the other assertions of this manifest.
        val idBox = if (idKey != null && idTarget != null) {
            val refs = (listOf(hashBox) + fixed).map { hashedUri(it) }
            val payload = signerPayload(refs, request.roles, request.payloadOrder)
            val cose = coseSign1(idKey, payload, timestamper = null, targetSize = null)
            identityBoxOfSize(payload, cose, idTarget) ?: throw SigningException(ct("core_c2pa_reserve_exceeded"))
        } else null

        // The claim and its signature.
        val claimBytes = claim(request, label, created, listOfNotNull(idBox))
        val signatureCbor = coseSign1(claimKey, claimBytes, timestamper, sigTarget)
        val store = store(oldManifests, label, created + listOfNotNull(idBox), claimBytes, signatureCbor)
        val out = embed(store)
        check(out.region == layout0.region && out.bytes.size == layout0.bytes.size) { "C2PA layout changed while signing" }
        if (binding == C2paBinding.DATA && !sidecar) {
            check(C2paBindings.without(out.bytes, listOf(out.region)).contentEquals(C2paBindings.without(layout0.bytes, listOf(layout0.region)))) { "C2PA layout changed while signing" }
        }
        return C2paSigned(out.bytes, sidecar, label, format.title, reason)
    }

    // ---------------------------------------------------------------- COSE

    /** The COSE algorithm and signing of a document key: ES256 for P-256, PS256 for RSA. */
    internal class CoseKey(private val signer: DocumentSigner) {
        val algorithm: Int = when (signer.keyType) {
            SignerKeyType.EC_P256 -> -7
            SignerKeyType.RSA -> -37
            SignerKeyType.SM2 -> throw SigningException(ct("core_key_sm2_unsupported"))
        }
        val chain: List<ByteArray> get() = signer.certificateChain
        val chainSize: Int get() = chain.sumOf { it.size }
        val maxSignature: Int get() = if (algorithm == -7) 64 else ((chain.firstOrNull()?.let { RsaPss.modulusBits(it) } ?: 4096) + 7) / 8

        suspend fun sign(data: ByteArray): ByteArray = when (algorithm) {
            -7 -> ecdsaRaw(signer.sign(data)) ?: throw SigningException(ct("core_c2pa_ecdsa_format"))
            else -> signer.signRsaPss(data) ?: throw SigningException(ct("core_c2pa_rsa_pss_unsupported"))
        }
    }

    /** Protected header {1: alg, 33: x5chain}: one certificate as a byte string, several as an array (C2PA 13.2). */
    private fun protectedHeader(key: CoseKey): ByteArray {
        val chain = key.chain
        val x5 = if (chain.size == 1) C2paCbor.bstr(chain.first()) else C2paCbor.array(chain.map { C2paCbor.bstr(it) })
        return C2paCbor.rawMap(listOf(C2paCbor.int(1) to C2paCbor.int(key.algorithm), C2paCbor.int(33) to x5))
    }

    /**
     * A tagged COSE_Sign1 with a detached [payload]. With [timestamper], a v2 time stamp over the countersignature
     * structure of the signature value goes into sigTst2; with [targetSize], zero padding (pad, pad2) makes the
     * encoding exactly that long.
     */
    private suspend fun coseSign1(key: CoseKey, payload: ByteArray, timestamper: Timestamper?, targetSize: Int?): ByteArray {
        val prot = protectedHeader(key)
        val signature = key.sign(C2paManifests.toBeSigned(prot, payload))
        val unprotected = ArrayList<Pair<String, ByteArray>>()
        if (timestamper != null) {
            val token = timestamper.timestamp(C2paManifests.counterSigned(prot, C2paCbor.bstr(signature)))
            unprotected += "sigTst2" to C2paCbor.map(listOf("tstTokens" to C2paCbor.array(listOf(C2paCbor.map(listOf("val" to C2paCbor.bstr(token)))))))
        }
        fun encode(pad: Int?, pad2: Int?) = C2paCbor.tag(18, C2paCbor.array(listOf(
            C2paCbor.bstr(prot),
            C2paCbor.map(unprotected + listOfNotNull(pad?.let { "pad" to C2paCbor.bstr(ByteArray(it)) }, pad2?.let { "pad2" to C2paCbor.bstr(ByteArray(it)) })),
            C2paCbor.NULL,
            C2paCbor.bstr(signature),
        )))
        if (targetSize == null) return encode(null, null)
        val pads = fitPads(targetSize) { p1, p2 -> encode(p1, p2).size } ?: throw SigningException(ct("core_c2pa_reserve_exceeded"))
        return encode(pads.first, pads.second).also { check(it.size == targetSize) }
    }

    /**
     * Pad lengths (first, optional second) that make [size] of the encoding equal [target]: the length of one byte
     * string cannot reach every size (the length header grows at 24 and 256 bytes), so a second one fills the gap.
     * [size] is called with candidate lengths and must grow by one per byte of padding within one header width.
     */
    private fun fitPads(target: Int, size: (Int, Int?) -> Int): Pair<Int, Int?>? {
        val base = size(0, null)
        if (base > target) return null
        // size(p) - base == bstrSize(p) - 1 for one pad.
        C2paCbor.bstrLengthFor(target - base + 1)?.let { p -> if (size(p, null) == target) return p to null }
        val withSecond = size(0, 0)
        for (p2 in 0..40) {
            val rest = target - withSecond - (C2paCbor.bstrSize(p2) - 1) + 1
            val p1 = C2paCbor.bstrLengthFor(rest) ?: continue
            if (size(p1, p2) == target) return p1 to p2
        }
        return null
    }

    private fun ecdsaRaw(der: ByteArray): ByteArray? {
        if (der.size == 64 && der[0] != 0x30.toByte()) return der
        var i = 0
        if (der.getOrNull(i++) != 0x30.toByte()) return null
        var len = der[i++].toInt() and 0xFF
        if (len and 0x80 != 0) { val n = len and 0x7F; len = 0; repeat(n) { len = (len shl 8) or (der[i++].toInt() and 0xFF) } }
        fun integer(): ByteArray? {
            if (der.getOrNull(i++) != 0x02.toByte()) return null
            val l = der[i++].toInt() and 0xFF
            var v = der.copyOfRange(i, i + l)
            i += l
            while (v.size > 32 && v[0] == 0.toByte()) v = v.copyOfRange(1, v.size)
            if (v.size > 32) return null
            return ByteArray(32 - v.size) + v
        }
        val r = integer() ?: return null
        val s = integer() ?: return null
        return r + s
    }

    // ---------------------------------------------------------------- assertions and claim

    private val PLACEHOLDER_INT = 0xFFFFFFFFL
    private const val HASH_PAD = 8

    /** Pad of the data hash: the placeholder's 8 bytes plus what the real integers save against 0xFFFFFFFF. */
    private fun padFor(sidecar: Boolean, start: Long, length: Long): Int =
        if (sidecar) HASH_PAD else HASH_PAD + 2 * C2paCbor.int(PLACEHOLDER_INT).size - C2paCbor.int(start).size - C2paCbor.int(length).size

    private fun dataHash(sidecar: Boolean, start: Long, length: Long, hash: ByteArray, pad: Int): ByteArray {
        if (!sidecar && (start > PLACEHOLDER_INT || length > PLACEHOLDER_INT)) throw SigningException(ct("core_c2pa_reserve_exceeded"))
        val exclusions = if (sidecar) C2paCbor.array(emptyList())
            else C2paCbor.array(listOf(C2paCbor.map(listOf("start" to C2paCbor.int(start), "length" to C2paCbor.int(length)))))
        return C2paCbor.map(listOf(
            "exclusions" to exclusions,
            "name" to C2paCbor.tstr("jumbf manifest"),
            "alg" to C2paCbor.tstr("sha256"),
            "hash" to C2paCbor.bstr(hash),
            "pad" to C2paCbor.bstr(ByteArray(pad)),
        ))
    }

    private fun softwareAgent(r: C2paSignRequest) =
        C2paCbor.map(listOfNotNull("name" to C2paCbor.tstr(r.generatorName), r.generatorVersion?.let { "version" to C2paCbor.tstr(it) }))

    private fun whenText(r: C2paSignRequest) = Instant.fromEpochSeconds(r.time.epochSeconds).toString()

    private fun actions(r: C2paSignRequest, ingredient: ByteArray?): ByteArray {
        val action = when (val a = r.authoring) {
            is C2paAuthoring.Created -> C2paCbor.map(listOf(
                "action" to C2paCbor.tstr("c2pa.created"),
                "digitalSourceType" to C2paCbor.tstr(DigitalSourceTypes.BASE + DigitalSourceTypes.code(a.digitalSourceType)),
                "softwareAgent" to softwareAgent(r),
                "when" to C2paCbor.tstr(whenText(r)),
            ))
            C2paAuthoring.Opened -> C2paCbor.map(listOfNotNull(
                "action" to C2paCbor.tstr("c2pa.opened"),
                ingredient?.let { "parameters" to C2paCbor.map(listOf("ingredients" to C2paCbor.array(listOf(hashedUriCbor(hashedUri(it)))))) },
                "softwareAgent" to softwareAgent(r),
                "when" to C2paCbor.tstr(whenText(r)),
            ))
        }
        return C2paCbor.map(listOf("actions" to C2paCbor.array(listOf(action))))
    }

    /** The file as it was, as the parent ingredient: its active manifest and that manifest's validation results. */
    private fun ingredient(r: C2paSignRequest, format: String, parent: C2paManifest?): ByteArray {
        val entries = ArrayList<Pair<String, ByteArray>>()
        entries += "dc:title" to C2paCbor.tstr(r.title)
        entries += "dc:format" to C2paCbor.tstr(format)
        entries += "relationship" to C2paCbor.tstr("parentOf")
        if (parent != null) {
            entries += "activeManifest" to hashedUriCbor("self#jumbf=/c2pa/${parent.label}" to DocCrypto.digest("SHA-256", parent.box.hashedBytes))
            parent.box.child("c2pa.signature")?.let { sig ->
                entries += "claimSignature" to hashedUriCbor("self#jumbf=/c2pa/${parent.label}/c2pa.signature" to DocCrypto.digest("SHA-256", sig.hashedBytes))
            }
            fun status(s: C2paStatus) = C2paCbor.map(listOfNotNull(
                "code" to C2paCbor.tstr(s.code), s.url?.let { "url" to C2paCbor.tstr(it) }, s.explanation?.let { "explanation" to C2paCbor.tstr(it) },
            ))
            entries += "validationResults" to C2paCbor.map(listOf("activeManifest" to C2paCbor.map(listOf(
                "success" to C2paCbor.array(r.previousResults.filter { it.success }.map(::status)),
                "informational" to C2paCbor.array(emptyList()),
                "failure" to C2paCbor.array(r.previousResults.filter { !it.success }.map(::status)),
            ))))
        }
        return C2paCbor.map(entries)
    }

    /** cawg.training-mining entries for AI inference, generative training, training and data mining. */
    private fun training(allowed: Boolean): ByteArray {
        val use = C2paCbor.map(listOf("use" to C2paCbor.tstr(if (allowed) "allowed" else "notAllowed")))
        return C2paCbor.map(listOf("entries" to C2paCbor.map(TRAINING_KEYS.map { it to use })))
    }

    val TRAINING_KEYS = listOf("cawg.ai_inference", "cawg.ai_generative_training", "cawg.ai_training", "cawg.data_mining")

    private fun claim(r: C2paSignRequest, label: String, created: List<ByteArray>, gathered: List<ByteArray>): ByteArray =
        C2paCbor.map(listOfNotNull(
            "instanceID" to C2paCbor.tstr("xmp:iid:" + label.removePrefix("urn:c2pa:")),
            "claim_generator_info" to softwareAgent(r),
            "signature" to C2paCbor.tstr("self#jumbf=c2pa.signature"),
            "created_assertions" to C2paCbor.array(created.map { hashedUriCbor(hashedUri(it)) }),
            gathered.takeIf { it.isNotEmpty() }?.let { g -> "gathered_assertions" to C2paCbor.array(g.map { hashedUriCbor(hashedUri(it)) }) },
            "dc:title" to C2paCbor.tstr(r.title),
            "alg" to C2paCbor.tstr("sha256"),
        ))

    /**
     * The CAWG signer_payload (1.3 section 5.2): referenced_assertions, sig_type and role, in RFC 8949 deterministic
     * order or in the c2pa-rs field order. Hashed URIs carry url and hash only (the claim's algorithm applies), so
     * both orders agree inside them.
     */
    fun signerPayload(refs: List<Pair<String, ByteArray>>, roles: List<String>, order: SignerPayloadOrder): ByteArray {
        val entries = listOfNotNull(
            "referenced_assertions" to C2paCbor.array(refs.map(::hashedUriCbor)),
            "sig_type" to C2paCbor.tstr(X509_SIG_TYPE),
            roles.takeIf { it.isNotEmpty() }?.let { "role" to C2paCbor.array(it.map(C2paCbor::tstr)) },
        )
        return if (order == SignerPayloadOrder.DETERMINISTIC) C2paCbor.deterministicMap(entries) else C2paCbor.map(entries)
    }

    private fun hashedUriCbor(u: Pair<String, ByteArray>) = C2paCbor.map(listOf("url" to C2paCbor.tstr(u.first), "hash" to C2paCbor.bstr(u.second)))

    /** The claim's hashed URI of an assertion superbox: its relative JUMBF URL and the SHA-256 of its content. */
    private fun hashedUri(box: ByteArray): Pair<String, ByteArray> {
        val label = labelOf(box)
        return "self#jumbf=c2pa.assertions/$label" to DocCrypto.digest("SHA-256", box.copyOfRange(8, box.size))
    }

    private fun labelOf(box: ByteArray): String {
        // jumb header (8), jumd header (8), uuid (16), toggles (1), label up to the NUL.
        val from = 8 + 8 + 16 + 1
        var end = from
        while (box[end] != 0.toByte()) end++
        return box.copyOfRange(from, end).decodeToString()
    }

    /** Size of the identity assertion box reserved for the key's signature (payload of the final references). */
    private fun identityPlaceholderSize(r: C2paSignRequest, fixed: List<ByteArray>, hashBox: ByteArray, key: CoseKey): Int {
        val refs = (listOf(hashBox) + fixed).map { hashedUri(it) }
        val payload = signerPayload(refs, r.roles, r.payloadOrder)
        val reserve = key.chainSize + key.maxSignature + COSE_OVERHEAD
        return identityBox(payload, ByteArray(reserve), 0, null).size
    }

    private fun identityCbor(payload: ByteArray, cose: ByteArray, pad1: Int, pad2: Int?): ByteArray = C2paCbor.map(listOfNotNull(
        "signer_payload" to payload,
        "signature" to C2paCbor.bstr(cose),
        "pad1" to C2paCbor.bstr(ByteArray(pad1)),
        pad2?.let { "pad2" to C2paCbor.bstr(ByteArray(it)) },
    ))

    private fun identityBox(payload: ByteArray, cose: ByteArray, pad1: Int, pad2: Int?) = assertionBox(IDENTITY_LABEL, identityCbor(payload, cose, pad1, pad2))

    /** The identity assertion padded (pad1, pad2 of zeros) to exactly [size] bytes, or null when it does not fit. */
    private fun identityBoxOfSize(payload: ByteArray, cose: ByteArray, size: Int): ByteArray? {
        val pads = fitPads(size) { p1, p2 -> identityBox(payload, cose, p1, p2).size } ?: return null
        return identityBox(payload, cose, pads.first, pads.second).also { check(it.size == size) }
    }

    /** A placeholder assertion box of exactly [size] bytes: a CBOR byte string of zeros under the final label. */
    private fun assertionBoxOfSize(label: String, size: Int): ByteArray {
        val empty = assertionBox(label, C2paCbor.bstr(ByteArray(0))).size
        val n = C2paCbor.bstrLengthFor(size - empty + 1) ?: throw SigningException(ct("core_c2pa_reserve_exceeded"))
        return assertionBox(label, C2paCbor.bstr(ByteArray(n))).also { check(it.size == size) }
    }

    // ---------------------------------------------------------------- JUMBF

    private fun box(type: String, body: ByteArray): ByteArray {
        val n = 8 + body.size
        return byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()) + type.encodeToByteArray() + body
    }

    private fun description(uuid: String, label: String): ByteArray = box("jumd", DocCryptoUtil.unhex(uuid) + byteArrayOf(0x03) + label.encodeToByteArray() + 0)

    private fun superbox(uuid: String, label: String, contents: List<ByteArray>) = box("jumb", C2paCbor.concat(listOf(description(uuid, label)) + contents))

    private fun assertionBox(label: String, cbor: ByteArray) = superbox(CBOR, label, listOf(box("cbor", cbor)))

    private fun store(old: List<ByteArray>, label: String, assertions: List<ByteArray>, claim: ByteArray, signature: ByteArray): ByteArray =
        superbox(STORE, "c2pa", old + superbox(MANIFEST, label, listOf(
            superbox(ASSERTIONS, "c2pa.assertions", assertions),
            superbox(CLAIM, "c2pa.claim.v2", listOf(box("cbor", claim))),
            superbox(SIGNATURE, "c2pa.signature", listOf(box("cbor", signature))),
        )))

    /** The asset with any C2PA manifest store it carries removed (the store's manifests are kept by the caller). */
    fun strip(b: ByteArray): ByteArray = C2paContainers.detect(b)?.let { C2paContainers.strip(b, it) } ?: b

    private fun uuid(): String {
        val r = PlatformCrypto.randomBytes(16)
        r[6] = ((r[6].toInt() and 0x0F) or 0x40).toByte()
        r[8] = ((r[8].toInt() and 0x3F) or 0x80).toByte()
        val h = DocCryptoUtil.hex(r).lowercase()
        return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
    }
}

/** CRC-32 (ISO 3309, the PNG chunk checksum). */
internal object Crc32 {
    private val table = IntArray(256) { n ->
        var c = n
        repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0xEDB88320.toInt() else c ushr 1 }
        c
    }

    fun of(data: ByteArray): Int {
        var c = -1
        for (b in data) c = table[(c xor b.toInt()) and 0xFF] xor (c ushr 8)
        return c.inv()
    }
}

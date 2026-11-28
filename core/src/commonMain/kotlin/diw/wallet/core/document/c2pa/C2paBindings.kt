package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.i18n.ct
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tstr

/**
 * Checks the hard binding of a manifest over its asset (C2PA 15.12): the data hash with the rule that one exclusion
 * is exactly the store's location, the box hash, the BMFF hash (file hash, Merkle trees over mdat blocks and
 * fragments) and the collection hash of a ZIP. The first status is the result; informational ones follow
 * (additional exclusions, what could not be checked).
 */
object C2paBindings {
    private val HARD = listOf("c2pa.hash.data", "c2pa.hash.boxes", "c2pa.hash.bmff", "c2pa.hash.collection.data")
    const val MULTI_ASSET = "c2pa.hash.multi-asset"

    /** Actions an update manifest may record (C2PA 11.2.3). */
    val UPDATE_ACTIONS = setOf("c2pa.edited.metadata", "c2pa.opened", "c2pa.published", "c2pa.redacted")

    /** The base label of a hard binding assertion ([label] without an instance suffix), or null. */
    fun hardLabel(label: String?): String? {
        val base = label?.substringBefore("__") ?: return null
        return HARD.firstOrNull { base == it || (it == "c2pa.hash.bmff" && (base == "c2pa.hash.bmff.v2" || base == "c2pa.hash.bmff.v3")) }
    }

    /**
     * The hard binding of [m] over the asset. For an update manifest the binding is that of the first standard manifest
     * up its chain of parentOf ingredients (C2PA 15.11.3.3), with the data hash's store exclusion taken at the store's
     * current length. When the standard binding fails and the manifest has a multi-asset hash, that is checked instead
     * (15.12.4).
     */
    fun check(store: C2paStore, m: C2paManifest): List<C2paStatus> {
        val target = if (m.update) standardOf(store, m).getOrElse {
            return listOf(C2paStatus("claim.hardBindings.missing", C2paManifests.absolute(m, "self#jumbf=c2pa.assertions"), false, it.message))
        } else m
        val primary = standard(store, target, adjusted = target !== m)
        val first = primary.firstOrNull() ?: return primary
        if (first.success || first.code.endsWith("notChecked") || first.code.startsWith("claim.")) return primary
        val multi = C2paManifests.signedAssertions(target).filter { it.label?.substringBefore("__") == MULTI_ASSET }
        if (multi.isEmpty()) return primary
        return multiAsset(store, target, multi, adjusted = target !== m)
    }

    /** The first standard manifest up the parentOf chain of the update manifest [m], or a failure that says why. */
    private fun standardOf(store: C2paStore, m: C2paManifest): Result<C2paManifest> {
        var cur = m
        val seen = HashSet<String>()
        while (cur.update) {
            if (!seen.add(cur.label)) return Result.failure(IllegalStateException(ct("core_c2pa_update_loop")))
            val ref = parentRef(cur) ?: return Result.failure(IllegalStateException(ct("core_c2pa_update_no_parent", cur.label)))
            val label = C2paManifests.jumbfPath(ref.url).trim('/').split('/').getOrNull(1)
            val parent = label?.let { store.manifest(it) } ?: return Result.failure(IllegalStateException(ct("core_c2pa_update_parent_missing", ref.url)))
            if (!DocCrypto.digest(C2paManifests.jcaHash(ref.algorithm ?: cur.algorithm), parent.box.hashedBytes).contentEquals(ref.hash)) {
                return Result.failure(IllegalStateException(ct("core_c2pa_update_parent_hash", ref.url)))
            }
            cur = parent
        }
        return Result.success(cur)
    }

    /** The hashed URI of the manifest of [m]'s single parentOf ingredient (activeManifest, or c2pa_manifest of v1 and v2). */
    private fun parentRef(m: C2paManifest): C2paHashedUri? {
        val parents = parentIngredients(m)
        val d = parents.singleOrNull() ?: return null
        return C2paManifests.hashedUri(d.getOrNullAny("activeManifest") ?: d.getOrNullAny("c2pa_manifest") ?: return null)
    }

    private fun parentIngredients(m: C2paManifest): List<DataItem> =
        C2paManifests.signedAssertions(m).filter { b -> INGREDIENTS.any { b.label == it || b.label?.startsWith("${it}__") == true } }
            .mapNotNull { b -> runCatching { Cbor.decode(b.content("cbor") ?: return@mapNotNull null) }.getOrNull() }
            .filter { (it.getOrNullAny("relationship") as? Tstr)?.value == "parentOf" }

    private val INGREDIENTS = listOf("c2pa.ingredient.v3", "c2pa.ingredient.v2", "c2pa.ingredient")

    /**
     * The rules of an update manifest (C2PA 15.10.1.3): exactly one ingredient, parentOf (v3 with activeManifest and
     * claimSignature, or c2pa_manifest of v1 and v2); no hard binding, multi-asset hash or thumbnail; only the actions
     * of [UPDATE_ACTIONS]. Empty when [m] is a standard manifest or keeps every rule.
     */
    fun updateRules(m: C2paManifest): List<C2paStatus> {
        if (!m.update) return emptyList()
        val out = ArrayList<C2paStatus>()
        val boxes = C2paManifests.signedAssertions(m)
        val ingredients = boxes.filter { b -> INGREDIENTS.any { b.label == it || b.label?.startsWith("${it}__") == true } }
        val wrong = ingredients.size != 1 || ingredients.first().let { b ->
            val d = runCatching { Cbor.decode(b.content("cbor") ?: ByteArray(0)) }.getOrNull()
            val v3 = b.label?.startsWith("c2pa.ingredient.v3") == true
            d == null || (d.getOrNullAny("relationship") as? Tstr)?.value != "parentOf" ||
                (if (v3) d.getOrNullAny("activeManifest") == null || d.getOrNullAny("claimSignature") == null else d.getOrNullAny("c2pa_manifest") == null)
        }
        val url = C2paManifests.absolute(m, "self#jumbf=c2pa.assertions")
        if (wrong) out += C2paStatus("manifest.update.wrongParents", url, false, ct("core_c2pa_update_parents"))
        boxes.firstOrNull { b -> hardLabel(b.label) != null || b.label?.substringBefore("__") == MULTI_ASSET || b.label?.startsWith("c2pa.thumbnail") == true }?.let { b ->
            out += C2paStatus("manifest.update.invalid", C2paManifests.absolute(m, "self#jumbf=c2pa.assertions/${b.label}"), false, ct("core_c2pa_update_assertion", b.label))
        }
        C2paManifests.actions(m).firstOrNull { it.action !in UPDATE_ACTIONS }?.let { a ->
            out += C2paStatus("manifest.update.invalid", url, false, ct("core_c2pa_update_action", a.action))
        }
        return out
    }

    /** The standard hard binding of [m]; [adjusted] when an update manifest was followed to it (15.12.1.1). */
    private fun standard(store: C2paStore, m: C2paManifest, adjusted: Boolean): List<C2paStatus> {
        val signed = C2paManifests.signedAssertions(m)
        val hard = signed.filter { hardLabel(it.label) != null }
        if (hard.isEmpty()) {
            val unsigned = m.box.child("c2pa.assertions")?.children.orEmpty().firstOrNull { hardLabel(it.label) != null }
                ?: return if (adjusted) listOf(C2paStatus("claim.hardBindings.missing", C2paManifests.absolute(m, "self#jumbf=c2pa.assertions"), false, ct("core_c2pa_no_hard_binding"))) else emptyList()
            return listOf(C2paStatus("claim.hardBindings.missing", url(m, unsigned.label), false, ct("core_c2pa_hard_binding_unsigned", unsigned.label)))
        }
        if (hard.size > 1) {
            return listOf(C2paStatus("claim.hardBindings.multiple", url(m, hard[1].label), false, ct("core_c2pa_multiple_bindings", hard.joinToString(", ") { it.label.orEmpty() })))
        }
        val box = hard.first()
        val label = box.label!!
        val u = url(m, label)
        val kind = hardLabel(label)!!
        val asset = store.asset ?: return listOf(C2paStatus(if (kind == "c2pa.hash.data") "assertion.dataHash.notChecked" else "assertion.hardBinding.notChecked", u, false, ct("core_c2pa_sidecar_no_asset")))
        val d = runCatching { Cbor.decode(box.content("cbor") ?: throw IllegalArgumentException()) }.getOrNull()
        return when (kind) {
            "c2pa.hash.data" -> d?.let { data(store, asset, it, m, u, adjusted) } ?: listOf(C2paStatus("assertion.dataHash.malformed", u, false))
            "c2pa.hash.boxes" -> d?.let { boxes(store, asset, it, m, u) } ?: listOf(C2paStatus("assertion.boxesHash.malformed", u, false))
            "c2pa.hash.bmff" -> d?.let { bmff(asset, it, label, m, u) } ?: listOf(C2paStatus("assertion.bmffHash.malformed", u, false))
            else -> d?.let { collection(store, asset, it, m, u) } ?: listOf(C2paStatus("assertion.collectionHash.malformed", u, false))
        }
    }

    // ---------------------------------------------------------------- multi-asset hash (C2PA 18.9, 15.12.4)

    /**
     * A located part: [range] is what its hash covers, [cover] the bytes of the file it takes up. They differ for a
     * bmffBox part, whose hash is over the box payload (C2PA 18.9.2) while the box header is still part of the file.
     */
    private class Part(val index: Int, val range: C2paRange, val cover: C2paRange, val payload: Boolean, val label: String, val box: JumbfSuperbox, val url: String)

    private fun multiAsset(store: C2paStore, m: C2paManifest, multi: List<JumbfSuperbox>, adjusted: Boolean): List<C2paStatus> {
        val u = url(m, multi.first().label)
        fun malformed(key: String, vararg args: Any?) = listOf(C2paStatus("assertion.multiAssetHash.malformed", u, false, ct(key, *args)))
        if (multi.size > 1) return malformed("core_c2pa_multi_asset_several")
        val asset = store.asset ?: return listOf(C2paStatus("assertion.hardBinding.notChecked", u, false, ct("core_c2pa_sidecar_no_asset")))
        val d = runCatching { Cbor.decode(multi.first().content("cbor") ?: throw IllegalArgumentException()) }.getOrNull() ?: return malformed("core_c2pa_multi_asset_malformed")
        val items = (d.getOrNullAny("parts") as? CborArray)?.items
        if (items.isNullOrEmpty()) return malformed("core_c2pa_multi_asset_malformed")
        val size = asset.size.toLong()
        val roots = if (store.format == C2paFormat.BMFF) runCatching { C2paBmff.tree(asset) }.getOrNull() else null
        val parts = ArrayList<Part>()
        val skipped = ArrayList<C2paStatus>()
        for ((k, p) in items.withIndex()) {
            val loc = p.getOrNullAny("location") as? CborMap ?: return malformed("core_c2pa_multi_asset_part", k)
            val ref = C2paManifests.hashedUri(p.getOrNullAny("hashAssertion") ?: return malformed("core_c2pa_multi_asset_part", k)) ?: return malformed("core_c2pa_multi_asset_part", k)
            val optional = p.getOrNullAny("optional") == Simple.TRUE
            val offset = loc.getOrNullAny("byteOffset")
            val length = loc.getOrNullAny("length")
            val xpath = (loc.getOrNullAny("bmffBox") as? Tstr)?.value
            if ((offset != null || length != null) == (xpath != null)) return malformed("core_c2pa_multi_asset_part", k)
            val partBox = store.resolve(ref.url, m) ?: return malformed("core_c2pa_multi_asset_assertion", ref.url)
            if (!DocCrypto.digest(C2paManifests.jcaHash(ref.algorithm ?: m.algorithm), partBox.hashedBytes).contentEquals(ref.hash)) {
                return malformed("core_c2pa_multi_asset_assertion", ref.url)
            }
            val label = partBox.label.orEmpty()
            val base = label.substringBefore("__")
            if (!base.endsWith(".part") || hardLabel(base.removeSuffix(".part")) == null || base.startsWith("c2pa.hash.collection")) {
                return malformed("core_c2pa_multi_asset_assertion", ref.url)
            }
            val partUrl = C2paManifests.absolute(m, ref.url)
            var cover: C2paRange? = null
            val range: C2paRange = if (xpath != null) {
                val box = roots?.let { C2paBmff.select(it, xpath).firstOrNull() }
                if (box == null) {
                    if (optional) { skipped += C2paStatus("assertion.multiAssetHash.missingPart", partUrl, false, ct("core_c2pa_multi_asset_optional", k), informational = true); continue }
                    return malformed("core_c2pa_multi_asset_box", xpath)
                }
                cover = C2paRange(box.start, box.size)
                C2paRange(box.start + box.header, box.size - box.header)
            } else {
                val o = (offset as? CborInt)?.asNumber
                val n = (length as? CborInt)?.asNumber
                if (o == null || n == null || o < 0 || n < 0) return malformed("core_c2pa_multi_asset_part", k)
                if (o >= size && n > 0) {
                    if (optional) { skipped += C2paStatus("assertion.multiAssetHash.missingPart", partUrl, false, ct("core_c2pa_multi_asset_optional", k), informational = true); continue }
                    return listOf(C2paStatus("assertion.multiAssetHash.missingPart", partUrl, false, ct("core_c2pa_multi_asset_missing", k)))
                }
                if (o + n > size) return listOf(C2paStatus("assertion.multiAssetHash.mismatch", partUrl, false, ct("core_c2pa_multi_asset_truncated", k)))
                C2paRange(o, n)
            }
            parts += Part(k, range, cover ?: range, xpath != null, label, partBox, partUrl)
        }
        // The located parts (a bmffBox part with its box header) must be in file order, contiguous and cover every byte.
        var pos = 0L
        for (p in parts) {
            if (p.cover.start != pos) return malformed("core_c2pa_multi_asset_cover")
            pos = p.cover.end
        }
        if (pos != size) return malformed("core_c2pa_multi_asset_cover")
        val out = ArrayList<C2paStatus>()
        for (p in parts) {
            val bytes = asset.copyOfRange(p.range.start.toInt(), p.range.end.toInt())
            val region = store.region?.takeIf { it.start >= p.range.start && it.end <= p.range.end }?.let { C2paRange(it.start - p.range.start, it.length) }
            val format = C2paContainers.detect(bytes)
            val sub = C2paStore(store.container, store.root, store.manifests, bytes, format, region)
            val d2 = runCatching { Cbor.decode(p.box.content("cbor") ?: throw IllegalArgumentException()) }.getOrNull() ?: return malformed("core_c2pa_multi_asset_assertion", p.url)
            val kind = hardLabel(p.label.substringBefore("__").removeSuffix(".part"))
            val result = when (kind) {
                "c2pa.hash.data" -> data(sub, bytes, d2, m, p.url, adjusted && region != null)
                "c2pa.hash.boxes" -> if (format != null && C2paBoxHash.supports(format)) boxes(sub, bytes, d2, m, p.url)
                    else listOf(C2paStatus("assertion.boxesHash.malformed", p.url, false, ct("core_c2pa_boxes_format", format?.title ?: "?")))
                else -> bmff(bytes, d2, p.label.substringBefore(".part"), m, p.url)
            }
            val r = result.first()
            if (!r.success) return listOf(C2paStatus("assertion.multiAssetHash.mismatch", p.url, false, ct("core_c2pa_multi_asset_part_failed", p.index, r.code + (r.explanation?.let { ": $it" } ?: ""))))
            out += C2paStatus("assertion.multiAssetHash.match", p.url, true, ct("core_c2pa_multi_asset_part_ok", p.index, if (p.payload) "bmffBox" else "${p.range.start}+${p.range.length}"))
        }
        return out + skipped
    }

    private fun url(m: C2paManifest, label: String?) = C2paManifests.absolute(m, "self#jumbf=c2pa.assertions/$label")

    // ---------------------------------------------------------------- data hash

    private fun data(store: C2paStore, asset: ByteArray, d: DataItem, m: C2paManifest, u: String, adjusted: Boolean = false): List<C2paStatus> {
        val expected = (d.getOrNullAny("hash") as? Bstr)?.value ?: return listOf(C2paStatus("assertion.dataHash.malformed", u, false))
        val listed = (d.getOrNullAny("exclusions") as? CborArray)?.items.orEmpty().map { e ->
            val start = (e.getOrNullAny("start") as? CborInt)?.asNumber ?: return listOf(C2paStatus("assertion.dataHash.malformed", u, false))
            val length = (e.getOrNullAny("length") as? CborInt)?.asNumber ?: return listOf(C2paStatus("assertion.dataHash.malformed", u, false))
            C2paRange(start, length)
        }.sortedBy { it.start }
        if (listed.any { it.start < 0 || it.length < 0 } || listed.zipWithNext().any { (a, b) -> a.end > b.start }) {
            return listOf(C2paStatus("assertion.dataHash.malformed", u, false, ct("core_c2pa_exclusion_range")))
        }
        val region = store.region
        // After update manifests the store has grown or shrunk where it is: its exclusion takes the current length and
        // the exclusions after it move by the difference (C2PA 15.12.1.1).
        val ranges = if (adjusted && region != null) {
            val at = listed.indexOfFirst { it.start == region.start }
            if (at < 0) listed else {
                val delta = region.length - listed[at].length
                listed.mapIndexed { k, r -> when { k == at -> region; k > at -> C2paRange(r.start + delta, r.length); else -> r } }
            }
        } else listed
        if (ranges.any { it.end > asset.size }) {
            return listOf(C2paStatus("assertion.dataHash.mismatch", u, false, ct("core_c2pa_exclusion_range")))
        }
        if (region != null && region.length > 0 && ranges.none { it == region }) {
            return listOf(C2paStatus("assertion.dataHash.mismatch", u, false, ct("core_c2pa_exclusion_location", store.container)))
        }
        val alg = (d.getOrNullAny("alg") as? Tstr)?.value ?: m.algorithm
        if (!DocCrypto.digest(C2paManifests.jcaHash(alg), without(asset, ranges)).contentEquals(expected)) {
            return listOf(C2paStatus("assertion.dataHash.mismatch", u, false, ct("core_c2pa_data_hash_mismatch")))
        }
        val out = arrayListOf(C2paStatus("assertion.dataHash.match", u, true))
        if (ranges.count { it.length > 0 && it != region } > 0) out += C2paStatus("assertion.dataHash.additionalExclusionsPresent", u, false, ct("core_c2pa_additional_exclusions"), informational = true)
        return out
    }

    /** [b] without the sorted [ranges]. */
    fun without(b: ByteArray, ranges: List<C2paRange>): ByteArray {
        val kept = ArrayList<ByteArray>()
        var pos = 0L
        for (r in ranges.sortedBy { it.start }) {
            if (r.start > pos) kept.add(b.copyOfRange(pos.toInt(), r.start.toInt()))
            pos = maxOf(pos, r.end)
        }
        if (pos < b.size) kept.add(b.copyOfRange(pos.toInt(), b.size))
        return C2paCbor.concat(kept)
    }

    // ---------------------------------------------------------------- box hash

    private fun boxes(store: C2paStore, asset: ByteArray, d: DataItem, m: C2paManifest, u: String): List<C2paStatus> {
        val format = store.format
        if (format == null || !C2paBoxHash.supports(format)) {
            return listOf(C2paStatus("assertion.hardBinding.notChecked", u, false, ct("core_c2pa_boxes_format", store.container)))
        }
        val r = runCatching { C2paBoxHash.verify(asset, format, d, m.algorithm) }.getOrElse { C2paBoxHash.Result("assertion.boxesHash.malformed", detail = it.message) }
        val explanation = when (r.status) {
            "assertion.boxesHash.match" -> null
            "assertion.boxesHash.mismatch" -> ct("core_c2pa_boxes_mismatch", r.detail.orEmpty())
            "assertion.boxesHash.unknownBox" -> ct("core_c2pa_boxes_unknown", r.detail.orEmpty())
            else -> ct("core_c2pa_boxes_malformed")
        }
        val out = arrayListOf(C2paStatus(r.status, u, r.status.endsWith("match") && !r.status.endsWith("mismatch"), explanation))
        if (r.additionalExclusions && out.first().success) out += C2paStatus("assertion.boxesHash.additionalExclusionsPresent", u, false, ct("core_c2pa_additional_exclusions"), informational = true)
        return out
    }

    // ---------------------------------------------------------------- BMFF hash

    private fun bmff(asset: ByteArray, d: DataItem, label: String, m: C2paManifest, u: String): List<C2paStatus> {
        fun malformed(why: String) = listOf(C2paStatus("assertion.bmffHash.malformed", u, false, ct("core_c2pa_bmff_malformed", why)))
        fun mismatch(key: String) = listOf(C2paStatus("assertion.bmffHash.mismatch", u, false, ct(key)))
        val base = label.substringBefore("__")
        val version = when (base) { "c2pa.hash.bmff.v3" -> 3; "c2pa.hash.bmff.v2" -> 2; else -> 1 }
        val a = runCatching { C2paBmff.parse(d) }.getOrElse { return malformed(it.message ?: "CBOR") }
        if (a.exclusions.isEmpty()) return malformed("no exclusions")
        for (x in a.exclusions) {
            val s = x.subset ?: continue
            if (s.zipWithNext().any { (p, q) -> p.offset > q.offset || p.offset + p.length > q.offset }) return malformed("subsets out of order")
        }
        val alg = a.alg ?: m.algorithm ?: "sha256"
        fun evaluate(ex: C2paBmff.Excluded): List<C2paStatus> {
            val notes = ArrayList<C2paStatus>()
            if (a.hash != null && !C2paBmff.hash(asset, ex, alg).contentEquals(a.hash)) return mismatch("core_c2pa_bmff_mismatch")
            if (a.merkle.isNotEmpty()) {
                val top = C2paBmff.topLevel(asset)
                val size = asset.size.toLong()
                val firstMoof = top.firstOrNull { it.type == "moof" }
                val fragments = C2paBmff.fragments(top)
                val aux = C2paBmff.auxMerkle(asset)
                for (mm in a.merkle) {
                    val init = mm.initHash ?: continue
                    // A flat fragmented file hashes what precedes the first moof; an initialization segment file of
                    // fragments kept in other files hashes all of it. A non-fragmented file has no initHash.
                    val extra = when {
                        firstMoof != null -> listOf(C2paRange(firstMoof.start, size - firstMoof.start))
                        top.any { it.type == "mdat" } -> return malformed("initHash in a file that is not fragmented")
                        else -> emptyList()
                    }
                    if (!C2paBmff.hash(asset, ex, mm.alg ?: alg, extra).contentEquals(init)) return mismatch("core_c2pa_bmff_merkle_mismatch")
                }
                fun auxOf(mm: C2paBmff.MerkleMap) = aux.filter { it.uniqueId == mm.uniqueId && it.localId == mm.localId }
                // The proofs of auxiliary boxes: locations 0, 1, 2... in file order, each leading to the stored row.
                fun proofs(mm: C2paBmff.MerkleMap, leaves: List<ByteArray>, group: List<C2paBmff.AuxMerkle>): Boolean =
                    group.sortedBy { it.offset }.withIndex().all { (k, x) ->
                        x.location == k.toLong() && x.location < leaves.size &&
                            C2paBmff.checkMerkleTree(mm, mm.alg ?: alg, leaves[x.location.toInt()], x.location, x.hashes)
                    }
                when {
                    fragments.isNotEmpty() -> {
                        if (aux.isEmpty()) return malformed("no merkle boxes")
                        for (mm in a.merkle) {
                            val leaves = fragments.map { chunk ->
                                C2paBmff.hash(asset, ex, mm.alg ?: alg, listOf(C2paRange(0, chunk.first().start), C2paRange(chunk.last().end, size - chunk.last().end)))
                            }
                            if (mm.count != leaves.size || !sameLayer(leaves, mm, alg)) return mismatch("core_c2pa_bmff_merkle_mismatch")
                            if (!proofs(mm, leaves, auxOf(mm))) return mismatch("core_c2pa_bmff_merkle_mismatch")
                        }
                    }
                    firstMoof == null && a.merkle.all { it.initHash != null } && top.none { it.type == "mdat" } ->
                        notes += C2paStatus("assertion.bmffHash.match", u, true, ct("core_c2pa_bmff_init_only"), informational = true)
                    else -> {
                        // Non-fragmented (C2PA 15.12.2.1): the Merkle tree localId covers the mdat of that index, its payload
                        // whole or in fixed or variable blocks; a row above the leaves needs the auxiliary boxes.
                        val failure = mdatMerkle(asset, top, a, alg, ::auxOf, ::proofs)
                        if (failure != null) {
                            // c2pa-rs builds a tree without block sizes over the chunks of the track localId names
                            // (media time), verified through the auxiliary boxes; that reading is the fallback.
                            if (timedMedia(asset, a, alg, aux)) notes += C2paStatus("assertion.bmffHash.match", u, true, ct("core_c2pa_bmff_timed_fallback"), informational = true)
                            else return failure.let { (code, key) -> listOf(C2paStatus(code, u, false, if (code.endsWith("malformed")) ct("core_c2pa_bmff_malformed", key) else ct(key))) }
                        }
                    }
                }
            } else if (a.hash == null) return malformed("no hash")
            val out = arrayListOf(C2paStatus("assertion.bmffHash.match", u, true, notes.firstOrNull { it.code == "assertion.bmffHash.match" }?.explanation))
            out += notes.filter { it.code != "assertion.bmffHash.match" }
            if (a.exclusions.any { !standard(it) }) out += C2paStatus("assertion.bmffHash.additionalExclusionsPresent", u, false, ct("core_c2pa_additional_exclusions"), informational = true)
            return out
        }
        return runCatching {
            // Flags of an exclusion that is not exact are matched as the specification reads first; only when that
            // gives a mismatch is the c2pa-rs reading tried, and a match through it is reported as such.
            val standardEx = C2paBmff.excluded(asset, a.exclusions, version > 1)
            val first = evaluate(standardEx)
            if (first.first().success || a.exclusions.none { it.exact == false && it.flags != null }) return@runCatching first
            val fallbackEx = C2paBmff.excluded(asset, a.exclusions, version > 1, C2paBmff.FlagMatch.C2PA_RS)
            if (fallbackEx.ranges == standardEx.ranges && fallbackEx.offsets == standardEx.offsets) return@runCatching first
            val second = evaluate(fallbackEx)
            if (!second.first().success) first
            else second + C2paStatus("assertion.bmffHash.match", u, true, ct("core_c2pa_bmff_flags_fallback"), informational = true)
        }.getOrElse { malformed(it.message ?: "BMFF") }
    }

    private fun standard(x: C2paBmff.Exclusion): Boolean = when (x.xpath) {
        "/uuid" -> x.data.size == 1 && x.data[0].offset == 8L && x.data[0].value.contentEquals(C2paBmff.UUID)
        "/ftyp", "/mfra", "/free", "/skip" -> true
        else -> false
    }

    private fun sameLayer(leaves: List<ByteArray>, mm: C2paBmff.MerkleMap, alg: String): Boolean {
        if (mm.hashes.isEmpty()) return false
        val layer = C2paBmff.merkleLayer(leaves, mm.hashes.size, mm.alg ?: alg) ?: return false
        return layer.zip(mm.hashes).all { (x, y) -> x.contentEquals(y) }
    }

    /**
     * Checks the Merkle trees of a non-fragmented file over its mdat boxes; null when they match, else the failure code
     * and the explanation key (or reason for malformed).
     */
    private fun mdatMerkle(
        asset: ByteArray,
        top: List<C2paBmff.Box>,
        a: C2paBmff.Assertion,
        alg: String,
        auxOf: (C2paBmff.MerkleMap) -> List<C2paBmff.AuxMerkle>,
        proofs: (C2paBmff.MerkleMap, List<ByteArray>, List<C2paBmff.AuxMerkle>) -> Boolean,
    ): Pair<String, String>? {
        val mdats = top.filter { it.type == "mdat" }
        if (mdats.size != a.merkle.size || a.merkle.map { it.localId }.toSet().size != a.merkle.size) return "assertion.bmffHash.mismatch" to "core_c2pa_bmff_merkle_mismatch"
        for (mm in a.merkle) {
            val box = mdats.getOrNull(mm.localId.toInt()) ?: return "assertion.bmffHash.mismatch" to "core_c2pa_bmff_merkle_mismatch"
            if (mm.fixedBlockSize != null && mm.variableBlockSizes != null) return "assertion.bmffHash.malformed" to "fixedBlockSize and variableBlockSizes"
            if (mm.variableBlockSizes != null && mm.variableBlockSizes.size != mm.count) return "assertion.bmffHash.malformed" to "variableBlockSizes count"
            val blocks = runCatching { mdatBlocks(box, mm) }.getOrElse { return "assertion.bmffHash.malformed" to (it.message ?: "blocks") }
            if (mm.count < blocks.size) return "assertion.bmffHash.malformed" to "count"
            val leaves = blocks.map { r -> DocCrypto.digest(C2paManifests.jcaHash(mm.alg ?: alg), asset.copyOfRange(r.start.toInt(), r.end.toInt())) }
            if (mm.count > mm.hashes.size && auxOf(mm).isEmpty()) return "assertion.bmffHash.malformed" to "no merkle boxes"
            if (leaves.size != mm.count || !sameLayer(leaves, mm, alg) || !proofs(mm, leaves, auxOf(mm))) return "assertion.bmffHash.mismatch" to "core_c2pa_bmff_merkle_mismatch"
        }
        return null
    }

    /**
     * The c2pa-rs reading of a Merkle tree without block sizes in a file with a moov: per Merkle map, the leaves are the
     * chunks of the track whose track_ID is its localId (the sample data of each chunk), and the auxiliary boxes, taken
     * count at a time in the order of the maps, prove each leaf at locations 0, 1, 2... in file order.
     */
    private fun timedMedia(asset: ByteArray, a: C2paBmff.Assertion, alg: String, aux: List<C2paBmff.AuxMerkle>): Boolean = runCatching {
        if (aux.isEmpty() || a.merkle.any { it.fixedBlockSize != null || it.variableBlockSizes != null }) return false
        if (C2paBmff.topLevel(asset).none { it.type == "moov" }) return false
        var rest = aux
        for (mm in a.merkle) {
            if (mm.count > rest.size) return false
            val group = rest.take(mm.count)
            rest = rest.drop(mm.count)
            val chunks = C2paBmff.trackChunks(asset, mm.localId) ?: return false
            val jca = C2paManifests.jcaHash(mm.alg ?: alg)
            val sorted = group.sortedBy { it.offset }
            if (sorted.withIndex().any { (k, x) -> x.location != k.toLong() }) return false
            for (x in sorted) {
                val ranges = chunks[x.location + 1] ?: return false
                val leaf = DocCrypto.digest(jca, C2paCbor.concat(ranges.map { asset.copyOfRange(it.start.toInt(), it.end.toInt()) }))
                if (!C2paBmff.checkMerkleTree(mm, mm.alg ?: alg, leaf, x.location, x.hashes)) return false
            }
        }
        true
    }.getOrDefault(false)

    /** The leaf ranges of an mdat box: its payload after 16 bytes, in fixed or variable blocks, or whole. */
    private fun mdatBlocks(box: C2paBmff.Box, mm: C2paBmff.MerkleMap): List<C2paRange> {
        val start = box.start + 16
        val total = maxOf(0L, box.size - 16)
        val fixed = mm.fixedBlockSize
        val variable = mm.variableBlockSizes
        return when {
            fixed != null -> {
                if (fixed <= 1) throw IllegalArgumentException("fixed block size")
                val out = ArrayList<C2paRange>()
                var p = start
                var left = total
                while (left > 0) { val n = minOf(left, fixed); out.add(C2paRange(p, n)); p += n; left -= n }
                out
            }
            variable != null -> {
                if (variable.sum() != total) throw IllegalArgumentException("variable block sizes")
                var p = start
                variable.map { n -> C2paRange(p, n).also { p += n } }
            }
            else -> listOf(C2paRange(start, total))
        }
    }

    // ---------------------------------------------------------------- collection hash

    private fun collection(store: C2paStore, asset: ByteArray, d: DataItem, m: C2paManifest, u: String): List<C2paStatus> {
        fun status(code: String, key: String, vararg args: Any?) = listOf(C2paStatus(code, u, false, ct(key, *args)))
        if (store.format != C2paFormat.ZIP) return listOf(C2paStatus("assertion.hardBinding.notChecked", u, false, ct("core_c2pa_collection_external")))
        val archive = runCatching { C2paZip.read(asset) }.getOrElse { return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed") }
        val alg = (d.getOrNullAny("alg") as? Tstr)?.value ?: m.algorithm ?: "sha256"
        val cd = (d.getOrNullAny("zip_central_directory_hash") as? Bstr)?.value ?: return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed")
        if ((0..2).none { C2paZip.centralDirectoryHash(asset, archive, alg, it).contentEquals(cd) }) return status("assertion.collectionHash.mismatch", "core_c2pa_collection_cd_mismatch")
        // uris: an array of maps; older c2pa-rs wrote a map keyed by URI.
        val listed: List<Pair<String, DataItem>> = when (val x = d.getOrNullAny("uris")) {
            is CborArray -> x.items.map { e -> ((e.getOrNullAny("uri") as? Tstr)?.value ?: return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed")) to e }
            is CborMap -> x.items.entries.map { (k, v) -> ((k as? Tstr)?.value ?: return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed")) to v }
            else -> return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed")
        }
        if (listed.isEmpty()) return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed")
        // Two entries (or two listed URIs) of one name: a check of one would vouch for the other, which is never read.
        val entryUris = archive.entries.map { C2paZip.uri(it) }
        entryUris.groupingBy { it }.eachCount().entries.firstOrNull { it.value > 1 }?.let { return status("assertion.collectionHash.malformed", "core_c2pa_collection_duplicate", it.key) }
        listed.map { it.first.replace('\\', '/').trimEnd('/') }.groupingBy { it }.eachCount().entries.firstOrNull { it.value > 1 }
            ?.let { return status("assertion.collectionHash.malformed", "core_c2pa_collection_duplicate", it.key) }
        val byUri = archive.entries.filter { it.name != C2paZip.MANIFEST }.associateBy { C2paZip.uri(it) }
        for ((uri, e) in listed) {
            val norm = uri.replace('\\', '/').trimEnd('/')
            if (!C2paZip.validUri(norm)) {
                return status("assertion.collectionHash.invalidURI", "core_c2pa_collection_uri", uri)
            }
            val entry = byUri[norm] ?: return status("assertion.collectionHash.incorrectFileCount", "core_c2pa_collection_count", uri)
            val hash = (e.getOrNullAny("hash") as? Bstr)?.value ?: return status("assertion.collectionHash.malformed", "core_c2pa_collection_malformed")
            val r = C2paZip.range(asset, entry)
            if (!DocCrypto.digest(C2paManifests.jcaHash(alg), asset.copyOfRange(r.start.toInt(), r.end.toInt())).contentEquals(hash)) {
                return status("assertion.collectionHash.mismatch", "core_c2pa_collection_mismatch", uri)
            }
        }
        val names = listed.map { it.first.replace('\\', '/').trimEnd('/') }.toSet()
        val unlisted = byUri.filter { (k, v) -> !v.directory && k !in names }.keys
        if (unlisted.isNotEmpty()) return status("assertion.collectionHash.incorrectFileCount", "core_c2pa_collection_count", unlisted.first())
        return listOf(C2paStatus("assertion.collectionHash.match", u, true))
    }
}

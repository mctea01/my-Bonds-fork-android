package diw.wallet.core.document.c2pa

import diw.wallet.core.document.DocCrypto
import diw.wallet.core.i18n.ct
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.CborArray
import org.multipaz.cbor.CborInt
import org.multipaz.cbor.CborMap
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tstr

/**
 * Checks the hard binding of a manifest over its asset (C2PA 15.12): the data hash with the rule that one exclusion
 * is exactly the store's location, the box hash, the BMFF hash (file hash, Merkle trees over mdat blocks and
 * fragments) and the collection hash of a ZIP. The first status is the result; informational ones follow
 * (additional exclusions, what could not be checked).
 */
object C2paBindings {
    private val HARD = listOf("c2pa.hash.data", "c2pa.hash.boxes", "c2pa.hash.bmff", "c2pa.hash.collection.data", "c2pa.hash.multi-asset")

    /** The base label of a hard binding assertion ([label] without an instance suffix), or null. */
    fun hardLabel(label: String?): String? {
        val base = label?.substringBefore("__") ?: return null
        return HARD.firstOrNull { base == it || (it == "c2pa.hash.bmff" && (base == "c2pa.hash.bmff.v2" || base == "c2pa.hash.bmff.v3")) }
    }

    fun check(store: C2paStore, m: C2paManifest): List<C2paStatus> {
        val signed = C2paManifests.signedAssertions(m)
        val hard = signed.filter { hardLabel(it.label) != null }
        if (hard.isEmpty()) {
            val unsigned = m.box.child("c2pa.assertions")?.children.orEmpty().firstOrNull { hardLabel(it.label) != null } ?: return emptyList()
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
            "c2pa.hash.data" -> d?.let { data(store, asset, it, m, u) } ?: listOf(C2paStatus("assertion.dataHash.malformed", u, false))
            "c2pa.hash.boxes" -> d?.let { boxes(store, asset, it, m, u) } ?: listOf(C2paStatus("assertion.boxesHash.malformed", u, false))
            "c2pa.hash.bmff" -> d?.let { bmff(asset, it, label, m, u) } ?: listOf(C2paStatus("assertion.bmffHash.malformed", u, false))
            "c2pa.hash.collection.data" -> d?.let { collection(store, asset, it, m, u) } ?: listOf(C2paStatus("assertion.collectionHash.malformed", u, false))
            else -> listOf(C2paStatus("assertion.hardBinding.notChecked", u, false, ct("core_c2pa_multi_asset")))
        }
    }

    private fun url(m: C2paManifest, label: String?) = C2paManifests.absolute(m, "self#jumbf=c2pa.assertions/$label")

    // ---------------------------------------------------------------- data hash

    private fun data(store: C2paStore, asset: ByteArray, d: DataItem, m: C2paManifest, u: String): List<C2paStatus> {
        val expected = (d.getOrNullAny("hash") as? Bstr)?.value ?: return listOf(C2paStatus("assertion.dataHash.malformed", u, false))
        val ranges = (d.getOrNullAny("exclusions") as? CborArray)?.items.orEmpty().map { e ->
            val start = (e.getOrNullAny("start") as? CborInt)?.asNumber ?: return listOf(C2paStatus("assertion.dataHash.malformed", u, false))
            val length = (e.getOrNullAny("length") as? CborInt)?.asNumber ?: return listOf(C2paStatus("assertion.dataHash.malformed", u, false))
            C2paRange(start, length)
        }.sortedBy { it.start }
        if (ranges.any { it.start < 0 || it.length < 0 || it.end > asset.size }) {
            return listOf(C2paStatus("assertion.dataHash.mismatch", u, false, ct("core_c2pa_exclusion_range")))
        }
        val region = store.region
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
        val result = runCatching {
            val ex = C2paBmff.excluded(asset, a.exclusions, version > 1)
            val notes = ArrayList<C2paStatus>()
            if (a.hash != null && !C2paBmff.hash(asset, ex, alg).contentEquals(a.hash)) return mismatch("core_c2pa_bmff_mismatch")
            if (a.merkle.isNotEmpty()) {
                val top = C2paBmff.topLevel(asset)
                val size = asset.size.toLong()
                val firstMoof = top.firstOrNull { it.type == "moof" }
                val fragments = C2paBmff.fragments(top)
                for (mm in a.merkle) {
                    val init = mm.initHash ?: continue
                    val extra = if (firstMoof != null) listOf(C2paRange(firstMoof.start, size - firstMoof.start)) else emptyList()
                    if (!C2paBmff.hash(asset, ex, mm.alg ?: alg, extra).contentEquals(init)) return mismatch("core_c2pa_bmff_merkle_mismatch")
                }
                when {
                    fragments.isNotEmpty() -> for (mm in a.merkle) {
                        val leaves = fragments.map { chunk ->
                            C2paBmff.hash(asset, ex, mm.alg ?: alg, listOf(C2paRange(0, chunk.first().start), C2paRange(chunk.last().end, size - chunk.last().end)))
                        }
                        if (mm.count != leaves.size || !sameLayer(leaves, mm, alg)) return mismatch("core_c2pa_bmff_merkle_mismatch")
                    }
                    firstMoof == null && a.merkle.all { it.initHash != null } && top.none { it.type == "mdat" } ->
                        notes += C2paStatus("assertion.bmffHash.match", u, true, ct("core_c2pa_bmff_init_only"), informational = true)
                    a.merkle.all { it.fixedBlockSize != null || it.variableBlockSizes != null } -> {
                        val mdats = top.filter { it.type == "mdat" }
                        if (mdats.size != a.merkle.size) return mismatch("core_c2pa_bmff_merkle_mismatch")
                        for ((box, mm) in mdats.zip(a.merkle)) {
                            val leaves = mdatBlocks(box, mm).map { r -> DocCrypto.digest(C2paManifests.jcaHash(mm.alg ?: alg), asset.copyOfRange(r.start.toInt(), r.end.toInt())) }
                            if (leaves.size != mm.count || !sameLayer(leaves, mm, alg)) return mismatch("core_c2pa_bmff_merkle_mismatch")
                        }
                    }
                    else -> notes += C2paStatus("assertion.bmffHash.notChecked", u, false, ct("core_c2pa_bmff_timed_merkle"), informational = true)
                }
                if (a.hash == null && notes.any { it.code == "assertion.bmffHash.notChecked" }) {
                    return listOf(C2paStatus("assertion.hardBinding.notChecked", u, false, ct("core_c2pa_bmff_timed_merkle")))
                }
            } else if (a.hash == null) return malformed("no hash")
            val out = arrayListOf(C2paStatus("assertion.bmffHash.match", u, true, notes.firstOrNull { it.code == "assertion.bmffHash.match" }?.explanation))
            out += notes.filter { it.code != "assertion.bmffHash.match" }
            if (a.exclusions.any { !standard(it) }) out += C2paStatus("assertion.bmffHash.additionalExclusionsPresent", u, false, ct("core_c2pa_additional_exclusions"), informational = true)
            out
        }
        return result.getOrElse { malformed(it.message ?: "BMFF") }
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

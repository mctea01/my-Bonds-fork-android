# zkPDF v1 public-input and witness ABI draft (Round 10)

Review status: **draft for Claude; not frozen and not a release allowlist**.
Design authority: `docs/design/p4-circuits.md` 1.1–1.2, 3.2–3.3 and
3.12.1–3.12.8, integration `9810ab7`. This document records the actual candidate
Noir ABI. Rust M3c and Kotlin implementation are outside this change.

## Profiles and encodings

| Composition ID | P = SEG_PLAIN | T0 | T | B | W | K | O = SEG_OPS |
|---|---:|---:|---:|---:|---:|---:|---:|
| `zkpdf-v1-phone` | 2048 | 1024 | 352 | 1 | 16 | 1 | 64 |
| `zkpdf-v1-desktop` | 4096 | 1536 | 576 | 1 | 8 | 1 | 128 |

Both use N=MAX_COMPRESSED=8192, MAX_PLAIN=40960, global tokens=6144,
global DEFLATE blocks=4, M=MAX_OPS=512, A=MAX_ANCHORS=16,
C=MAX_CLAIMS=12, Q=MAX_CLAIM_SRC=384, R=MAX_ANCHOR_SRC=96,
D=MAX_DIGIT_FONTS=4, V=MAX_PREDICATES=2. Both use one claim circuit
covering slots 0–11 and zero or one predicate circuit. SHA content B=130 and
opaque B=128 are shared. `tools/formal_profiles.py::validate` rejects mismatched
N, P, M and other composition constants. A verification key is selected by
**composition ID and circuit kind**, never by the circuit-name Field alone.

| Kind | ASCII circuit-name Field | Phone package | Desktop package |
|---|---|---|---|
| SHA content | `pdf_sha_content_v1` | same name | shared |
| SHA opaque | `pdf_sha_opaque_v1` | same name | shared |
| Inflate first | `pdf_inflate_seg0_v1` | same name | name + `_desktop` |
| Inflate general | `pdf_inflate_seg_v1` | same name | name + `_desktop` |
| Lexical | `pdf_lex_seg_v1` | same name | name + `_desktop` |
| Claim | `pdf_claim_v1` | same name | shared |
| Predicate | `pdf_pred_v1` | same name | shared |

Desktop source packages are under `profiles/desktop/`. Phone and shared source
packages are at the workspace root. `VERSIONS` gives ACIR JSON and VK file
SHA-256 digests for these exact packages; historical component hashes are not
composition keys. ACIR hash means SHA-256 over the complete emitted JSON file,
not only its base64 bytecode. Compiler source maps can affect this digest.

Encoding is over the BN254 scalar field
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
A scalar `Field` occupies one field element, canonically represented in 32-byte
big-endian form in bb public-input files. Integers `u8/u16/u32/u64` occupy one
Field each with their unsigned numeric value; bool is 0 or 1. Arrays flatten in
index order, nested arrays in row-major order, structs in declaration order.
There are no array-length prefixes in the ABI. `domain` is always the ASCII
big-endian integer of `diw-zkpdf-v1`; `circuit` is the ASCII big-endian integer
listed above. All circuit mains constrain both constants.

`pack31(bytes[N])` is ceil(N/31) Fields: each group is a big-endian integer;
the final short group is **left** zero padded, never right padded. SHA keystream
has 265 Fields (264 groups of 31 bytes and one group of 8). Each head/tail
buffer is first zero padded to 63 bytes and then packed as 31+31+1 bytes.
The unpacker rejects
values with excess high bytes, including a final group >=2^64. Commitment
buffers are zero padded to their fixed capacity before pack31; actual length is
included separately in the commitment preimage.

**Encoding issue for Claude:** existing lexical, claim and predicate mains
expose byte arrays as one `u8` per Field (beta, anchors, digests and font names).
This draft preserves that Round 9 ABI. The new SHA head/tail, SHA keystream
and internal commitment preimages use pack31. The inherited byte arrays differ
from the blanket public-byte packing rule in section 1.1.3;
Claude must resolve the wording or request an ABI revision before freezing.
The counts below describe what is actually compiled, with no hidden transport
repacking. No change to the design authority file is made here.

## Public inputs in exact order

Offsets below are zero based, inclusive. Counts exclude the proof itself.

### SHA content: 294 Fields (9,408 bytes), both tiers

| Offsets | Name | Encoding / count |
|---|---|---|
| 0–1 | domain, circuit | Field each |
| 2–9 | mid_in (H_s) | 8 u32, SHA word order |
| 10–17 | mid_out (H_e) | 8 u32 |
| 18 | blocks | u32 |
| 19 | head_len | u32 |
| 20–22 | head | pack31 of 63 bytes: 3 Fields |
| 23 | tail_len | u32 |
| 24–26 | tail | pack31 of 63 bytes: 3 Fields |
| 27 | encrypted | bool |
| 28–292 | keystream | 265 pack31 Fields |
| 293 | cz | Field |

`n = 64*blocks-head_len-tail_len` is derived, not an independent witness or
public input. Require 0<n<=8192. Head/tail lengths are <=63; unused bytes and
unused SHA blocks are zero. Unencrypted keystream is entirely zero; encrypted
keystream is zero from n to 8191. No SHA padding is permitted in private windows
by the external verifier.

### SHA opaque: 27 Fields (864 bytes), both tiers

Exactly SHA-content offsets 0–26. No encrypted flag, key, C_z or salt.
Private stream length is the same derived expression and must be positive.

### Inflate first: 9 Fields (288 bytes), both tiers

`domain, circuit, index:u32, first:bool, last:bool, cz, sin, sout, cp`.
Index=0, first=true, sin=0. `last` may be true for a single-segment stream.

### Inflate general: phone 25 Fields (800 bytes); desktop 17 (544 bytes)

Same first nine Fields, then `previous[W]` Fields in oldest-to-newest order:
slot w is absolute index `index-W+w`. A negative absolute index is zero.
Index>0 and first=false. The verifier supplies prior actual C_p values.

### Lexical: 1,646 Fields (52,672 bytes), both tiers

| Offsets | Name | Encoding / count |
|---|---|---|
| 0–1 | domain, circuit | 2 Fields |
| 2–4 | index, first, last | u32, bool, bool |
| 5–7 | cz, lin, lout | 3 Fields |
| 8 | cp[0] | 1 Field (K=1) |
| 9–1608 | anchors[16] | each 100 Fields, struct below |
| 1609–1644 | slots[12] | each 3 Fields |
| 1645 | cg | Field |

Anchor struct: `enabled:bool, len:u32, raw[96]:u8, ordinal:u32, total:u32`.
Slot struct: `enabled:bool, before:u32, after:u32` (indices into anchors).
Final anchors must match template ordinal/total policy and have nonzero ordinal
when enabled. Every non-final segment has ordinal=total=0 for **all** anchors,
and cg=0. Compare anchor content and slot selections across all segments;
compare ordinal/total only at the final segment. First lin=0.

### Claim: 2,058 Fields (65,856 bytes), both tiers

| Offsets | Name | Encoding / count |
|---|---|---|
| 0–1 | domain, circuit | 2 Fields |
| 2–33 | beta | 32 u8 |
| 34–35 | start, count | u32, constants 0 and 12 |
| 36 | cz | Field |
| 37–1636 | anchors | 16 × 100 Fields |
| 1637–1672 | slots | 12 × 3 Fields |
| 1673 | cg | Field |
| 1674–2057 | digests | 12 × 32 u8, slot order |

Disabled slots have zero digests. Every slot, including an unrevealed predicate
input, has its enabled digest proved. A zero salt or noncanonical irrelevant
private hint is not a random-salt guarantee: freshness is the prover's duty.

### Predicate: 1,798 Fields (57,536 bytes), both tiers

| Offsets | Name | Encoding / count |
|---|---|---|
| 0–1 | domain, circuit | 2 Fields |
| 2–33 | beta | 32 u8 |
| 34 | cz | Field |
| 35–1634 | anchors | 16 × 100 Fields |
| 1635–1670 | slots | 12 × 3 Fields |
| 1671 | cg | Field |
| 1672–1787 | fonts | 4 × 29 Fields |
| 1788–1797 | predicates | 2 × 5 Fields |

DigitFont struct has **29** Fields: `enabled:bool, len:u32, name[16]:u8,
width:u8, digits[10]:u16`. Predicate struct has 5 Fields:
`enabled:bool, kind:u8, slot:u32, format:u8, cutoff:u32`.
DATE_LE=0, DATE_GE=1, format=0 (Gregorian YYYY, M[M], D[D]).
Disabled selections are ignored by the date decoder; the verifier supplies
canonical all-zero disabled predicates. Active font names and ten digit codes
must be unique. Width is 1 or 2.

## Private Prover.toml inputs

Prover.toml contains **both** the public parameters above and private parameters
below, using exact ABI names. Use decimal integers for unsigned integers, TOML
true/false for bools, and quoted `"0x..."` strings for Field values. Arrays have
exact fixed lengths, including all zero padding. Structs use inline TOML tables
or equivalent tables. `tools/pdf_fixture_chain.py` emits complete accepted
examples under ignored `target/`; it never prints witness values. All synthetic
salts are 42 / deterministic bytes; real M3c must sample fresh private salts.

| Circuit | Private inputs, in main declaration order |
|---|---|
| SHA content | `bytes:[u8;8320]`, `salt:Field` |
| SHA opaque | `bytes:[u8;8192]` |
| Inflate first | salt, data[8192]:u8, data_len:u32, incoming:State, resumed_l:Huffman<288>, resumed_d:Huffman<32>, headers:[BlockHint;1], header_count:u32, events:[Event;T0+1], event_count:u32, hints:SegmentHints<T0+1,1>, plain[P]:u8, plain_len:u32, owners[P]:u32 |
| Inflate general | same, using T+1 events; `history:[[u8;P];W]` between hints and plain |
| Lexical | salt, plain:[[u8;P];1], lengths:[u32;1], incoming:LexState<16,12>, plan:Plan<16,12,384>, positions:[u32;O], used:u32 |
| Claim | salt, plan:Plan<16,12,384>, claim_salts:[[u8;16];12] |
| Predicate | salt, plan:Plan<16,12,384> |

Plan fields: `anchor_ops:[u32;16], lengths:[u32;12], records:[[u8;384];12]`.
Each record is v2: `u8 font_length || font || u8 kind || u8 string_count ||
(u16be string_length || raw_string_bytes)*`. The kind is 0 literal / 1 hex.
Raw strings exclude their delimiters, retain escapes and hex whitespace, and
have separate lengths. A claim contains the exact ordered concatenation of
records strictly between its boundary anchors. No operation-position table
outside the lexical `positions` and `used` is part of the ABI.

Huffman<N>: `lengths:[u8;N], codes:[u32;N]`.
TokenHint: `block:u32,start:u32,symbol:u16,width:u8,distance_symbol:u8,
distance_width:u8,prefix:u8,suffix:u64`. Event: `action:u8, token:TokenHint`;
action 0 inactive, 1 header, 2 token. All arrays are immutable advice checked
by the circuit; they do not authorize skipping source data.

BlockHint fields in order:
`start:u32,end:u32,first_token:u32,tokens:u32,code_symbols:[u16;320],
code_widths:[u8;320],cl_lengths:[u8;19],cl_codes:[u32;19],
expanded_lengths:[u8;320],cl_prefixes:[u16;285],ll_prefixes:[u16;4320],
dd_prefixes:[u16;480],cl_first:[u32;16],ll_first:[u32;16],dd_first:[u32;16],
header_repeats:[u8;320],header_prefixes:[u8;320],header_suffixes:[u32;320]`.

SegmentHints<E,1> fields in order:
`ll_lengths:[u8;576],ll_codes:[u32;576],dd_lengths:[u8;64],dd_codes:[u32;64],
starts:[u32;E+1],ends:[u32;E+1],distances:[u32;E+1],symbols:[u16;E+1],
lengths:[u32;E],token_distances:[u32;E]`. E=T0+1 for first, T+1 otherwise.
First table slot is the resumed table; second is the one possible new block.
Owners index pending-copy slot 0 or event+1. Missing history bytes are zero.

State TOML declaration order is its commitment order below. LexState TOML
**declaration** order differs from commitment order: pos,mode,depth,escaped,dict,
array,closed,bt,font,font_len,name,name_len,font_fp,font_power,name_fp,name_power,
word,word_len,long_word,pending,kind,raw_fp,raw_power,raw_len,strings_fp,
strings_power,strings_len,strings,ops,counts[16],ordinals[16],values[12],
lengths[12],slot,field_fp,field_len,pi,r. TOML table order is semantically
irrelevant, but the names and types are not. Types follow the next section.

## Frozen-order proposal: commitments and states

All commitments use `commit(tag,salt,fields) = hash_fields([tag,salt,len(fields),
fields...])`. Poseidon2 width=4, rate=3, additive absorb, IV=len(input_fields)<<64,
zero-filled final rate, output state[0]. `tools/poseidon_reference.py` and
Noir's `commitment.nr` implement the same fixed-length sponge. The salt is a
single private Field with at least 248 bits of fresh entropy per evidence.

C_z tag 1: `[n,pack31(z zero-padded to 8192)...]` (266 data Fields).
C_p tag 2: `[index,n,pack31(plain zero-padded to P)...]` (69/135 data Fields).
Huffman tag 3: LL lengths[288], LL codes[288], DD lengths[32], DD codes[32].
Pi tag 6: anchor_ops[16], then each slot's length followed by pack31(records[384]);
184 data Fields. A=hash_fields(pack31(anchor enabled/len_be16/raw[96] for all
anchors, then slot enabled/before_be32/after_be32 for all slots)); 1692 bytes,
55 Fields. r=hash_fields([7,C_z,Pi,A]). C_g tag 8: 12 interleaved G/length pairs.
Pi stays private: equality of records across kinds follows the specified C_g
fingerprint argument, not an external equality comparison of Pi.

State S (tag 4), 13 Fields, **this order is proposed frozen**:

`pos,output,tokens,blocks,phase,kind,final_block,table_commitment,pending_len,
pending_dist,a,b,stored_end`.

All are u32 except phase/kind u8, final_block bool, table_commitment Field.
Initial S=(16,0,0,0,0,0,false,0,0,0,1,0,0). First sin is constant zero,
not commit(initial). stored_end is necessary for mid-stored-block continuation.

Lambda (tag 5), 90 Fields, **this order is proposed frozen**:

| Offset | Field(s) |
|---|---|
| 0–20 | pos,mode,depth,escaped,dict,array,closed,bt,font_len,name_len,word,word_len,long_word,pending,kind,raw_fp,raw_power,raw_len,ops,pi,r |
| 21–26 | font,name,font_fp,font_power,name_fp,name_power |
| 27–58 | counts[a],ordinals[a] interleaved for a=0..15 |
| 59–82 | values[c],lengths[c] interleaved for c=0..11 |
| 83–85 | slot,field_fp,field_len |
| 86–89 | strings_fp,strings_power,strings_len,strings |

Field-valued members: pi,r,font,name, all *_fp, all *_power, values[].
Booleans: escaped,array,closed,bt,long_word,pending. mode/kind are u8; all other
scalar counters and counts/ordinals/lengths arrays are u32. This is the exact
`lex_segment.nr::state_commit` order; it includes all four v2 string fields.
font/name encode at most 16 bytes as big-endian integers, with separate length.
First lin=0. Initialization sets fingerprint accumulators to zero and powers to
one, pi/r to derived values and slot to the first enabled slot (or C).

## External verifier checklist

1. Select a permitted composition ID, template version and exact ACIR/VK hashes
   (V1). Require the seven role-specific kinds and parameters above. Do not mix
   phone/desktop plaintext capacities or key variants. Verify counts/capacities
   before witness generation too; no silent fallback or alternate segmentation.
2. Decode the redacted document with bounded resources and require its declared
   exact length (V2). Select the signed revision using ByteRange. Validate ordered,
   nonoverlapping in-range ByteRange intervals and exclude signature Contents.
   Stream ranges must be contained in signed intervals. Aligned windows must not
   overlap **each other at block granularity** or contain any SHA padding block.
   Alignment is in the concatenated ByteRange message, not absolute file offsets. Require exactly one content and at most one opaque.
3. Parse the signed revision's xrefs, catalog, first page, Contents and resources
   from public structure (V5). Require a single supported FlateDecode content
   stream with exact object/generation, start and Length. Each opaque window must
   equal a full permitted object stream payload. Reject alternate object or font
   substitution. Bytes outside stream payloads remain unchanged in redaction.
4. Derive aligned block ranges, block count, head_len/head and tail_len/tail from
   those ranges and the public document, with canonical zero tails. Recompute
   all public SHA compressions from IV in byte order. At each window check H_s,
   substitute the proof's H_e, and continue; append FIPS padding only in the
   public suffix. Final digest must equal CMS messageDigest (V3).
5. Validate CMS signed attributes, digest algorithm, signature, certificate chain
   and timestamp under existing DocumentInspector TrustRole.DOCUMENT policy (V4).
   Inspect later revisions using LaterChanges; do not accept altered page/font
   semantics. The fixture Python reader checks SHA chaining; existing Kotlin
   tests remain responsible for full CMS trust/signature policy, not nargo.
6. For encryption enforce Standard V2 R3 RC4 only. Derive the empty-user-password
   file key from O/P/ID, validate U (PDF algorithms 2/6), derive the content
   object's key using object+generation, and recompute n bytes of RC4 keystream.
   Pad to 8192 with zeros and pack31; compare exactly (V6). For clear documents
   supply encrypted=false and all-zero key. Do not trust a prover-supplied key.
7. Require inflate indices 0..k-1 with k>=1, first iff index=0, last iff index=k-1,
   first variant only at index 0, sin[0]=0, and sout[i]=sin[i+1]. Every C_z equals
   SHA-content C_z. Match all W previous commitments to their actual absolute
   prior indices, with zero for nonexistent history. No missing/extra segments.
8. Require lexical indices 0..m-1 and exact first/last flags, lin[0]=0 and
   lout[j]=lin[j+1]. All C_z match. C_p inputs cover every inflate segment once,
   in order, using the same P; with K=1 require m=k. Non-final cg, ordinals and
   totals are zero. All anchor enabled/length/raw and slot selections are equal
   across lexical, claim and predicate proofs. Final ordinal/total match claim
   and predicate data as well as the template's occurrence policy.
9. Derive public fonts from signed first-page resources (V7); decode each full
   v2 anchor record with per-string boundaries, compare exact template labels,
   ordinals and totals. Derive digit maps from WinAnsi or Identity-H/ToUnicode;
   do not accept prover-supplied arbitrary digit maps or reinterpret widths.
10. Require exactly one claim proof, start=0/count=12, matching C_z, C_g from the
    final lexical proof, anchor data and slot ranges. Require all enabled policy
    slots and canonical disabled digests. Generic partition support is not an
    alternative v1 composition; a future composition must explicitly pin it.
11. If policy requires predicates, require exactly one predicate proof with the
    same C_z/C_g/anchors/slots/beta; derive enabled kind/slot/format/cutoff and
    fonts from policy and V7. No predicate proof is needed when none requested.
    It is not enough to accept whichever predicates the prover chose.
12. Derive beta as SHA-256 of the UTF-8 bytes of the cnf.jwk RFC 7638
    base64url thumbprint string, as specified by p4-zkp.md section 5.1; require
    equal beta across claim/predicate proofs (V9). These circuits bind exactly
    32 bytes and do not perform JWK canonicalization.
13. For each revealed zkOpen slot, recompute SHA-256 over ASCII
    `diw-zkpdf-claim-v1` || slot:u8 || salt[16] || length:u16be || full zero-padded
    records[384], compare the claim digest, decode each string through the signed
    font resources, and apply template normalization; require equality with the
    claimed revealed value (V10). Hidden predicate slots need no opening.
14. Construct the exact ordered public Field arrays yourself and verify **every**
    UltraHonk proof with the pinned zero-knowledge key and bb 2.1.9 poseidon2
    configuration, never --disable_zk (V8). Reject unknown/duplicate/unconsumed
    proofs, altered constants, noncanonical Field encodings, wrong proof length,
    missing joins or failed verification. nargo execution alone is not V8.

`tools/pdf_fixture_chain.py` is a fixture reference, not the production verifier.
It checks the executable SHA/inflate/lexical/claim/predicate joins and openings,
using only the five authorized synthetic documents. Production CMS trust,
credential policy, proof transport, holder identity and GUI decisions remain in
Claude's Kotlin work. No assertion here extends the proof to visual PDF layout,
Form-XObject text, arbitrary PDF parser features or the holder's civil identity.

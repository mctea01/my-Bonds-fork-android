# zkPDF component circuits

This workspace implements the seven zkPDF segment kinds: SHA content and opaque,
first/general inflate, lexical, claim and predicate. The selected phone and
desktop candidates use the parameters in [PUBLIC_SPEC.md](PUBLIC_SPEC.md), whose
ABI and S/Lambda field order remain a draft for Claude's review. Round 10 of
[IMPLEMENTATION.md](IMPLEMENTATION.md) describes the current soundness argument;
earlier rounds below are historical experiments, not alternative release profiles.

From this directory, run the required circuit and fixture checks:

```sh
nargo test
python3 -I tools/regressions.py
python3 -I tools/regressions.py --multiblock
python3 -I tools/regressions.py --segments --bb-js /path/to/bb.js/dest/node/index.js
python3 -I tools/regressions.py --lex-claims --bb-js /path/to/bb.js/dest/node/index.js
python3 -I tools/regressions.py --sha
python3 -I tools/pdf_fixture_chain.py
```

All tools accept `--nargo /path/to/nargo`. The fixture-chain command uses only
Python's standard library and nargo: its Poseidon2 reference does not require
bb.js. It reads the five committed fictional M3d PDFs without modifying them,
emits complete private Prover.toml files under ignored `target/pdf-fixture-chain/`,
and prints only case outcomes. It is an M3c reference, not Rust or a production
PDF/CMS verifier. Negative PDF cases require the actual lexical constraint to
fail; oversize is rejected before witness generation.

After all tests and other compilation have ended, measure the ten distinct
candidate packages sequentially (four packages are shared between tiers):

```sh
python3 -I tools/serial_profiles.py --nargo /path/to/nargo --bb /path/to/bb \
  --crs /path/to/crs --output target/round10-profiles
```

This invokes `compile_profile.py --formal-tier ... --formal-kind ...`, with
HARDWARE_CONCURRENCY=2 and RAYON_NUM_THREADS=2, against the actual workspace
packages. It checks for competing nargo/bb/Java processes, compiles each package
fresh, and measures independent first/warm ZK provers and verification. Never
run these measurements concurrently with regression or Gradle jobs. `--resume`
retains only already verified records whose circuit sources still match.

Use the exact tool versions in `VERSIONS`. The package manifest's compiler
constraint cannot express the pinned prerelease, so `tools/measure.py` checks
the actual version before generating proofs.

```sh
python3 tools/fixtures.py
python3 tools/bench_fixtures.py
nargo test
python3 tools/measure.py sha256_65 sha256_130 sha256_260 \
  --nargo /path/to/nargo --bb /path/to/bb --crs /path/to/crs
python3 tools/measure.py inflate_16k inflate_32k inflate_40k \
  --nargo /path/to/nargo --bb /path/to/bb --crs /path/to/crs
```

The inflate regression functions run in Brillig for fast semantic coverage.
`bench/inflate_probe` is a separate fully constrained harness: no compiler checks
are disabled and no unconstrained helper supplies accepted values. Generate its
inputs with `tools/probe_fixture.py bench/inflate_probe/Prover.toml --kind dynamic`,
then run `nargo execute --package inflate_probe`. Kinds `stored`, `fixed` and
`empty` must also succeed. Mutations `checksum`, `gap` and `owner` with `fixed`
must fail. See `IMPLEMENTATION.md` for the actual validation results and limits.

The Round 4 recovery adds targeted empty-block, overlapping-copy, dynamic-repeat
and EOB attacks, plus a three-block harness with different Huffman tables:

```sh
python3 -I tools/regressions.py --nargo /path/to/nargo
python3 -I tools/regressions.py --multiblock --nargo /path/to/nargo
```

These commands compile constrained ACIR and execute each synthetic case with
pedantic solving. Negative cases must fail a constraint; parser/compiler errors
do not count. The runner suppresses witness-bearing output and removes its
temporary inputs. Synthetic fixture source generation remains reproducible with
`python3 tools/fixtures.py`.

The large inflate benchmark instances use one block, 128 compressed bytes and
192 token slots, with 16/32/40 KiB output capacity. Their repetitive synthetic
input isolates output reconstruction cost. They do not measure the full profile
ceiling of 4 blocks, 8192 compressed bytes and 6144 tokens. All these capacities
are explicit compile-time parameters of the library and bounded in `inflate`.

Measure compilation at the Round 5 full inflate capacities separately:

```sh
python3 -I tools/compile_profile.py --nargo /path/to/nargo \
  --bb /path/to/bb --seconds 1800 --address-space-gib 24 \
  --output target/full-profile.json
```

The defaults are 8192 compressed bytes, 40960 output bytes, 6144 tokens and
4 blocks. Use `--blocks`, `--tokens`, `--plain` and `--compressed` to isolate
individual dimensions within those ceilings. Round 5 compares these tuples
`(blocks, tokens, plain)` at the same compressed capacity:

- `(4, 6144, 40960)` and `(1, 6144, 40960)`;
- `(4, 512, 1024)`;
- `(1, 6144, 1024)` and `(1, 512, 40960)`.

Run each case in a separate process, sequentially, with the same resource
budgets. `nargo info` performs the fresh compilation and reports ACIR opcodes;
`--bb` additionally runs `bb gates` for completed compilations. Records include
the container's actual CPU and memory ceilings, which may be lower than the
requested address-space budget. On a constrained development container, an
optional `--rss-limit-gib 6` protects the session. A termination at this guard
is reported as `rss_guard`, not as OOM, timeout, or evidence of failure at the
24 GiB address-space ceiling. Successful compilation is saved before gates
are attempted, so a backend failure cannot erase the compiler result.

The runner uses a fresh temporary package outside this workspace to avoid a
compiler cache hit, and records timeout/failure as well as successful builds.
It exits nonzero when compilation fails, after saving the measurement record.
The address-space budget protects the development session; it is not the proof
memory threshold or a circuit parameter. This harness does not include SHA
windows, PDF parsing, claims or predicates. Missing gate/proof measurements are
recorded as null. Round 6 gate extrapolations are separately labeled estimates;
proof timings and RSS are never extrapolated from a small-capacity proof.

Witness inputs and proof assets are generated under ignored paths. Measurement
JSON contains only timings, sizes, gate counts and artifact hashes. First/warm
runs are fresh processes against the same local SRS cache; no privileged cache
flush is performed. Compile timing can include a compiler cache hit. RSS is the
child process peak, not a platform-independent allocation counter.

Measure only the cost of one or two UltraHonk ZK recursive verifiers:

```sh
npm install --prefix target/recursion-tools --ignore-scripts @aztec/bb.js@2.1.9
python3 -I tools/recursion_profile.py --nargo /path/to/nargo --bb /path/to/bb \
  --bb-js target/recursion-tools/node_modules/@aztec/bb.js \
  --verifiers 1 --public-inputs 32 --rss-limit-gib 6 --output target/recursion-one.json
python3 -I tools/recursion_profile.py --nargo /path/to/nargo --bb /path/to/bb \
  --bb-js target/recursion-tools/node_modules/@aztec/bb.js \
  --verifiers 2 --public-inputs 32 --rss-limit-gib 6 --output target/recursion-two.json
```

In bb 2.1.9, native `CircuitStats` passes `UltraCircuitBuilder` to a helper
that expects a flavor, leaving `honk_recursion=0`. The native `gates` command
therefore rejects recursive opcodes. The runner retains that failure and,
only for this error, optionally uses the same release's existing WASM API
`acirGetCircuitSizes(bytecode, false, true)`. Both finalize an Ultra circuit
and report its finalized gate count; no backend source is patched. The record
identifies the API, one WASM thread, elapsed time and RSS. These timings are
gate-construction costs, not proof timings. The optional MIT-licensed tool is
not bundled with the app; see `NOTICE` in this directory.

These fresh cost-only harnesses use bb 2.1.9's ZK proof type 7 (508 proof
fields, 115 VK fields). They do not implement PDF splitting, trusted VK
selection, state chaining or a valid recursive proof. The backend generates
dummy assignments for gate counting. Application public input counts are
explicit; these are not a proposed frozen PDF ABI or an end-to-end benchmark.

Round 5 candidate patches in `validation/m3b-round5-*.patch` apply separately
to capacity-only commit `f79397c`. Only the `bits` candidate is adopted;
`scalar` and `fixed` are reproducibility records for discarded comparisons.
Their measurement JSON files include source hashes and explicit capacities.

Round 6 supplies immutable private advice to `inflate`: the plaintext bytes,
flat Huffman lengths/reversed codes, block body/kind, and token output
starts/lengths/ends/distances. Each is checked at constant indices before it can
affect acceptance. Block advice also supplies canonical prefix counters, first
codes and expanded lengths. Header and token prefix/suffix advice provides a
range-checked decomposition of the compressed bit window. These are untrusted
witness inputs, not a parser oracle or a new public ABI. Use the committed
generators to construct the expanded input format; see `IMPLEMENTATION.md` for
the induction and integer bounds establishing soundness.

Run the additional Adler wraparound regressions with:

```sh
python3 -I tools/regressions.py --adler --nargo /path/to/nargo
```

The Round 6 matrix is in `validation/m3b-round6-matrix.json`. Reproduce each row
with the indicated source commit and the four capacity arguments to
`compile_profile.py`. Run sequentially in fresh processes. At N=512 use
`(B,T,P)` = `(1,32,128)`, `(1,256,128)`, `(1,512,128)`, `(2,32,128)`,
`(3,32,128)`, `(2,256,128)`, `(1,32,1024)`, `(1,32,2048)`, `(1,32,8192)`;
at N=8192 use `(1,32,128)` and `(4,512,2048)`. Historical stages use the eight
tuples recorded in their JSON. Candidate patches apply independently to
`15d25c5`; they reproduce the library variant for compilation, not a complete
replacement fixture set. Final source hashes are stable across the subsequent
fixture-only test correction. ACIR hashes can also reflect source paths and
compiler metadata.

An optional guarded proof measurement generates a synthetic repeated-byte
stream filling the selected output capacity and runs witness generation, two
ZK proofs and an independent verifier:

```sh
python3 -I tools/compile_profile.py --nargo /path/to/nargo --bb /path/to/bb \
  --prove --crs /path/to/crs --seconds 1800 --address-space-gib 24 \
  --rss-limit-gib 6 --output target/full-profile-proof.json
```

Each proof phase has independent child RSS accounting and the same resource
guards. Results are saved after each phase; a failed phase exits nonzero without
claiming a complete proof measurement. The first run uses the existing CRS cache,
not a privileged cold-cache reset. All temporary witness/proof assets are removed.
The scalar entrypoint has no public PDF statement, even when every capacity is
set to its profile maximum.

## Round 7 inflate segments

`pdf_inflate_seg_v1` is a draft segment circuit, with public commitments and a
private immutable 32 KiB history. It is not a full PDF/lexer circuit. The Round 7
main was P=2048/T=288/B=1/N=8192; W=16 is computed at compile time.
The selected desktop profile is P=4096/T=576/B=1/N=8192/W=8. Parameter profiles
are pinned separately; final measurements and recommendations are recorded in
`docs/research/p4-benchmarks.md`. Exact proposed encodings and the composition
argument are in `IMPLEMENTATION.md` and need Claude review before M3c.

Use external pinned nargo beta.15, bb 2.1.9 and bb.js 2.1.9 tools. The latter is
already covered by NOTICE and is only an independent development oracle.

```sh
python3 -I tools/segment_reference.py --bb-js /path/to/bb.js/dest/node/index.js \
  --output target/segments --kind dynamic --length 6000
python3 -I tools/regressions.py --segments --nargo /path/to/nargo \
  --bb-js /path/to/bb.js/dest/node/index.js
python3 -I tools/compile_profile.py --segment --plain 2048 --tokens 288 --blocks 1 \
  --compressed 8192 --nargo /path/to/nargo --bb /path/to/bb --prove \
  --bb-js /path/to/bb.js/dest/node/index.js --crs /path/to/crs \
  --rss-limit-gib 5 --output target/profile-segment-2048.json
```

The segment generator uses synthetic data and salt 42; it never prints witness
contents. It writes a Prover.toml per segment plus public chain.json and verifies
all joins/openings and the zlib result. Field values in chain.json are hex
strings to preserve all 254 bits across JSON readers. It rejects insufficient token/block-start
capacity instead of changing fixed-size splitting. Copy a generated Prover.toml
into a matching parameterized package before `nargo execute --pedantic-solving`.
For a stored stream, choose enough token slots per emitted literal byte. The
regressions include a smaller literal-rich profile for stored cross-boundary
checks and a B=3 mixed-block profile. A B=1 profile is intended for the single
block sample, not for arbitrary many-block streams.


## Round 9 v2 text records and split claims/predicates

The current phone general main is P=2048/T=352/B=1/N=8192/W=16. Index zero
uses `pdf_inflate_seg0_v1` with T0=1024 and no history; the general circuit
rejects index zero. The reference CLI now defaults to these capacities.
For desktop, generate with `--plain 4096 --tokens 576 --tokens0 1536` and
compile matching first/general main profiles.
The text-chain CLI selects these token defaults automatically for `--plain 4096`.

```sh
python3 -I tools/lex_reference.py --style word --bb-js /path/to/bb.js/dest/node/index.js --output target/text-word
python3 -I tools/lex_reference.py --style table --bb-js /path/to/bb.js/dest/node/index.js --output target/text-table
python3 -I tools/regressions.py --lex-claims --nargo /path/to/nargo --bb-js /path/to/bb.js/dest/node/index.js
python3 -I tools/record_boundary_analysis.py --nargo /path/to/nargo --bb-js /path/to/bb.js/dest/node/index.js
```

The first two commands generate each inflate, lexical, claim and predicate
Prover.toml and validate the synthetic chain outside the circuit. Add
`--claim-slots N` to generate disjoint claim ranges; compile each range with its
matching SLOT_START/SLOT_COUNT. `--lex-claims` retains the previous round's
cases and exercises v2 boundaries, operator-list completeness, split claims and
predicate-only attacks. A negative case passes only on an ACIR constraint
failure. The boundary-analysis command now verifies that v2 preserves PDF
per-string octal and odd-hex decoding and rejects the former false predicate.

`compile_profile.py --text-profile lex --k 1 --plain 2048` (also K=2/4),
`--text-profile claim --slot-count 12`, and `--text-profile pred` use the full
text capacities A=16/C=12/Q=384/R=96. Add the pinned tool/proof flags and
`--bounded-codegen` used in the Round 9 profiles. Gate counts, timing, memory,
selected capacities and unavailable measurements are recorded in the benchmark
report. Each operator-position list is checked against immutable scanner output;
there is no unconstrained acceptance helper. Inflate and lex must use identical
plaintext segment sizes, since C_p commits to the capacity-padded segment.

Measured production configurations are phone P=2048/K=1/SEG_OPS=64 and desktop
P=4096/K=1/SEG_OPS=128, with 12 slots in one claim proof and at most two
predicates in a separate proof. The requested common-P=2048 comparison also
measures desktop K=2/SEG_OPS=128; that variant consumes two 2048-byte inflate
commitments, not one 4096-byte commitment. Generate the desktop main with the
matching compile-time constants before compiling its verification key. Full
timings, capacity limits and sample-stream estimates are in
`docs/research/p4-benchmarks.md` at the repository root.

# zkPDF component circuits

This workspace implements SHA-256 aligned-window compression and constrained
RFC 1950/1951 inflate. It does not implement the M3b PDF lexer, claims, predicates
or final public-input ABI. None of the benchmark binaries is a deployable PDF
proof circuit.

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

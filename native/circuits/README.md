# M3a component circuits

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
requested address-space budget. Successful compilation is saved before gates
are attempted, so a backend failure cannot erase the compiler result.

The runner uses a fresh temporary package outside this workspace to avoid a
compiler cache hit, and records timeout/failure as well as successful builds.
It exits nonzero when compilation fails, after saving the measurement record.
The address-space budget protects the development session; it is not the proof
memory threshold or a circuit parameter. This harness does not include SHA
windows, PDF parsing, claims or predicates. Missing gate/proof measurements are
recorded as null, never estimated from a small-capacity proof.

Witness inputs and proof assets are generated under ignored paths. Measurement
JSON contains only timings, sizes, gate counts and artifact hashes. First/warm
runs are fresh processes against the same local SRS cache; no privileged cache
flush is performed. Compile timing can include a compiler cache hit. RSS is the
child process peak, not a platform-independent allocation counter.

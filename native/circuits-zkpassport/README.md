# FaceMatch circuits of this project

zkPassport's FaceMatch circuits prove that an attested app signed a statement
(mode, hash of the document's photo). Its Android circuits also need a Play
Integrity token, and a verifier of zkPassport accepts the official app only. The
circuits here are this project's own alternatives for where that does not fit;
only this project's verifier would accept them. Design, comparison with the
official circuits and limits: `docs/design/zkpassport.md` section 5.6.

| Circuit | Evidence | Where |
| --- | --- | --- |
| `diw_facematch_keyattest_*` (78 chain shapes, generated) | Android key attestation: hardware key, boot state, package name and signing certificate | Android devices with a hardware keystore, with or without Google Play services |
| `diw_facematch_self` | None: the wallet's own statement | Android devices without a usable attestation, when the requester accepts it (desktop has no camera comparison and declines FaceMatch) |

All of them have the public inputs and outputs of zkPassport's FaceMatch circuits
(`comm_in`, `current_date`, `service_scope`, `service_subscope`; parameter
commitment, nullifier type, nullifier, OPRF key hash) and use zkPassport's
commitment and nullifier code from `native/vendor/zkpassport-circuits`.

The wallet proves them on Android after its own camera comparison and the
verifier accepts them when a request lists them (`"facematch": {"diw": [...]}`).
`circuits.json` lists the verification key hash of every circuit; the native
library embeds it, and the prover and the verifier take no circuit whose key
hashes elsewhere. The self-declared circuit is embedded (`artifacts/`); the key
attestation circuits are downloaded on demand from the `zkpassport-facematch-v1`
release, which the `zkPassport FaceMatch assets` workflow builds from these
sources and publishes.

## Layout

- `src/`: Nargo workspace with the library (`lib/diw_facematch`: key attestation
  reader, parameter commitments) and the self-declared circuit.
- `tools/keyattest.py`: generates the key attestation circuits into `gen/`
  (ignored by git) and checks them with synthetic chains.
- `VERSIONS`: toolchain and upstream revision.
- `circuits.json`: verification key hash of every circuit, built into the wallet and the verifier.
- `artifacts/`: the self-declared circuit as the native library embeds it.

## Checks

Toolchain: nargo 1.0.0 and bb 6.0.0, the versions zkPassport's circuits use
(`native/circuits` pins another nargo for zkPDF; do not mix them).

```sh
cd src && nargo test                                   # library and self-declared circuit
cd .. && python3 -I tools/keyattest.py check --nargo nargo --bb bb --crs /path/to/crs
python3 -I tools/keyattest.py check --nargo nargo rk_ecdsa_ik_p256_sha256   # one shape
python3 -I tools/keyattest.py list                     # all shape names
```

`check` needs the Python package `cryptography`. For each shape it builds a chain
of fresh keys ending in a keystore certificate of a fictional app, executes the
circuit on it (four boot states, each with its expected commitment) and on nine
tampered or unacceptable variants that must fail or be read correctly, and with
`--bb` proves and verifies. Without shape names it checks one ECDSA-root and one
RSA-root shape. The document is the specimen of zkPassport's own tests.

`package` compiles the circuits, derives their keys and writes the gzip
artifacts the wallet downloads, then compares the key hashes with
`circuits.json` (`--pin` rewrites it instead, only for a deliberate change):

```sh
cargo build --release --manifest-path ../Cargo.toml -p zkpassport-verify --example vkey_hash
python3 -I tools/keyattest.py package --nargo nargo --bb bb \
  --vkey-hash ../target/release/examples/vkey_hash --crs /path/to/crs --out /tmp/facematch --jobs 2
```

Keys come from the upstream bb CLI (`--bb`) or from `zkpdf-vk` (`--vk`) built
with clang; a Barretenberg built with GCC derives other keys for these circuits
(see `../zkpdf-prover/README.md`).

`python3 -I tools/keyattest.py libtests` rewrites the library's test vectors
(`src/lib/diw_facematch/src/tests.nr`) after a change to the fixtures.

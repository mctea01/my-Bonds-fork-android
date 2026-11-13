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
| `diw_facematch_self` | None: the wallet's own statement | Any platform, including desktop |

All of them have the public inputs and outputs of zkPassport's FaceMatch circuits
(`comm_in`, `current_date`, `service_scope`, `service_subscope`; parameter
commitment, nullifier type, nullifier, OPRF key hash) and use zkPassport's
commitment and nullifier code from `native/vendor/zkpassport-circuits`.

Not wired into the wallet yet: no assets are published and neither the prover
nor the verifier knows these circuits.

## Layout

- `src/`: Nargo workspace with the library (`lib/diw_facematch`: key attestation
  reader, parameter commitments) and the self-declared circuit.
- `tools/keyattest.py`: generates the key attestation circuits into `gen/`
  (ignored by git) and checks them with synthetic chains.
- `VERSIONS`: toolchain and upstream revision.

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

`python3 -I tools/keyattest.py libtests` rewrites the library's test vectors
(`src/lib/diw_facematch/src/tests.nr`) after a change to the fixtures.

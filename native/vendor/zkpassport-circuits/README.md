# Vendored zkPassport circuit libraries

Noir libraries from https://github.com/zkpassport/circuits (Apache-2.0, `LICENSE`
in this directory) at revision `2c5673df14d496a1b0baf7a92e883ca19fbb618b`
(package version 0.22.0), unmodified and at their upstream paths:

- `src/noir/lib/utils`
- `src/noir/lib/commitment/common`, `src/noir/lib/commitment/scoped-nullifier`
- `src/noir/lib/facematch`
- `src/noir/lib/sig-check/common`, `src/noir/lib/sig-check/ecdsa`, `src/noir/lib/sig-check/rsa`
- `src/noir/lib/data-check/expiry`, `src/noir/lib/data-check/tbs-pubkey`

They are the dependencies of the project's own FaceMatch circuits in
`native/circuits-zkpassport`, which keep zkPassport's commitments, nullifier and
client data so that their proofs chain with zkPassport's other proofs.

Why vendored: Nargo pins a git dependency by tag only, and the upstream repository
tags toolchains (`noir-v1.0.0`, `bb-v6.0.0`), not circuit versions. A copy at a
recorded revision keeps the circuits reproducible. Their own git dependencies
(poseidon, sha256, sha512, bignum, ecdsa, rsa, date, oprf-nr) are still fetched by
Nargo at the tags the libraries name.

To update: copy the same directories from the new revision, change the revision
here and in `native/circuits-zkpassport/VERSIONS`, and run the checks in
`native/circuits-zkpassport/README.md`.

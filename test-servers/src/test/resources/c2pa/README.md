# C2PA test files

- `signed.jpg`, `signed.png`: 16x16 pictures signed with c2pa-python 0.38 (c2pa-rs 0.91, claim v2, ES256) by
  `generate.py`, with a test chain made for these tests only. `test-root.pem` is that chain's root; its key is not kept.
- `c2pa-rs-CA.jpg`: `sdk/tests/fixtures/CA.jpg` of https://github.com/contentauth/c2pa-rs (MIT or Apache-2.0):
  claim v1, PS256, a sigTst time stamp and an ingredient.
- `ica/`: identity claims aggregation samples of c2pa-rs 0.92.0 (`src/identity/tests/fixtures/claim_aggregation`, MIT or
  Apache-2.0): `success.jpg`, `signature_mismatch.jpg` and `signer_payload_mismatch.jpg` (issuer: an Ed25519 did:jwk),
  and `adobe_connected_identities.jpg` with the DID document of its did:web issuer (`connected_identities_did.json`),
  which `C2paSigningTest` serves instead of fetching it.

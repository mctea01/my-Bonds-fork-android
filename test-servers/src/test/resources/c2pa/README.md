# C2PA test files

- `signed.jpg`, `signed.png`: 16x16 pictures signed with c2pa-python 0.38 (c2pa-rs 0.91, claim v2, ES256) by
  `generate.py`, with a test chain made for these tests only. `test-root.pem` is that chain's root; its key is not kept.
- `c2pa-rs-CA.jpg`: `sdk/tests/fixtures/CA.jpg` of https://github.com/contentauth/c2pa-rs (MIT or Apache-2.0):
  claim v1, PS256, a sigTst time stamp and an ingredient.
- `ica/`: identity claims aggregation samples of c2pa-rs 0.92.0 (`src/identity/tests/fixtures/claim_aggregation`, MIT or
  Apache-2.0): `success.jpg`, `signature_mismatch.jpg` and `signer_payload_mismatch.jpg` (issuer: an Ed25519 did:jwk),
  and `adobe_connected_identities.jpg` with the DID document of its did:web issuer (`connected_identities_did.json`),
  which `C2paSigningTest` serves instead of fetching it.
- `containers/`: files of `sdk/tests/fixtures` of c2pa-rs at revision adf4d6f (0.93.0-dev, MIT or Apache-2.0).
  `boxhash.jpg` with `boxhash.json` (the `c2pa.hash.boxes` assertion c2pa-rs computes for it) and `dashinit.mp4` (the
  initialization segment of a fragmented MP4 signed with a BMFF hash and Merkle tree) are checked as they are;
  `sample1.avif`, `basic.pdf`, `sample1.docx` and `sample1.odt` are unsigned files that `C2paSigningTest` signs and
  checks. The other container samples (GIF, TIFF, WAV, AVI, MP3, FLAC, SVG, JPEG XL, MP4, ZIP) are made by the test.

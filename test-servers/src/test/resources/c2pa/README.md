# C2PA test files

- `signed.jpg`, `signed.png`: 16x16 pictures signed with c2pa-python 0.38 (c2pa-rs 0.91, claim v2, ES256) by
  `generate.py`, with a test chain made for these tests only. `test-root.pem` is that chain's root; its key is not kept.
- `c2pa-rs-CA.jpg`: `sdk/tests/fixtures/CA.jpg` of https://github.com/contentauth/c2pa-rs (MIT or Apache-2.0):
  claim v1, PS256, a sigTst time stamp and an ingredient.

# Vendored zkPassport crates

`zkpassport-core`, `zkpassport-ffi` and `zkpassport-bridge` from
https://github.com/zkpassport/zkpassport-packages at revision
`dae2129a0722e9391a4a243c6d53df0a134a74f8` (directory `rust/crates`).

They give the wallet zkPassport's own circuit input generation and its sans-IO
session driver, so the circuits, their order and their inputs are the ones the
official app uses. `diw-zk-ffi` wraps the driver (`ZkPassportProofSession`) and
proves each circuit with the project's Barretenberg (`zkpassport_prove`).

Why vendored: Cargo cannot fetch the repository as a git dependency because its
submodules use SSH URLs. The workspace excludes this directory, so the crates
build only as dependencies and their own tests (which need upstream fixtures)
do not run here.

Changes from upstream, all in the `Cargo.toml` files only:

- workspace inheritance replaced by explicit `version`, `edition`, `license`
  and `repository` values taken from the upstream workspace manifest;
- `[lib] crate-type` removed, so the crates build as plain Rust libraries.

One change in `src/`: `processed_sod_signature` (`zkpassport-core/src/input_gen.rs`)
left-pads an RSA signature to the modulus size, as `id_data.rs` already does for
the ID-data circuit. The integrity circuit checks a commitment over the private
nullifier that the ID-data circuit computed from the padded signature, so an
unpadded signature shorter than the modulus failed the integrity proof. Keep
this change when updating unless upstream has made it.

Tests, fixtures and the wasm crate are not copied.

License: the upstream Rust workspace declares `license = "MIT"`; the
repository has no root license file for these crates. The MIT terms:

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

To update: copy `rust/crates/{zkpassport-core,zkpassport-ffi,zkpassport-bridge}/src`
and `Cargo.toml` from the new revision, reapply the two manifest changes, update
the revision here and in NOTICE, reapply the `src/` change above, and rerun `cargo test -p diw-zk-ffi --features zkpdf`.

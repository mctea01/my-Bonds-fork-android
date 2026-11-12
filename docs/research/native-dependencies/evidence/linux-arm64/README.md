# Linux ARM64 evidence

See the [report](../../linux-arm64-poc.md). The final runner records 29 successful
commands under an x86_64 host with QEMU user max, not physical ARM64 hardware.
Logs have LF endings and trailing whitespace removed. Binaries, downloaded
sources and generated public-fixture headers remain outside the repository.
`packages.json` lists Debian trixie package paths relative to
https://deb.debian.org/debian/ and SHA-256 values checked before extraction;
only qemu-aarch64 was extracted from qemu-user. Package download caches were
removed after extraction. `inspection.json` summarizes ELF symbols and counts
selected ARM64 instructions; it does not establish a minimum runtime platform.
`longfellow-target-cfg.log` is a standalone rustc feature inspection, not a dump
of release profile settings (the release library uses its Cargo panic/profile).
`negative-runtime.json` records expected errors in two separate QEMU calls.
`validation.json` checks hashes, clean sources, the shared proof fixture,
metadata, and input guards; it does not add hardware or prover coverage.

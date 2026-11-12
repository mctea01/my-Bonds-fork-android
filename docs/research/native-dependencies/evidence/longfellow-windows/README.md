# Longfellow Windows evidence

See the [report](../../longfellow-windows-poc.md). `result.json` records the final
source-pinned, patch-checked build, feature graphs, PE inspection and Wine C
probe. Empty logs mean a successful command emitted nothing. Logs use LF and
remove trailing whitespace; downloaded sources, binaries and generated public
fixture headers stay outside this repository. `attempts.json` retains earlier
source and toolchain failures. The lockfile is an experimental resolution,
not a reconstruction of the published Multipaz binaries. `mingw-packages.json`
records packages extracted from https://deb.debian.org/debian/ plus each Filename;
SHA-256 values were checked against Debian trixie's Packages index before use.
Wine setup is the same as the [BB experiment](../bb-windows-link/toolchain.json).
`validation.json` checks delivery consistency, pin guards and patch scope.

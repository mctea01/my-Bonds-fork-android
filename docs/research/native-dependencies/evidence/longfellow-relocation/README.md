# Longfellow relocation evidence

See the [report](../../longfellow-relocation-poc.md). `build/` records the embedded
DLL build and original C suite. `relocation/` records the comparison after the
source checkout was temporarily renamed: the baseline's nonzero exit is the
expected failure control, followed by successful embedded-DLL tests. The source
was restored. Logs have LF endings and trailing whitespace removed; binaries,
reference assets and generated headers stay outside the repository. The baseline
is the [previous build](../longfellow-windows/result.json). Toolchain and Wine
versions are unchanged. `validation.json` describes pin checks and guard tests;
this remains Wine testing, not native Windows acceptance.

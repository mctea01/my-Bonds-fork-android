# BB Linux ARM64 evidence

`result.json` records the final runner invocation: official BB 6.0.0 archive,
source-built libdeflate and unchanged DIW bridge, three AArch64 executables,
and six QEMU executions across `max` and `cortex-a53`. All 45 commands succeeded.
Full BB source rebuild, physical hardware and proof generation remain untested.

Logs use LF and omit trailing whitespace; empty successful compiler logs remain
empty. No binary, generated fixture header, disclosure text, or proving CRS is
committed. Paths identify external inputs and build outputs. The reused C caller
filenames and their Windows-specific untested messages are historical; the ELF
headers and recorded QEMU commands establish this experiment's architecture.

`download.json` records the upstream release URL and checked archive hashes.
`inspection.json` summarizes the 191 archive member ELF headers, executable
dependencies and GLIBC symbol versions. Source file hashes identify the pinned
upstream target configuration; they do not prove release binary provenance.

`validation.json` records input/artifact hashes, clean pinned checkouts, fixture
parity with Windows, runner input rejection checks, document/matrix checks and
unchanged production sources. It does not increase hardware or functional scope.

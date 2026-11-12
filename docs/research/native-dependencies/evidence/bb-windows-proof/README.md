# Windows GNU proof evidence

See the [report](../../bb-windows-proof-poc.md). `result.json` contains the full
39-command run with hashes, exit codes, and explicit Wine scope. The underlying
[toolchain setup](../bb-windows-link/toolchain.json) is unchanged. Logs have LF
endings and trailing whitespace removed; empty successful compiler logs remain
empty. Generated headers, downloaded fixtures/archives and PE binaries remain
outside the repository. `fixture-source.json` records pinned upstream source
and circuit gitlink checks; it does not authenticate production registry keys.
`validation.json` describes delivery checks and fixture hash rejection.

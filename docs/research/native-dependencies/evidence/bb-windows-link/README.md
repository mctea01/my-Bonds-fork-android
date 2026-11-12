# Windows GNU BB evidence

See the [report](../../bb-windows-link-poc.md) for scope and reproduction.
`result.json` preserves commands, exit codes, input hashes, and artifact hashes
from the successful run. Logs are copied with trailing whitespace removed and
LF endings; empty successful compiler logs remain empty. PE files, archives,
downloads, and Wine prefixes stay outside the repository. Absolute paths in
commands identify the experiment workspace and can be replaced when reproducing.

`without-deflate-control.json` records a separate link/run control, not an
additional proof test. `toolchain.json` and `wine-packages.json` describe the
isolated tools and portable Wine setup. Native Windows and full proof validation
remain untested. `validation.json` checks delivery consistency and input guards;
it does not extend the runtime coverage.

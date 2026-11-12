#!/usr/bin/env python3
"""Drops test-only entries from the tracing agent's output in DIR (tools/desktop-native.sh).

The desktop tests run under the agent to reach the screens and flows a short start of the app never opens; what only the
tests and their harness use (JUnit, Gradle's worker, kotlin.test, the test servers, the test classes) is left out.
Every list in every JSON file is filtered, so both the per-kind files and reachability-metadata.json are handled.
Usage: native-metadata-filter.py DIR
"""
import json
import pathlib
import re
import sys

TEST = re.compile(
    r"org\.junit|org\.opentest4j|junit-platform|kotlin\.test|kotlinx\.coroutines\.test|io\.ktor\.server\.testing|"
    r"diw\.testservers|org\.gradle|worker\.org\.gradle|TestEngine|LauncherSessionListener|PostDiscoveryFilter|"
    r"TestExecutionListener|AsserterContributor|"
    r"\b(?:[a-z0-9_]+\.)+[A-Z][A-Za-z0-9_]*Test(?:Kt)?\b"
)


def prune(value):
    """Removes, at every depth, list entries whose JSON text mentions a test-only name; returns how many went."""
    dropped = 0
    if isinstance(value, dict):
        for item in value.values():
            dropped += prune(item)
    elif isinstance(value, list):
        kept = []
        for item in value:
            if isinstance(item, (dict, str)) and TEST.search(json.dumps(item)):
                dropped += 1
            else:
                dropped += prune(item)
                kept.append(item)
        value[:] = kept
    return dropped


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    total = 0
    for path in sorted(root.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        dropped = prune(data)
        total += dropped
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"{path.name}: dropped {dropped}")
    print(f"native metadata: dropped {total} test-only entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Run synthetic attacks through compiled ACIR without logging private inputs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# Explicit repository-local imports also work under python3 -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import compressed, regression_cases
from probe_fixture import write

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nargo', default='nargo')
    args = parser.parse_args()
    version = subprocess.check_output([args.nargo, '--version'], text=True)
    if '1.0.0-beta.15' not in version:
        raise RuntimeError('Use the pinned nargo version')
    subprocess.run([args.nargo, 'compile', '--package', 'inflate_probe'], cwd=ROOT, check=True)
    prover = ROOT / 'bench/inflate_probe/Regression.toml'
    cases = [('overlap_control', compressed(b'AB' * 40), None)] + regression_cases()
    results = []
    try:
        for name, data, mutation in cases:
            write(prover, data, mutation=mutation)
            result = subprocess.run(
                [args.nargo, 'execute', '--package', 'inflate_probe',
                 '--prover-name', 'Regression', '--pedantic-solving', 'regression'],
                cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            # A parsing or compilation failure must never count as rejection.
            rejected = result.returncode == 1 and 'Cannot satisfy constraint' in result.stdout
            passed = rejected if mutation is not None else result.returncode == 0
            results.append(dict(case=name, expected='reject' if mutation else 'accept', passed=passed))
            print(f'{name}: {"pass" if passed else "FAIL"}', flush=True)
            if not passed:
                raise RuntimeError(f'Unexpected ACIR result for synthetic case {name}; output suppressed')
    finally:
        prover.unlink(missing_ok=True)
        (ROOT / 'target/regression.gz').unlink(missing_ok=True)
        target = ROOT / 'target/regressions.json'
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()

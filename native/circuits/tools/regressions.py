#!/usr/bin/env python3
"""Run synthetic attacks through compiled ACIR without logging private inputs."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# Explicit repository-local imports also work under python3 -I.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import compressed, regression_cases, multiblock_cases
from probe_fixture import write

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nargo', default='nargo')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--multiblock', action='store_true')
    group.add_argument('--adler', action='store_true')
    group.add_argument('--segments', action='store_true')
    parser.add_argument('--bb-js', type=Path, help='Pinned bb.js 2.1.9 dest/node/index.js for segment commitments')
    args = parser.parse_args()
    version = subprocess.check_output([args.nargo, '--version'], text=True)
    if '1.0.0-beta.15' not in version:
        raise RuntimeError('Use the pinned nargo version')
    if args.segments:
        if not args.bb_js:
            parser.error('--segments requires --bb-js')
        from segment_regressions import run
        run(args.nargo,args.bb_js,ROOT/'target/segment-regressions.json')
        return
    package = 'inflate_adler_probe' if args.adler else 'inflate_multiblock_probe' if args.multiblock else 'inflate_probe'
    witness_name = f'{package}_regression'
    subprocess.run([args.nargo, 'compile', '--package', package], cwd=ROOT, check=True)
    prover = ROOT / 'bench' / package / 'Regression.toml'
    cases = multiblock_cases() if args.multiblock else [('overlap_control', compressed(b'AB' * 40), None)] + regression_cases()
    if args.adler:
        data = compressed(bytes([255])*600)
        cases = [('adler_wrap_control',data,None),
                 ('rejects_wrapped_checksum',data,('bits',(len(data)-1)*8,8,data[-1]^1)),
                 ('rejects_late_plain_copy',data,('plain',599))]
    results = []
    try:
        for name, data, mutation in cases:
            write(prover, data, mutation=mutation,
                  plain_capacity=1024 if args.adler else 128,
                  token_capacity=64 if args.multiblock else 32,
                  block_capacity=3 if args.multiblock else 1)
            result = subprocess.run(
                [args.nargo, 'execute', '--package', package,
                 '--prover-name', 'Regression', '--pedantic-solving', witness_name],
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
        (ROOT / 'target' / f'{witness_name}.gz').unlink(missing_ok=True)
        target = ROOT / 'target' / f'{package}-regressions.json'
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()

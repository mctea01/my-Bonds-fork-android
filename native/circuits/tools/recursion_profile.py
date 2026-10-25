#!/usr/bin/env python3
"""Measure UltraHonk ZK recursive verifier gates, not a split PDF circuit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compile_profile import run_limited


def measured(command, output, seconds, address_space_gib, rss_limit_gib):
    # Isolate resource accounting from earlier compiler/backend children.
    pid = os.fork()
    if pid == 0:
        def limits():
            budget = address_space_gib * 1024**3
            resource.setrlimit(resource.RLIMIT_AS, (budget, budget))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        start = time.monotonic()
        with output.open('w') as stdout, output.with_suffix('.stderr.log').open('w') as stderr:
            code, status = run_limited(command, stdout, stderr, seconds, limits, rss_limit_gib)
        record = dict(seconds=time.monotonic()-start, exit_code=code, status=status,
                      peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        output.with_suffix('.measurement.json').write_text(json.dumps(record))
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if status != 0:
        raise RuntimeError('Measurement worker failed')
    return json.loads(output.with_suffix('.measurement.json').read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nargo', default='nargo')
    parser.add_argument('--bb', default='bb')
    parser.add_argument('--bb-js', type=Path,
                        help='Optional @aztec/bb.js 2.1.9 package directory for the native gates recursion bug')
    parser.add_argument('--node', default='node')
    parser.add_argument('--verifiers', type=int, choices=(1, 2), default=1)
    parser.add_argument('--public-inputs', type=int, default=32)
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--address-space-gib', type=int, default=24)
    parser.add_argument('--rss-limit-gib', type=float)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.public_inputs < 1 or args.seconds <= 0 or args.address_space_gib <= 0:
        parser.error('Input count and resource budgets must be positive')
    if args.rss_limit_gib is not None and args.rss_limit_gib <= 0:
        parser.error('RSS guard must be positive')
    nargo = subprocess.check_output([args.nargo, '--version'], text=True).strip()
    bb = subprocess.check_output([args.bb, '--version'], text=True).strip()
    if nargo.splitlines()[0] != 'nargo version = 1.0.0-beta.15' or bb != '2.1.9':
        raise RuntimeError('Use the pinned nargo and bb versions')
    # bb v2.1.9 bb_proof_verification/src/lib.nr specifies these lengths and type.
    # This cost-only harness deliberately has no PDF statement or trusted VK.
    source = f'''fn main(
    keys: [[Field;115];{args.verifiers}], proofs: [[Field;508];{args.verifiers}],
    inputs: pub [[Field;{args.public_inputs}];{args.verifiers}],
    key_hashes: [Field;{args.verifiers}],
) {{
    for i in 0..{args.verifiers} {{
        std::verify_proof_with_type(keys[i], proofs[i], inputs[i], key_hashes[i], 7);
    }}
}}
'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    record = dict(scope='cost-only UltraHonk ZK recursion; no PDF circuit or valid proof',
                  nargo=nargo, bb=bb, verifiers=args.verifiers,
                  application_public_inputs_per_proof=args.public_inputs,
                  proof_fields=508, vk_fields=115, proof_type=7,
                  timeout_seconds=args.seconds, address_space_limit_gib=args.address_space_gib,
                  rss_guard_gib=args.rss_limit_gib,
                  source_sha256=hashlib.sha256(source.encode()).hexdigest(), gates=None,
                  environment={name: Path('/sys/fs/cgroup', name).read_text().strip()
                               for name in ('memory.max', 'cpu.max')
                               if Path('/sys/fs/cgroup', name).exists()})
    with tempfile.TemporaryDirectory(prefix='diw-recursion-profile-') as directory:
        root = Path(directory)
        (root/'src').mkdir()
        (root/'src/main.nr').write_text(source)
        (root/'Nargo.toml').write_text('[package]\nname="recursion_profile"\ntype="bin"\nauthors=[]\n')
        record['compile'] = measured([args.nargo, 'compile', '--program-dir', str(root)],
                                    args.output.with_suffix('.compile.log'), args.seconds,
                                    args.address_space_gib, args.rss_limit_gib)
        args.output.write_text(json.dumps(record, indent=2)+'\n')
        if record['compile']['exit_code'] == 0:
            acir = root/'target/recursion_profile.json'
            record['acir_sha256'] = hashlib.sha256(acir.read_bytes()).hexdigest()
            record['gate_measurement'] = measured([args.bb, 'gates', '-b', str(acir)],
                args.output.with_suffix('.gates.log'), args.seconds, args.address_space_gib, args.rss_limit_gib)
            if record['gate_measurement']['exit_code'] == 0:
                record['gates'] = json.loads(args.output.with_suffix('.gates.log').read_text())
            elif args.bb_js and 'circuit is not recursive' in args.output.with_suffix('.gates.stderr.log').read_text():
                record['native_gate_error'] = 'bb 2.1.9 CircuitStats sets honk_recursion=0'
                helper = Path(__file__).with_name('recursion_gates.mjs')
                record['fallback_measurement'] = measured(
                    [args.node, '--max-old-space-size=512', str(helper), str(args.bb_js.resolve()), str(acir)],
                    args.output.with_suffix('.wasm.log'), args.seconds, args.address_space_gib, args.rss_limit_gib)
                record['gate_api'] = '@aztec/bb.js 2.1.9 acirGetCircuitSizes(bytecode, false, true); one WASM thread'
                if record['fallback_measurement']['exit_code'] == 0:
                    record['gates'] = json.loads(args.output.with_suffix('.wasm.log').read_text())
        args.output.write_text(json.dumps(record, indent=2)+'\n')
        print(json.dumps(record, indent=2))
        if record['gates'] is None:
            raise SystemExit(1)


if __name__ == '__main__':
    main()

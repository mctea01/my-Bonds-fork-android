#!/usr/bin/env python3
"""Measure full-capacity inflate compilation in a fresh standalone package."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAIN = '''use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint};
fn main(data:[u8;8192],data_len:u32,blocks:[BlockHint;8],block_count:u32,
    tokens:[TokenHint;20480],owners:[u32;40960],plain_len:u32,expected:[u8;40960]) {
    assert_eq(inflate(data,data_len,blocks,block_count,tokens,owners,plain_len),expected);
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nargo', default='nargo')
    parser.add_argument('--seconds', type=int, default=600)
    parser.add_argument('--address-space-gib', type=int, default=24)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.seconds <= 0 or args.address_space_gib <= 0:
        parser.error('Resource budgets must be positive')
    version = subprocess.check_output([args.nargo, '--version'], text=True).strip()
    if version.splitlines()[0] != 'nargo version = 1.0.0-beta.15':
        raise RuntimeError('Use the pinned nargo version')
    # Only the compiler child receives these limits. Preserve the rest of the session.
    def limits():
        budget = args.address_space_gib * 1024**3
        resource.setrlimit(resource.RLIMIT_AS, (budget, budget))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source_hash = hashlib.sha256((ROOT / 'pdf_text_v1/src/inflate.nr').read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='diw-inflate-profile-') as directory:
        root = Path(directory)
        (root / 'src').mkdir()
        (root / 'src/main.nr').write_text(MAIN)
        # JSON quoted strings are also valid TOML strings for these filesystem paths.
        (root / 'Nargo.toml').write_text(
            '[package]\nname="full_inflate_preflight"\ntype="bin"\nauthors=[]\n'
            '[dependencies]\npdf_text_v1={path=' + json.dumps(str(ROOT / 'pdf_text_v1')) + '}\n')
        start = time.monotonic()
        with args.output.with_suffix('.log').open('w') as log:
            try:
                result = subprocess.run([args.nargo, 'compile', '--program-dir', str(root)],
                    stdout=log, stderr=log, timeout=args.seconds, preexec_fn=limits)
                code = result.returncode
                status = 'compiled' if code == 0 else 'compiler_failed'
            except subprocess.TimeoutExpired:
                code, status = 124, 'timeout'
        record = dict(
            scope='inflate only; not the complete pdf_text_v1_1p circuit',
            nargo=version, status=status, exit_code=code,
            seconds=time.monotonic()-start,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            timeout_seconds=args.seconds, address_space_limit_gib=args.address_space_gib,
            compressed_capacity=8192, plain_capacity=40960, token_capacity=20480, block_capacity=8,
            main_sha256=hashlib.sha256(MAIN.encode()).hexdigest(),
            inflate_source_sha256=source_hash,
            acir_sha256=None, vk_sha256=None, gates=None, prove=None, verify=None, proof_bytes=None)
        acir = root / 'target/full_inflate_preflight.json'
        if code == 0:
            record['acir_sha256'] = hashlib.sha256(acir.read_bytes()).hexdigest()
            args.output.with_suffix('.acir.json').write_bytes(acir.read_bytes())
        args.output.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record, indent=2))
        if code != 0:
            raise SystemExit(1)


if __name__ == '__main__':
    main()

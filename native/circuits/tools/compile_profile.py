#!/usr/bin/env python3
"""Measure full-capacity inflate compilation in a fresh standalone package."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAIN = '''use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint,InflateHints};
fn main(data:[u8;COMPRESSED],data_len:u32,blocks:[BlockHint;BLOCKS],block_count:u32,
    tokens:[TokenHint;TOKENS],owners:[u32;PLAIN],plain_len:u32,hints:InflateHints<TOKENS,BLOCKS>,expected:[u8;PLAIN]) {
    assert_eq(inflate(data,data_len,blocks,block_count,tokens,owners,plain_len,expected,hints),expected);
}
'''


def run_limited(command, stdout, stderr, seconds, limits, rss_limit_gib=None):
    """Keep an optional RSS guard distinct from timeout and compiler failure."""
    start = time.monotonic()
    with subprocess.Popen(command, stdout=stdout, stderr=stderr, preexec_fn=limits) as child:
        status = None
        while child.poll() is None:
            if time.monotonic() - start >= seconds:
                status = 'timeout'
            if rss_limit_gib is not None:
                try:
                    current = Path(f'/proc/{child.pid}/status').read_text()
                    match = re.search(r'^VmRSS:\s+(\d+) kB$', current, re.MULTILINE)
                    if match and int(match[1]) >= rss_limit_gib * 1024**2:
                        status = 'rss_guard'
                except FileNotFoundError:
                    pass
            if status is not None:
                child.kill()
                child.wait()
                return (124 if status == 'timeout' else child.returncode), status
            time.sleep(0.05)
        return child.returncode, 'compiled' if child.returncode == 0 else 'compiler_failed'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--nargo', default='nargo')
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--compressed', type=int, default=8192)
    parser.add_argument('--plain', type=int, default=40960)
    parser.add_argument('--tokens', type=int, default=6144)
    parser.add_argument('--blocks', type=int, default=4)
    parser.add_argument('--bb', help='Pinned bb 2.1.9; measure gates after compilation')
    parser.add_argument('--address-space-gib', type=int, default=24)
    parser.add_argument('--rss-limit-gib', type=float,
                        help='Optional session-protection guard; reported separately from compiler failure')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.seconds <= 0 or args.address_space_gib <= 0:
        parser.error('Resource budgets must be positive')
    if args.rss_limit_gib is not None and args.rss_limit_gib <= 0:
        parser.error('RSS guard must be positive')
    for name, maximum in [('compressed',8192), ('plain',40960), ('tokens',6144), ('blocks',4)]:
        if not 0 < getattr(args, name) <= maximum:
            parser.error(f'{name} must be between 1 and {maximum}')
    source = MAIN
    for name in ('compressed', 'plain', 'tokens', 'blocks'):
        source = source.replace(name.upper(), str(getattr(args, name)))
    version = subprocess.check_output([args.nargo, '--version'], text=True).strip()
    if version.splitlines()[0] != 'nargo version = 1.0.0-beta.15':
        raise RuntimeError('Use the pinned nargo version')
    if args.bb and subprocess.check_output([args.bb, '--version'], text=True).strip() != '2.1.9':
        raise RuntimeError('Use the pinned bb version')
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
        (root / 'src/main.nr').write_text(source)
        # JSON quoted strings are also valid TOML strings for these filesystem paths.
        (root / 'Nargo.toml').write_text(
            '[package]\nname="full_inflate_preflight"\ntype="bin"\nauthors=[]\n'
            '[dependencies]\npdf_text_v1={path=' + json.dumps(str(ROOT / 'pdf_text_v1')) + '}\n')
        start = time.monotonic()
        with args.output.with_suffix('.log').open('w') as log:
            code, status = run_limited([args.nargo, 'info', '--program-dir', str(root)],
                log, log, args.seconds, limits, args.rss_limit_gib)
        record = dict(
            scope='inflate only; not the complete pdf_text_v1_1p circuit',
            nargo=version, status=status, exit_code=code,
            seconds=time.monotonic()-start,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            timeout_seconds=args.seconds, address_space_limit_gib=args.address_space_gib,
            rss_guard_gib=args.rss_limit_gib,
            compressed_capacity=args.compressed, plain_capacity=args.plain,
            token_capacity=args.tokens, block_capacity=args.blocks,
            main_sha256=hashlib.sha256(source.encode()).hexdigest(),
            inflate_source_sha256=source_hash,
            acir_sha256=None, acir_opcodes=None, vk_sha256=None, gates=None,
            prove=None, verify=None, proof_bytes=None,
            measurement_command='nargo info (fresh package; includes compilation)',
            environment={name: Path('/sys/fs/cgroup', name).read_text().strip()
                         for name in ('memory.max', 'cpu.max', 'memory.events')
                         if Path('/sys/fs/cgroup', name).exists()})
        acir = root / 'target/full_inflate_preflight.json'
        if code == 0:
            record['acir_sha256'] = hashlib.sha256(acir.read_bytes()).hexdigest()
            args.output.with_suffix('.acir.json').write_bytes(acir.read_bytes())
            # nargo info prints one row per function: package, function, opcodes.
            counts = re.findall(r'\|\s*full_inflate_preflight\s*\|\s*main\s*\|[^|]+\|\s*(\d+)',
                                args.output.with_suffix('.log').read_text())
            if counts:
                record['acir_opcodes'] = int(counts[0])
            if args.bb:
                # Preserve successful compilation even if the gate tool fails.
                args.output.write_text(json.dumps(record, indent=2) + '\n')
                start = time.monotonic()
                gate_log = args.output.with_suffix('.gates.log')
                with gate_log.open('w') as log, args.output.with_suffix('.gates.stderr.log').open('w') as errors:
                    gate_code, gate_status = run_limited([args.bb, 'gates', '-b', str(acir)],
                        log, errors, args.seconds, limits, args.rss_limit_gib)
                record['gate_measurement'] = dict(exit_code=gate_code, status=gate_status,
                                                seconds=time.monotonic()-start)
                if gate_code == 0:
                    record['gates'] = json.loads(gate_log.read_text())
                    record['acir_opcodes'] = record['gates']['functions'][0]['acir_opcodes']
        args.output.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record, indent=2))
        if code != 0:
            raise SystemExit(1)


if __name__ == '__main__':
    main()

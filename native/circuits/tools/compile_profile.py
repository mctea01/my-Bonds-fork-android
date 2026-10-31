#!/usr/bin/env python3
"""Measure full-capacity inflate compilation in a fresh standalone package."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MAIN = '''use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint,InflateHints};
fn main(data:[u8;COMPRESSED],data_len:u32,blocks:[BlockHint;BLOCKS],block_count:u32,
    tokens:[TokenHint;TOKENS],owners:[u32;PLAIN],plain_len:u32,hints:InflateHints<TOKENS,BLOCKS>,expected:[u8;PLAIN]) {
    assert_eq(inflate(data,data_len,blocks,block_count,tokens,owners,plain_len,expected,hints),expected);
}
'''


def run_limited(command, stdout, stderr, seconds, limits, rss_limit_gib=None, poll_interval=0.05):
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
            time.sleep(poll_interval)
        return child.returncode, 'compiled' if child.returncode == 0 else 'compiler_failed'


def measured_limited(command, log, seconds, limits, rss_limit_gib):
    """Use fresh child accounting for each witness/prover/verifier process."""
    pid = os.fork()
    if pid == 0:
        start = time.monotonic()
        with log.open('w') as output:
            witness = len(command)>1 and command[1]=='execute'
            sink = subprocess.DEVNULL if witness else output
            code, status = run_limited(command, sink, sink, seconds, limits, rss_limit_gib,
                                       0.001 if len(command)>1 and command[1]=='verify' else 0.05)
            if witness:
                output.write(json.dumps(dict(exit_code=code,status=status,output='witness diagnostics suppressed'))+'\n')
        result = dict(seconds=time.monotonic()-start, exit_code=code,
                      status={"compiled":"completed", "compiler_failed":"process_failed"}.get(status,status),
                      peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        log.with_suffix('.measurement.json').write_text(json.dumps(result))
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    if status != 0:
        raise RuntimeError('Measurement worker failed')
    return json.loads(log.with_suffix('.measurement.json').read_text())


def prove_profile(args, root, acir, record, limits):
    # Explicit local imports remain available under python3 -I.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from fixtures import compressed
    from probe_fixture import write
    prover = root/'Prover.toml'
    if args.segment or args.segment0:
        from segment_reference import Poseidon, segments, write as write_segment
        oracle = Poseidon(args.bb_js)
        try:
            chain = segments(compressed(b'A'*(args.plain if args.segment0 else args.plain*2)), oracle, args.plain, args.tokens, args.blocks, args.compressed)
            write_segment(prover, chain[0] if args.segment0 else chain[1])
        finally:
            oracle.close()
    else:
        write(prover, compressed(b'A'*args.plain), capacity=args.compressed,
              plain_capacity=args.plain, token_capacity=args.tokens, block_capacity=args.blocks)
        if args.blocks == 1:
            prover.write_text('block_count = 1\n'+prover.read_text())
    args.crs.mkdir(parents=True, exist_ok=True)
    proof = root/'target/proof'
    proof.mkdir()
    record['proof_scope'] = ('Synthetic repeated-byte stream fills plain capacity; first/final or second/final segment' if (args.segment or args.segment0) else 'Synthetic repeated-byte stream fills plain capacity; component only, no PDF statement')
    record['zero_knowledge'] = True
    record['oracle_hash'] = 'poseidon2'
    record['prove'] = {}
    commands = [('witness', [args.nargo, 'execute', '--program-dir', str(root), '--pedantic-solving'])]
    for run in ('first', 'warm'):
        commands.append((run, [args.bb, 'prove', '-s', 'ultra_honk', '--oracle_hash', 'poseidon2',
            '-b', str(acir), '-w', str(root/'target/full_inflate_preflight.gz'),
            '-o', str(proof), '--write_vk', '-c', str(args.crs.resolve())]))
    commands.append(('verify', [args.bb, 'verify', '-s', 'ultra_honk', '--oracle_hash', 'poseidon2',
        '-k', str(proof/'vk'), '-p', str(proof/'proof'), '-i', str(proof/'public_inputs'),
        '-c', str(args.crs.resolve())]))
    compiled_bytecode = json.loads(acir.read_text())['bytecode']
    for name, command in commands:
        result = measured_limited(command, args.output.with_suffix(f'.{name}.log'),
                                  args.seconds, limits, args.rss_limit_gib)
        if name == 'witness' and result['exit_code'] == 0:
            solved_acir = json.loads(acir.read_text())
            if solved_acir['bytecode'] != compiled_bytecode:
                raise RuntimeError('Circuit changed between compilation and witness generation')
            record['pre_witness_acir_sha256'] = record['acir_sha256']
            record['acir_sha256'] = hashlib.sha256(acir.read_bytes()).hexdigest()
            args.output.with_suffix('.acir.json').write_bytes(acir.read_bytes())
        if name in ('first', 'warm'):
            record['prove'][name] = result
        else:
            record[name] = result
        if (proof/'proof').exists() and (proof/'vk').exists():
            record['proof_bytes'] = (proof/'proof').stat().st_size
            record['public_input_bytes'] = (proof/'public_inputs').stat().st_size
            record['vk_sha256'] = hashlib.sha256((proof/'vk').read_bytes()).hexdigest()
        args.output.write_text(json.dumps(record, indent=2)+'\n')
        if result['exit_code'] != 0:
            return False
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compile-threads',type=int,choices=[1,2],default=2)
    parser.add_argument('--formal-tier',choices=['phone','desktop'])
    parser.add_argument('--formal-kind',choices=['sha_content','sha_opaque','inflate0','inflate','lex','claim','pred'])
    parser.add_argument('--bounded-codegen', action='store_true')
    parser.add_argument('--text-profile', choices=['lex','claim','pred'])
    parser.add_argument('--k', type=int, default=1)
    parser.add_argument('--slot-count', type=int, default=12)
    parser.add_argument('--nargo', default='nargo')
    parser.add_argument('--seconds', type=int, default=1800)
    parser.add_argument('--compressed', type=int, default=8192)
    parser.add_argument('--plain', type=int, help='Defaults to 2048 for text profiles, 40960 otherwise')
    parser.add_argument('--tokens', type=int, default=6144)
    parser.add_argument('--blocks', type=int, default=4)
    parser.add_argument('--bb', help='Pinned bb 2.1.9; measure gates after compilation')
    parser.add_argument('--segment0', action='store_true', help='Profile first segment without history')
    parser.add_argument('--segment', action='store_true', help='Profile pdf_inflate_seg_v1 with full 32 KiB history')
    parser.add_argument('--bb-js', type=Path, help='Pinned bb.js dest/node/index.js for segment synthetic witnesses')
    parser.add_argument('--prove', action='store_true', help='Also measure a synthetic full-output component proof')
    parser.add_argument('--crs', type=Path, help='External CRS cache for --prove')
    parser.add_argument('--address-space-gib', type=int, default=24)
    parser.add_argument('--rss-limit-gib', type=float,
                        help='Optional session-protection guard; reported separately from compiler failure')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.plain is None:
        args.plain = 2048 if args.text_profile else 40960
    if args.seconds <= 0 or args.address_space_gib <= 0:
        parser.error('Resource budgets must be positive')
    if args.rss_limit_gib is not None and args.rss_limit_gib <= 0:
        parser.error('RSS guard must be positive')
    if args.formal_tier or args.formal_kind:
        if not (args.formal_tier and args.formal_kind):parser.error('Both formal tier and kind are required')
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from formal_profile import run
        raise SystemExit(0 if run(args) else 1)
    if args.text_profile:
        sys.path.insert(0,str(Path(__file__).resolve().parent))
        from text_profile import run
        raise SystemExit(0 if run(args) else 1)
    if args.prove and (not args.bb or not args.crs):
        parser.error('--prove requires --bb and --crs')
    for name, maximum in [('compressed',8192), ('plain',40960), ('tokens',6144), ('blocks',4)]:
        if not 0 < getattr(args, name) <= maximum:
            parser.error(f'{name} must be between 1 and {maximum}')
    if (args.segment or args.segment0) and args.plain > 8192:
        parser.error('Segment plain capacity must be <=8192')
    if (args.segment or args.segment0) and args.prove and not args.bb_js:
        parser.error('Segment --prove requires --bb-js')
    source = MAIN
    if args.segment or args.segment0:
        source = (ROOT/('pdf_inflate_seg0_v1' if args.segment0 else 'pdf_inflate_seg_v1')/'src/main.nr').read_text()
        for constant, value in [('SEG_PLAIN',args.plain),('SEG0_TOKENS' if args.segment0 else 'SEG_TOKENS',args.tokens),('SEG_BLOCK_STARTS',args.blocks),('MAX_COMPRESSED',args.compressed)]:
            source = re.sub(r'(global '+constant+r':u32=)\d+',lambda m: m[1]+str(value),source)
    if not (args.segment or args.segment0):
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
    args.output.with_suffix('.main.nr').write_text(source)
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
            scope=('first inflate segment without history' if args.segment0 else 'inflate segment with 32 KiB history') if (args.segment or args.segment0) else 'inflate only; not the complete pdf_text_v1_1p circuit',
            nargo=version, status=status, exit_code=code,
            seconds=time.monotonic()-start,
            peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            timeout_seconds=args.seconds, address_space_limit_gib=args.address_space_gib,
            rss_guard_gib=args.rss_limit_gib,
            compressed_capacity=args.compressed, plain_capacity=args.plain,
            token_capacity=args.tokens, block_capacity=args.blocks,
            main_sha256=hashlib.sha256(source.encode()).hexdigest(),
            inflate_source_sha256=source_hash,
            segment_source_sha256=hashlib.sha256((ROOT/'pdf_text_v1/src/inflate_segment.nr').read_bytes()).hexdigest() if args.segment else None,
            history_segments=(32768+args.plain-1)//args.plain if args.segment else None,
            acir_sha256=None, acir_opcodes=None, vk_sha256=None, gates=None,
            prove=None, verify=None, proof_bytes=None,
            measurement_command='nargo info (fresh package; includes compilation)',
            environment={name: Path('/sys/fs/cgroup', name).read_text().strip()
                         for name in ('memory.max', 'cpu.max', 'memory.events')
                         if Path('/sys/fs/cgroup', name).exists()})
        acir = root / 'target/full_inflate_preflight.json'
        if code == 0:
            record['acir_sha256'] = hashlib.sha256(acir.read_bytes()).hexdigest()
            snapshot = json.loads(acir.read_text()).get('file_map', {})
            record['source_snapshot_sha256'] = {
                item['path']: hashlib.sha256(item['source'].encode()).hexdigest()
                for item in snapshot.values() if 'pdf_text_v1/' in item['path']}

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
        proof_completed = not args.prove
        if code == 0 and args.prove:
            proof_completed = prove_profile(args, root, acir, record, limits)
        args.output.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record, indent=2))
        if code != 0 or not proof_completed:
            raise SystemExit(1)


if __name__ == '__main__':
    main()

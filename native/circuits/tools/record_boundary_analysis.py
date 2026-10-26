#!/usr/bin/env python3
"""Reproduce the specified raw-TJ record boundary ambiguity, using fake dates."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lex_reference import decode_literal


def analyze():
    parts = [b'2020-01-', bytes([92, 55]), b'1']
    per_string = b''.join(decode_literal(part) for part in parts)
    raw_record = decode_literal(b''.join(parts))

    def date_groups(data):
        year, month, day = map(int, re.findall(rb'[0-9]+', data))
        return year * 10000 + month * 100 + day

    pdf_date, record_date = date_groups(per_string), date_groups(raw_record)
    assert (pdf_date, record_date) == (20200101, 20200109)
    assert (pdf_date >= 20200105) != (record_date >= 20200105)
    hex_parts = ['3', '1']
    pdf_hex = b''.join(bytes.fromhex(part + '0') for part in hex_parts)
    record_hex = bytes.fromhex(''.join(hex_parts))
    assert pdf_hex == bytes([0x30, 0x10]) and record_hex == bytes([0x31])
    return dict(status='design_issue_reproduced', pdf_date=pdf_date,
                concatenated_record_date=record_date, date_ge_cutoff=20200105,
                pdf_hex=list(pdf_hex), concatenated_record_hex=list(record_hex))


def constrained_demo(nargo, module):
    from lex_reference import build, text, package, write, Poseidon, ROOT, verify_chain
    h = Poseidon(module)
    try:
        show = b'BT /FakeFont 12 Tf [(2020-01-)(' + bytes([92, 55]) + b')(1)] TJ ET\n'
        content = text(b'FAKE START') + show + text(b'FAKE END')
        chain = build(content, h, P=64, A=8, C=4, Q=128, R=64,
                      anchor_ops=[0, 2], ranges=[(0, 1)], T=96, T0=96, N=1024)
        chain['claim']['predicates'][0].update(kind=1, cutoff=20200105)
        verify_chain(chain, h, 64, 1)
        cache = Path(tempfile.gettempdir()) / ('diw-text-regressions-' + hashlib.sha256(str(ROOT).encode()).hexdigest()[:16])
        lex = package(cache / 'lex', 'lex', P=64, A=8, C=4, Q=128, R=64)
        claim = package(cache / 'claim', 'claim', A=8, C=4, Q=128, R=64)
        executions = [(lex, witness) for witness in chain['lex']] + [(claim, chain['claim'])]
        for root, witness in executions:
            write(root / 'Prover.toml', witness)
            result = subprocess.run([nargo, 'execute', '--program-dir', str(root), '--pedantic-solving'],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if result.returncode:
                raise RuntimeError('Boundary demonstration execution failed; witness output suppressed')
        return dict(lexical_segments=len(chain['lex']), claim_executions=1,
                    circuit_accepts_concatenated_record_predicate=True,
                    pdf_per_string_predicate=False)
    finally:
        h.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nargo')
    parser.add_argument('--bb-js', type=Path)
    args = parser.parse_args()
    if bool(args.nargo) != bool(args.bb_js):
        parser.error('--nargo and --bb-js must be supplied together')
    result = analyze()
    if args.nargo:
        result['constrained_demonstration'] = constrained_demo(args.nargo, args.bb_js)
    print(json.dumps(result, indent=2))

#!/usr/bin/env python3
"""Reproduce the specified raw-TJ record boundary ambiguity, using fake dates."""
import json
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


if __name__ == '__main__':
    print(json.dumps(analyze(), indent=2))

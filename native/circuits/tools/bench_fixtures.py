#!/usr/bin/env python3
"""Regenerate synthetic inputs. No document, credential or live response is read."""
from pathlib import Path
import subprocess
import sys
from fixtures import compressed
from probe_fixture import write, small_dynamic

root=Path(__file__).resolve().parents[1]
for blocks in (65,130,260):
    subprocess.run([sys.executable,str(root/'tools/sha_fixture.py'),str(blocks)],check=True)
for size in (16384,32768,40960):
    write(root/'bench'/f'inflate_{size//1024}k'/'Prover.toml',compressed(b'A'*size),plain_capacity=size,token_capacity=192)
write(root/'bench/inflate_probe/Prover.toml',small_dynamic())

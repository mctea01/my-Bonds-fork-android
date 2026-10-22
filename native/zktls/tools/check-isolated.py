#!/usr/bin/env python3
"""Validate WP5 without changing the integration-owned module registry or lock."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

p=argparse.ArgumentParser()
p.add_argument('--cargo',default='cargo')
p.add_argument('--toolchain',default='1.95.0')
a=p.parse_args()
native=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='diw-wp5-') as temporary:
    work=Path(temporary)
    for name in ('zktls','diw-zk-ffi'):
        shutil.copytree(native/name,work/name,ignore=shutil.ignore_patterns('target','__pycache__'))
    (work/'Cargo.toml').write_text('''[workspace]
members = ["zktls", "diw-zk-ffi"]
resolver = "2"
[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"
rust-version = "1.95"
[workspace.dependencies]
uniffi = "=0.29.4"
sha2 = "=0.10.9"
thiserror = "=2.0.17"
''')
    # OpenAC and zkPDF are unrelated work packages. Keep their cfg names for
    # checking, without resolving their optional dependency graphs here.
    manifest=work/'diw-zk-ffi/Cargo.toml'
    lines=manifest.read_text().splitlines()
    manifest.write_text('\n'.join(line for line in lines if not line.startswith(('openac','zkpdf')))
        .replace('default = []','default = []\nopenac = []\nzkpdf = []')+'\n')
    lib=work/'diw-zk-ffi/src/lib.rs'
    lib.write_text(lib.read_text().replace('mod openac;','mod openac;\nmod zktls;'))
    env=os.environ.copy();env['RUSTUP_TOOLCHAIN']=a.toolchain
    subprocess.run([a.cargo,'generate-lockfile','--manifest-path',str(work/'Cargo.toml')],env=env,check=True)
    for flags in (['-p','zktls','-p','diw-zk-ffi','--features','tlsn'],['-p','diw-zk-ffi']):
        subprocess.run([a.cargo,'test','--release','--locked','--manifest-path',str(work/'Cargo.toml')]+flags,env=env,check=True)

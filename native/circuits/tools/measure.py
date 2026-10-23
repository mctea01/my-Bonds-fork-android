#!/usr/bin/env python3
"""Measure synthetic component proofs; never prints or exports witnesses."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]

def measured(command, log, cwd=ROOT):
    # Each measurement runs in its own child, so ru_maxrss is not cumulative.
    pid = os.fork()
    if pid == 0:
        start = time.monotonic()
        with log.open('w') as output:
            result = subprocess.run(command, cwd=cwd, stdout=output, stderr=output)
        record = dict(seconds=time.monotonic()-start, peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                      exit_code=result.returncode)
        log.with_suffix('.measurement.json').write_text(json.dumps(record))
        os._exit(0)
    os.waitpid(pid, 0)
    result = json.loads(log.with_suffix('.measurement.json').read_text())
    if result['exit_code'] != 0:
        raise RuntimeError(f'Command failed; inspect {log.name}')
    return result

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('packages', nargs='+')
    p.add_argument('--nargo', default='nargo')
    p.add_argument('--bb', default='bb')
    p.add_argument('--crs', required=True)
    args = p.parse_args()
    assert '1.0.0-beta.15' in subprocess.check_output([args.nargo,'--version'],text=True)
    assert subprocess.check_output([args.bb,'--version'],text=True).strip() == '2.1.9'
    results = ROOT/'target/measurements'
    results.mkdir(parents=True,exist_ok=True)
    for package in args.packages:
        if not package.replace('_','').isalnum(): raise ValueError('Invalid package')
        record = dict(package=package,nargo='1.0.0-beta.15',bb='2.1.9',zk=True,oracle_hash='poseidon2')
        record['compile'] = measured([args.nargo,'compile','--package',package],results/f'{package}-compile.log')
        record['witness'] = measured([args.nargo,'execute','--package',package],results/f'{package}-execute.log')
        acir = ROOT/'target'/f'{package}.json'
        witness = ROOT/'target'/f'{package}.gz'
        proof = ROOT/'target'/f'{package}_zk'
        proof.mkdir(exist_ok=True)
        gates = subprocess.check_output([args.bb,'gates','-b',str(acir)],stderr=subprocess.DEVNULL,text=True)
        record['gates'] = json.loads(gates)
        for run in ('first','warm'):
            record[run] = measured([args.bb,'prove','-s','ultra_honk','--oracle_hash','poseidon2','-b',str(acir),
                '-w',str(witness),'-o',str(proof),'--write_vk','-c',args.crs],results/f'{package}-{run}.log')
        record['verify'] = measured([args.bb,'verify','-s','ultra_honk','--oracle_hash','poseidon2',
            '-k',str(proof/'vk'),'-p',str(proof/'proof'),'-i',str(proof/'public_inputs'),'-c',args.crs],results/f'{package}-verify.log')
        record.update(acir_sha256=digest(acir),vk_sha256=digest(proof/'vk'),proof_bytes=(proof/'proof').stat().st_size,
                      public_input_bytes=(proof/'public_inputs').stat().st_size)
        (results/f'{package}.json').write_text(json.dumps(record,indent=2)+'\n')
        print(package, 'complete', flush=True)

if __name__=='__main__': main()

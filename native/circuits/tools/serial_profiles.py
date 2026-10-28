#!/usr/bin/env python3
"""Run the ten distinct candidate circuits sequentially after validation ends."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from formal_profiles import ROOT

JOBS=[('phone','sha_content'),('phone','sha_opaque'),('phone','inflate0'),('phone','inflate'),('desktop','inflate0'),('desktop','inflate'),('phone','lex'),('desktop','lex'),('phone','claim'),('phone','pred')]

def busy_processes():
    names=[]
    for p in Path('/proc').glob('[0-9]*/comm'):
        try:
            name=p.read_text().strip()
            if name in ('nargo','bb','java'):names.append(name)
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    return names

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nargo',required=True);parser.add_argument('--bb',required=True)
    parser.add_argument('--crs',type=Path,required=True);parser.add_argument('--output',type=Path,default=ROOT/'target/round10-profiles')
    parser.add_argument('--resume',action='store_true',help='Skip already verified source-identical profile records')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    env=dict(os.environ,HARDWARE_CONCURRENCY='2',RAYON_NUM_THREADS='2')
    for tier,kind in JOBS:
        if busy_processes():raise RuntimeError('Finish other nargo, bb and Java processes before isolated measurements')
        output=args.output/f'{tier}-{kind}.json'
        if args.resume and output.exists():
            import hashlib
            r=json.loads(output.read_text())
            if r.get('status')=='verified' and all(hashlib.sha256((ROOT/k).read_bytes()).hexdigest()==v for k,v in r['source_sha256'].items()):
                print(tier+'/'+kind+': verified source-identical record retained',flush=True);continue
        command=[sys.executable,'-I',str(ROOT/'tools/compile_profile.py'),'--formal-tier',tier,'--formal-kind',kind,'--nargo',str(Path(args.nargo).resolve()),'--bb',str(Path(args.bb).resolve()),'--prove','--crs',str(args.crs.resolve()),'--seconds','1800','--address-space-gib','24','--rss-limit-gib','6','--output',str(output.resolve())]
        print(tier+'/'+kind+': isolated compile, first/warm prove, verify',flush=True)
        result=subprocess.run(command,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode:raise RuntimeError(tier+'/'+kind+': measurement failed; inspect sanitized metadata')
        record=json.loads(output.read_text());assert record['status']=='verified'
        print(tier+'/'+kind+': verified',flush=True)
if __name__=='__main__':main()

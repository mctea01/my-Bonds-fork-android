#!/usr/bin/env python3
"""Fresh lexical/claim profiles, using the shared bounded measurement runner."""
import hashlib
import json
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import time
from compile_profile import measured_limited
from lex_reference import package,build,synthetic,text,write,Poseidon,ROOT

def run(args):
    if not args.bb or not args.bb_js:raise ValueError('Text profile requires pinned --bb and --bb-js')
    if args.prove and not args.crs:raise ValueError('--prove requires --crs')
    if not 1<=args.plain<=8192:raise ValueError('Text fixture plain capacity must be in 1..8192')
    if args.k not in (1,2,4):raise ValueError('K must be 1, 2 or 4')
    if not 1<=args.slot_count<=12:raise ValueError('Invalid slot count')
    version=subprocess.check_output([args.nargo,'--version'],text=True).strip()
    assert version.splitlines()[0]=='nargo version = 1.0.0-beta.15'
    assert subprocess.check_output([args.bb,'--version'],text=True).strip()=='2.1.9'
    args.output.parent.mkdir(parents=True,exist_ok=True)
    compile_flags=['--bounded-codegen'] if args.bounded_codegen else []
    def limits():
        budget=args.address_space_gib*1024**3;resource.setrlimit(resource.RLIMIT_AS,(budget,budget));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    record=dict(timeout_seconds=args.seconds,rss_guard_gib=args.rss_limit_gib,address_space_limit_gib=args.address_space_gib,compile_flags=compile_flags,scope=args.text_profile,nargo=version,plain_capacity=args.plain,k=args.k,max_claims=12,max_claim_src=384,max_anchor_src=96,seg_ops=64*((args.k*args.plain+2047)//2048),slot_start=0,slot_count=args.slot_count,zero_knowledge=True,oracle_hash='poseidon2',prove={})
    with tempfile.TemporaryDirectory(prefix='diw-text-profile-') as tmp:
        root=package(tmp,args.text_profile,P=args.plain,K=args.k,A=16,C=12,Q=384,R=96,count=args.slot_count)
        # Compile and execute the exact same immutable source snapshot.
        shutil.copytree(ROOT/'pdf_text_v1',root/'library',ignore=shutil.ignore_patterns('target','Prover.toml','__pycache__'))
        (root/'Nargo.toml').write_text('[package]\nname="text_regression"\ntype="bin"\nauthors=[]\n[dependencies]\npdf_text_v1={path="library"}\n')
        source=(root/'src/main.nr').read_bytes();args.output.with_suffix('.main.nr').write_bytes(source)
        record['source_sha256']={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*.nr'))}
        measured=measured_limited([args.nargo,'info','--program-dir',str(root),*compile_flags],args.output.with_suffix('.compile.log'),args.seconds,limits,args.rss_limit_gib)
        record['compile']=measured;record['status']=measured['status']
        args.output.write_text(json.dumps(record,indent=2)+'\n')
        if measured['exit_code']:return False
        acir=root/'target/text_regression.json';record['acir_sha256']=hashlib.sha256(acir.read_bytes()).hexdigest()
        # Large ACIRs stay outside version control; hashes and source remain reproducible.
        gate_log=args.output.with_suffix('.gates.log')
        record['gate_measurement']=measured_limited([args.bb,'gates','-b',str(acir)],gate_log,args.seconds,limits,args.rss_limit_gib)
        if record['gate_measurement']['exit_code']==0:record['gates']=json.loads(gate_log.read_text()[gate_log.read_text().index('{'):])
        args.output.write_text(json.dumps(record,indent=2)+'\n')
        if not args.prove or record['gate_measurement']['exit_code']:return record['gate_measurement']['exit_code']==0
        h=Poseidon(args.bb_js)
        try:
            if args.text_profile=='lex':
                content,a,c=synthetic() if args.plain>=2048 else (text(b'FAKE'),[],[])
                content+=b' '*max(0,args.k*args.plain-len(content))
            else:
                content=text(b'FAKE BOUNDARY')
                for _ in range(12):content+=text(b'2020\\05501\\05502')+text(b'FAKE BOUNDARY')
                a=list(range(0,25,2));c=[(i,i+1) for i in range(12)]
            b=build(content,h,P=args.plain,K=args.k,anchor_ops=a,ranges=c)
            w=b['lex'][0] if args.text_profile=='lex' else b[args.text_profile]
            if args.text_profile=='claim':
                w['count']=args.slot_count;w['digests']=w['digests'][:args.slot_count];w['claim_salts']=w['claim_salts'][:args.slot_count]
            write(root/'Prover.toml',w)
        finally:h.close()
        args.crs.mkdir(parents=True,exist_ok=True);proof=root/'proof';proof.mkdir()
        commands=[('witness',[args.nargo,'execute','--program-dir',str(root),'--pedantic-solving',*compile_flags])]
        for name in ('first','warm'):commands.append((name,[args.bb,'prove','-s','ultra_honk','--oracle_hash','poseidon2','-b',str(acir),'-w',str(root/'target/text_regression.gz'),'-o',str(proof),'--write_vk','-c',str(args.crs.resolve())]))
        commands.append(('verify',[args.bb,'verify','-s','ultra_honk','--oracle_hash','poseidon2','-k',str(proof/'vk'),'-p',str(proof/'proof'),'-i',str(proof/'public_inputs'),'-c',str(args.crs.resolve())]))
        original=json.loads(acir.read_text())['bytecode']
        for name,command in commands:
            measured=measured_limited(command,args.output.with_suffix('.'+name+'.log'),args.seconds,limits,args.rss_limit_gib)
            if name in ('first','warm'):record['prove'][name]=measured
            else:record[name]=measured
            if name=='witness' and measured['exit_code']==0:assert json.loads(acir.read_text())['bytecode']==original
            if (proof/'proof').exists():
                record.update(proof_bytes=(proof/'proof').stat().st_size,public_input_bytes=(proof/'public_inputs').stat().st_size,vk_sha256=hashlib.sha256((proof/'vk').read_bytes()).hexdigest())
            args.output.write_text(json.dumps(record,indent=2)+'\n')
            if measured['exit_code']:return False
    return True

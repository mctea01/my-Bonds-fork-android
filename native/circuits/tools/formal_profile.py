"""Serial compile/prove measurement of actual pinned candidate packages."""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
from compile_profile import measured_limited
from formal_profiles import ROOT,PARAMS,location,package_name,validate
from poseidon_reference import Poseidon
from segment_reference import write,segments,byte_commit,pack31,DOMAIN
from fixtures import compressed
from lex_reference import build,synthetic,text
from sha_fixture import IV,compress

def witness(tier,kind):
    h=Poseidon();h.self_test();p=PARAMS[tier];P=p['P']
    if kind in ('inflate0','inflate'):
        chain=segments(compressed(b'A'*(P if kind=='inflate0' else 2*P)),h,P,p['T'],1,8192,token0_capacity=p['T0']);return chain[0 if kind=='inflate0' else 1]
    if kind in ('lex','claim','pred'):
        if kind=='lex':
            content,a,c=synthetic();content+=b' '*max(0,P-len(content))
        else:
            content=text(b'FAKE BOUNDARY')
            for _ in range(12):content+=text(b'2020\\05501\\05502')+text(b'FAKE BOUNDARY')
            a=list(range(0,25,2));c=[(i,i+1) for i in range(12)]
        b=build(content,h,P=P,anchor_ops=a,ranges=c,T=p['T'],T0=p['T0'])
        return b['lex'][0] if kind=='lex' else b[kind]
    content=kind=='sha_content';capacity=130 if content else 128;n=8192;head_len=63 if content else 0
    private=bytes((i*73+19)%256 for i in range(n));head=bytes(range(head_len));tail=bytes((-(head_len+n))%64)
    data=head+private+tail;state=IV[:]
    for i in range(0,len(data),64):state=compress(state,data[i:i+64])
    w=dict(domain=DOMAIN,circuit=int.from_bytes(('pdf_'+kind+'_v1').encode(),'big'),mid_in=IV,mid_out=state,blocks=len(data)//64,head_len=len(head),head=[hex(x) for x in pack31(head+bytes(63-len(head)))],tail_len=len(tail),tail=[hex(x) for x in pack31(tail+bytes(63-len(tail)))],bytes=list(data)+[0]*(capacity*64-len(data)))
    if content:
        key=bytes((i*17+3)%256 for i in range(n));z=bytes(a^b for a,b in zip(private,key))
        w.update(encrypted=True,keystream=[hex(x) for x in pack31(key)],cz=byte_commit(h,42,z,8192),salt=42)
    return w

def run(args):
    tier,kind=args.formal_tier,args.formal_kind;validate(tier)
    assert args.bb and args.crs and args.prove
    version=subprocess.check_output([args.nargo,'--version'],text=True).strip();assert version.splitlines()[0]=='nargo version = 1.0.0-beta.15'
    assert subprocess.check_output([args.bb,'--version'],text=True).strip()=='2.1.9'
    root=location(tier,kind);name=package_name(tier,kind);acir=ROOT/'target'/f'{name}.json'
    w=witness(tier,kind);write(root/'Prover.toml',w)
    args.output.parent.mkdir(parents=True,exist_ok=True);args.crs.mkdir(parents=True,exist_ok=True)
    proof=ROOT/'target/formal-proofs'/name;proof.mkdir(parents=True,exist_ok=True)
    def limits():
        size=args.address_space_gib*1024**3;resource.setrlimit(resource.RLIMIT_AS,(size,size));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    record=dict(scope='Candidate formal package; synthetic witness; serial isolated measurement',tier=tier,kind=kind,package=name,nargo=version,bb='2.1.9',zero_knowledge=True,oracle_hash='poseidon2',prove={},environment={**{n:Path('/sys/fs/cgroup',n).read_text().strip() for n in ('cpu.max','memory.max')},'hardware_concurrency':os.environ.get('HARDWARE_CONCURRENCY'),'rayon_num_threads':os.environ.get('RAYON_NUM_THREADS'),'cpu_affinity':sorted(os.sched_getaffinity(0))},parameters=PARAMS[tier],source_sha256={str(x.relative_to(ROOT)):hashlib.sha256(x.read_bytes()).hexdigest() for x in sorted([*root.rglob('*.nr'),*(ROOT/'pdf_text_v1/src').glob('*.nr')])})
    record['crs_before']={str(x.relative_to(args.crs)):x.stat().st_size for x in args.crs.rglob('*') if x.is_file()}
    def save():args.output.write_text(json.dumps(record,indent=2)+'\n')
    def measure(label,cmd):
        r=measured_limited(cmd,args.output.with_suffix('.'+label+'.log'),args.seconds,limits,args.rss_limit_gib)
        if label in ('first','warm'):record['prove'][label]=r
        else:record[label]=r
        save();return r['exit_code']==0
    try:
        # Delete only this package's cached ACIR so compilation is measured fresh.
        acir.unlink(missing_ok=True)
        if not measure('compile',[args.nargo,'info','--program-dir',str(ROOT),'--package',name]):return False
        if not measure('gate_measurement',[args.bb,'gates','-b',str(acir)]):return False
        gate=args.output.with_suffix('.gate_measurement.log').read_text();record['gates']=json.loads(gate[gate.index('{'):]);save()
        before=json.loads(acir.read_text())['bytecode']
        if not measure('witness',[args.nargo,'execute','--program-dir',str(ROOT),'--package',name,'--pedantic-solving']):return False
        assert before==json.loads(acir.read_text())['bytecode']
        record['acir_sha256']=hashlib.sha256(acir.read_bytes()).hexdigest();record['abi']=json.loads(acir.read_text())['abi'];save()
        for label in ('first','warm'):
            if not measure(label,[args.bb,'prove','-s','ultra_honk','--oracle_hash','poseidon2','-b',str(acir),'-w',str(ROOT/'target'/f'{name}.gz'),'-o',str(proof),'--write_vk','-c',str(args.crs.resolve())]):return False
        if not measure('verify',[args.bb,'verify','-s','ultra_honk','--oracle_hash','poseidon2','-k',str(proof/'vk'),'-p',str(proof/'proof'),'-i',str(proof/'public_inputs'),'-c',str(args.crs.resolve())]):return False
        record['crs_after']={str(x.relative_to(args.crs)):x.stat().st_size for x in args.crs.rglob('*') if x.is_file()}
        record.update(proof_bytes=(proof/'proof').stat().st_size,public_input_bytes=(proof/'public_inputs').stat().st_size,vk_sha256=hashlib.sha256((proof/'vk').read_bytes()).hexdigest(),status='verified');save()
        return True
    finally:(root/'Prover.toml').unlink(missing_ok=True)

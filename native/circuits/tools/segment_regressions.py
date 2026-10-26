#!/usr/bin/env python3
"""Execute synthetic segment chains and adversarial openings through ACIR."""
from copy import deepcopy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import zlib

from segment_reference import Poseidon,segments,write,ROOT,verify_chain,byte_commit
from fixtures import compressed,witness,table,LBASE,LEXTRA,DBASE,DEXTRA


def package(directory,P,T,B,N=8192):
    root=Path(directory); (root/'src').mkdir(parents=True,exist_ok=True)
    source=(ROOT/'pdf_inflate_seg_v1/src/main.nr').read_text()
    for key,value in [('SEG_PLAIN',P),('SEG_TOKENS',T),('SEG_BLOCK_STARTS',B),('MAX_COMPRESSED',N)]:
        source=re.sub(r'(global '+key+r':u32=)\d+',lambda m:m[1]+str(value),source)
    (root/'src/main.nr').write_text(source)
    (root/'Nargo.toml').write_text('[package]\nname="segment_regression"\ntype="bin"\nauthors=[]\n'
        '[dependencies]\npdf_text_v1={path='+json.dumps(str(ROOT/'pdf_text_v1'))+'}\n')
    return root


def long_distance():
    bits=[]
    def put(value,width): bits.extend((value>>i)&1 for i in range(width))
    def code(value,width): bits.extend((value>>i)&1 for i in reversed(range(width)))
    ll=[8]*144+[9]*112+[7]*24+[8]*8
    codes={symbol:(width,value) for (width,value),symbol in table(ll).items()}
    def symbol(s): width,value=codes[s]; code(value,width)
    def match(length,distance):
        i=next(i for i,b in reversed(list(enumerate(LBASE))) if b<=length)
        symbol(i+257); put(length-LBASE[i],LEXTRA[i])
        j=next(j for j,b in reversed(list(enumerate(DBASE))) if b<=distance)
        code(j,5); put(distance-DBASE[j],DEXTRA[j])
    put(1,1); put(1,2); symbol(65)
    remaining=32768-1
    while remaining:
        length=min(258,remaining)
        if length<3:
            symbol(65); remaining-=1
        else: match(length,1); remaining-=length
    match(258,32768); symbol(256)
    payload=bytes(sum(b<<j for j,b in enumerate(bits[i:i+8])) for i in range(0,len(bits),8))
    data=b'\x78\x01'+payload+zlib.adler32(b'A'*33026).to_bytes(4,'big')
    assert zlib.decompress(data)==b'A'*33026
    return data


def mixed():
    pieces=[compressed(b'A'*2500,zlib.Z_FIXED),compressed(b'stored-data'*7,level=0),
            compressed(b'variable alphabet abcdefghijklmnop '*180)]
    bits=[]; plain=b''
    for i,data in enumerate(pieces):
        blocks,_,_,out=witness(data); assert len(blocks)==1
        final=int(i==len(pieces)-1); kind=blocks[0]['kind']
        if kind==0:
            bits.extend([final,0,0]); bits.extend([0]*((-len(bits))%8))
            raw=len(out).to_bytes(2,'little')+(65535-len(out)).to_bytes(2,'little')+out
            for byte in raw: bits.extend((byte>>j)&1 for j in range(8))
        else:
            raw=[(data[j//8]>>(j%8))&1 for j in range(16,blocks[0]['end'])]; raw[0]=final
            bits.extend(raw)
        plain+=out
    payload=bytes(sum(b<<j for j,b in enumerate(bits[i:i+8])) for i in range(0,len(bits),8))
    result=b'\x78\x01'+payload+zlib.adler32(plain).to_bytes(4,'big')
    assert [b['kind'] for b in witness(result)[0]]==[1,0,2]
    return result


def run(nargo,module,output):
    h=Poseidon(module); results=[]
    def execute(root,name,s,reject=False):
        write(root/'Prover.toml',s)
        proc=subprocess.run([nargo,'execute','--program-dir',str(root),'--pedantic-solving'],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        rejected=proc.returncode==1 and 'Cannot satisfy constraint' in proc.stdout
        passed=rejected if reject else proc.returncode==0
        results.append(dict(case=name,expected='reject' if reject else 'accept',passed=passed))
        print(name+(': pass' if passed else ': FAIL'),flush=True)
        if not passed:
            # Keep diagnostics local to ignored target; never print private values.
            (ROOT/'target/segment-failure.log').write_text(proc.stdout)
            raise RuntimeError('Unexpected ACIR result; diagnostic retained under ignored target')
    try:
        with tempfile.TemporaryDirectory(prefix='diw-segments-') as tmp:
            root=package(Path(tmp)/'main',2048,288,3)
            fixed=segments(compressed(b'AB'*3000,zlib.Z_FIXED),h,2048,288,3)
            dynamic=segments(compressed(b'variable alphabet abcdefghijklmnop '*180),h,2048,288,3)
            assert witness(bytes(dynamic[0]['data'][:dynamic[0]['data_len']]))[0][0]['kind']==2
            far=segments(long_distance(),h,2048,288,3)
            multiple=segments(mixed(),h,2048,288,3)
            empty=segments(compressed(b''),h,2048,288,3)
            for label,chain in [('fixed',fixed),('dynamic',dynamic),('distance32768',far),('mixed',multiple),('empty',empty)]:
                verify_chain(chain,h,2048)
                for i,s in enumerate(chain): execute(root,f'{label}_{i}',s)
            # Every attack leaves all unrelated fields/openings valid.
            def attack(label,base,mutator):
                s=deepcopy(base); mutator(s); execute(root,label,s,True)
            attack('rejects_history_plain',fixed[1],lambda s:s['history'][-1].__setitem__(0,s['history'][-1][0]^1))
            attack('rejects_segment_index',fixed[1],lambda s:s.__setitem__('index',2))
            attack('rejects_resumed_table',dynamic[1],lambda s:s['resumed_l']['codes'].__setitem__(0,s['resumed_l']['codes'][0]^1))
            attack('rejects_table_commitment',dynamic[1],lambda s:s['incoming'].__setitem__('table_commitment',s['incoming']['table_commitment']+1))
            pending=next(s for s in fixed[1:] if s['incoming']['pending_len'])
            attack('rejects_pending_length',pending,lambda s:s['incoming'].__setitem__('pending_len',s['incoming']['pending_len']+1))
            attack('rejects_pending_distance',pending,lambda s:s['incoming'].__setitem__('pending_dist',s['incoming']['pending_dist']+1))
            def header(s):
                s['data'][0]^=1
                s['cz']=byte_commit(h,s['salt'],bytes(s['data'][:s['data_len']]),len(s['data']))
            attack('rejects_first_zlib_header',fixed[0],header)
            def adler(s):
                s['data'][s['data_len']-1]^=1
                s['cz']=byte_commit(h,s['salt'],bytes(s['data'][:s['data_len']]),len(s['data']))
            attack('rejects_last_adler',fixed[-1],adler)
            attack('rejects_cz',fixed[0],lambda s:s.__setitem__('cz',s['cz']+1))
            attack('rejects_output_plain',fixed[1],lambda s:s['plain'].__setitem__(0,s['plain'][0]^1))
            attack('rejects_sout',fixed[1],lambda s:s.__setitem__('sout',s['sout']+1))
            attack('rejects_cp',fixed[1],lambda s:s.__setitem__('cp',s['cp']+1))
            attack('rejects_first_flag',fixed[0],lambda s:s.__setitem__('first',False))
            attack('rejects_premature_last',fixed[0],lambda s:s.__setitem__('last',True))
            attack('rejects_domain',fixed[0],lambda s:s.__setitem__('domain',s['domain']+1))
            # Stored blocks cross a segment boundary under a literal-rich profile.
            stored_root=package(Path(tmp)/'stored',64,96,1,512)
            stored=segments(compressed(b'stored-boundary '*9,level=0),h,64,96,1,512)
            assert len(stored)>1 and stored[1]['incoming']['kind']==0
            for i,s in enumerate(stored): execute(stored_root,f'stored_{i}',s)
            attack_base=deepcopy(stored[1]); attack_base['incoming']['stored_end']+=8
            execute(stored_root,'rejects_stored_endpoint',attack_base,True)
            # Off-circuit splice/order checks complement proof acceptance.
            swapped=deepcopy(fixed); swapped[1],swapped[2]=swapped[2],swapped[1]
            try: verify_chain(swapped,h,2048)
            except AssertionError: results.append(dict(case='reference_rejects_reordered_chain',expected='reject',passed=True))
            else: raise RuntimeError('Reference accepted reordered chain')
    finally:
        h.close(); output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(results,indent=2)+'\n')

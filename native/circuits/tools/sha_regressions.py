"""SHA segment attacks through constrained ACIR; no witness diagnostics escape."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from pdf_fixture_chain import sha_package,execute
from poseidon_reference import Poseidon,P
from segment_reference import ROOT,DOMAIN,pack31,byte_commit
from sha_fixture import IV,compress

def fixture(kind='content',capacity=3,n=128,head_len=3,encrypted=True):
    h=Poseidon();key=bytes((i*17+3)%256 for i in range(n)) if encrypted else bytes(n)
    z=bytes((i*29+7)%256 for i in range(n));private=bytes(x^y for x,y in zip(z,key))
    head=bytes(range(head_len));tail=bytes((-(head_len+n))%64)
    data=head+private+tail;state=IV[:]
    for i in range(0,len(data),64):state=compress(state,data[i:i+64])
    w=dict(domain=DOMAIN,circuit=int.from_bytes(('pdf_sha_'+kind+'_v1').encode(),'big'),mid_in=IV,mid_out=state,blocks=len(data)//64,head_len=len(head),head=[hex(x) for x in pack31(head+bytes(63-len(head)))],tail_len=len(tail),tail=[hex(x) for x in pack31(tail+bytes(63-len(tail)))],bytes=list(data)+[0]*(capacity*64-len(data)))
    if kind=='content':w.update(encrypted=encrypted,keystream=[hex(x) for x in pack31(key+bytes(128-n))],cz=byte_commit(h,42,z,128),salt=42)
    return w

def run(nargo,output):
    results=[]
    with tempfile.TemporaryDirectory(prefix='diw-sha-regressions-') as directory:
        roots={k:sha_package(Path(directory)/k,k) for k in ('content','opaque')}
        for root in roots.values():
            p=root/'src/main.nr';s=p.read_text().replace('MAX_SHA_BLOCKS:u32=130','MAX_SHA_BLOCKS:u32=3').replace('MAX_SHA_BLOCKS:u32=128','MAX_SHA_BLOCKS:u32=3').replace('MAX_COMPRESSED:u32=8192','MAX_COMPRESSED:u32=128');p.write_text(s)
        for kind in roots:
            control=fixture(kind,n=60);root=roots[kind]
            results.append(execute(nargo,root,kind+'_control',control))
            def attack(name,mutate,base=control):
                w=deepcopy(base);mutate(w);results.append(execute(nargo,root,kind+'_'+name,w,True))
            attack('rejects_head',lambda w:w['head'].__setitem__(0,hex(int(w['head'][0],16)^(1<<240))))
            attack('rejects_tail',lambda w:w['tail'].__setitem__(0,hex(1<<240)))
            attack('rejects_mid_out',lambda w:w['mid_out'].__setitem__(0,w['mid_out'][0]^1))
            attack('rejects_zero_blocks',lambda w:w.__setitem__('blocks',0))
            attack('rejects_excess_blocks',lambda w:w.__setitem__('blocks',4))
            attack('rejects_zero_private_length',lambda w:w.update(blocks=1,head_len=1,tail_len=63))
            attack('rejects_unused_block',lambda w:w['bytes'].__setitem__(128,1))
            attack('rejects_head_pack_width',lambda w:w['head'].__setitem__(2,'0x100'))
            attack('rejects_tail_pack_width',lambda w:w['tail'].__setitem__(0,hex(1<<248)))
            attack('rejects_max_field_pack',lambda w:w['head'].__setitem__(0,hex(P-1)))
            attack('rejects_unused_head',lambda w:w['head'].__setitem__(2,'0x1'))
            attack('rejects_unused_tail',lambda w:w['tail'].__setitem__(2,'0x1'))
            if kind=='content':
                full=fixture(kind,n=128);results.append(execute(nargo,root,'content_full_capacity',full))
                for offset in (0,31,32,63):
                    results.append(execute(nargo,root,'content_full_head_'+str(offset),fixture(kind,n=128,head_len=offset)))
                results.append(execute(nargo,root,'content_single_byte_head_63',fixture(kind,n=1,head_len=63)))
                clear=fixture(kind,n=60,encrypted=False);results.append(execute(nargo,root,'content_clear_control',clear))
                attack('rejects_unencrypted_key',lambda w:w.__setitem__('encrypted',False))
                attack('rejects_key_after_length',lambda w:w['keystream'].__setitem__(2,'0x1'))
                attack('rejects_noncanonical_last_pack',lambda w:w['keystream'].__setitem__(-1,hex(1<<32)))
                attack('rejects_oversized_pack',lambda w:w['keystream'].__setitem__(0,hex(1<<248)))
                attack('rejects_wrong_cz',lambda w:w.__setitem__('cz',w['cz']+1))
                attack('rejects_changed_ciphertext',lambda w:w['bytes'].__setitem__(5,w['bytes'][5]^1))
                attack('rejects_excess_private_length',lambda w:w.update(head_len=0,head=["0x0"]*3,tail_len=0,tail=["0x0"]*3),full)
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(results,indent=2)+'\n')

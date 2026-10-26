#!/usr/bin/env python3
"""Synthetic segment witness/reference chain generator; run with python3 -I.

Poseidon2 is independently calculated by pinned bb.js 2.1.9, never trusted by
Noir. No witness or private input is printed. See --help for reproduction.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fixtures import witness, compressed
from probe_fixture import write as write_probe

ROOT = Path(__file__).resolve().parents[1]
STATE_KEYS = ('pos','output','tokens','blocks','phase','kind','final_block',
              'table_commitment','pending_len','pending_dist','a','b','stored_end')
TOKEN_KEYS = ('block','start','symbol','width','distance_symbol','distance_width','prefix','suffix')
DOMAIN = int.from_bytes(b'diw-zkpdf-v1','big')
CIRCUIT = int.from_bytes(b'pdf_inflate_seg_v1','big')
CIRCUIT0 = int.from_bytes(b'pdf_inflate_seg0_v1','big')

class Poseidon:
    def __init__(self, module):
        version=json.loads((Path(module).resolve().parents[2]/'package.json').read_text())['version']
        if version != '2.1.9': raise ValueError('Use pinned bb.js 2.1.9')
        self.child = subprocess.Popen(['node', str(ROOT/'tools/poseidon_reference.mjs'),str(module)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        self.cache = {}
    def hash(self, fields):
        key=tuple(map(int,fields))
        if key not in self.cache:
            self.child.stdin.write(json.dumps(list(map(str,key)))+'\n'); self.child.stdin.flush()
            response=self.child.stdout.readline()
            if not response: raise RuntimeError('Pinned Poseidon oracle failed; inputs suppressed')
            self.cache[key]=int(json.loads(response),16)
        return self.cache[key]
    def commit(self, tag, salt, fields): return self.hash([tag,salt,len(fields),*fields])
    def close(self):
        self.child.stdin.close(); self.child.wait(timeout=30)
        if self.child.returncode: raise RuntimeError('Poseidon oracle failed')

def pack31(data): return [int.from_bytes(data[i:i+31],'big') for i in range(0,len(data),31)]
def byte_commit(h,salt,data,size): return h.commit(1,salt,[len(data),*pack31(data+bytes(size-len(data)))])
def plain_commit(h,salt,index,plain,size): return h.commit(2,salt,[index,len(plain),*pack31(plain+bytes(size-len(plain)))])
def state_commit(h,salt,s): return h.commit(4,salt,[s[k] for k in STATE_KEYS])
def table_commit(h,salt,l,d): return h.commit(3,salt,l['lengths']+l['codes']+d['lengths']+d['codes'])
def initial():
    return dict(zip(STATE_KEYS,[16,0,0,0,0,0,False,0,0,0,1,0,0]))
def empty_table(n): return dict(lengths=[0]*n,codes=[0]*n)
def zero_token(): return dict(zip(TOKEN_KEYS,[0]*8))

def blank_header():
    # Reuse the established witness schema, including all canonical table hints.
    import tempfile
    import tomllib
    with tempfile.TemporaryDirectory() as tmp:
        path=Path(tmp)/'Prover.toml'; write_probe(path,compressed(b''),block_capacity=2)
        return tomllib.loads(path.read_text())['blocks'][1]

def tables(full,b):
    return (dict(lengths=full['ll_lengths'][b*288:(b+1)*288],codes=full['ll_codes'][b*288:(b+1)*288]),
            dict(lengths=full['dd_lengths'][b*32:(b+1)*32],codes=full['dd_codes'][b*32:(b+1)*32]))

def segments(data,h,plain_capacity=2048,token_capacity=288,block_capacity=1,compressed_capacity=8192,salt=42,token0_capacity=None):
    blocks,tokens,_,plain,full=witness(data,with_hints=True)
    if len(data)>compressed_capacity or len(plain)>40960 or len(tokens)>6144 or len(blocks)>4:
        raise ValueError('Synthetic stream exceeds global capacities')
    P,B=plain_capacity,block_capacity
    if token0_capacity is None: token0_capacity=token_capacity
    W=(32768+P-1)//P
    cz=byte_commit(h,salt,data,compressed_capacity)
    state=initial(); previous=[]; result=[]; token_cursor=0
    while True:
        index=len(result); incoming=deepcopy(state); state=deepcopy(state)
        T=token0_capacity if index==0 else token_capacity; E=T+B
        W=0 if index==0 else (32768+P-1)//P
        if state['phase']==1 and state['kind']>0: rl,rd=tables(full,state['blocks']-1)
        else: rl,rd=empty_table(288),empty_table(32)
        selected=[]; events=[]; lens=[]; distances=[]
        starts=[0]; ends=[state['pending_len']]; dists=[state['pending_dist']]; symbols=[0]
        produced=state['pending_len']; last_dist=state['pending_dist']; decoded=0
        while state['phase']!=2 and produced<=P:
            if produced==P and (state['phase']==0 or full['lengths'][token_cursor]>0): break
            if len(events)==E: raise ValueError('Segment event capacity insufficient for fixed-size split')
            before=produced; length=0; distance=0; symbol=0
            if state['phase']==0:
                if len(selected)==B: raise ValueError('SEG_BLOCK_STARTS insufficient for fixed-size split')
                b=state['blocks']; selected.append(deepcopy(blocks[b]))
                header=selected[-1]; header.pop('kind',None)
                assert header['start']==state['pos']
                state.update(pos=full['body'][b],kind=full['kinds'][b],final_block=b+1==len(blocks),
                             stored_end=blocks[b]['end'] if full['kinds'][b]==0 else 0,blocks=b+1,phase=1)
                if state['kind']==0 and state['pos']==state['stored_end']:
                    state['phase']=2 if state['final_block'] else 0
                events.append(dict(action=1,token=zero_token()))
            else:
                if token_cursor>=len(tokens): raise ValueError('Missing synthetic token')
                length=full['lengths'][token_cursor]; distance=full['distances'][token_cursor]
                if produced==P and length: break
                if decoded==T: raise ValueError('SEG_TOKENS insufficient for fixed-size split')
                t=tokens[token_cursor]; symbol=t[2]; assert t[1]==state['pos']
                events.append(dict(action=2,token=dict(zip(TOKEN_KEYS,t))))
                if state['kind']==0: state['pos']=t[1]+8
                else:
                    from fixtures import LEXTRA,DEXTRA
                    state['pos']=t[1]+t[3]+(LEXTRA[symbol-257]+t[5]+DEXTRA[t[4]] if symbol>256 else 0)
                token_cursor+=1; decoded+=1; state['tokens']+=1
                if (state['kind']==0 and state['pos']==state['stored_end']) or (state['kind']>0 and symbol==256):
                    state['phase']=2 if state['final_block'] else 0
                produced+=length
                if length: last_dist=distance
            starts.append(before); ends.append(produced); dists.append(distance); symbols.append(symbol)
            lens.append(length); distances.append(distance)
        event_count=len(events); header_count=len(selected)
        length=min(produced,P); last=state['phase']==2
        if not last and length!=P: raise ValueError('Non-final segment must fill SEG_PLAIN')
        segment_plain=plain[index*P:index*P+length]
        state['pending_len']=max(produced-P,0); state['pending_dist']=last_dist if produced>P else 0
        state['table_commitment']=table_commit(h,salt,*tables(full,state['blocks']-1)) if state['phase']==1 and state['kind']>0 else 0
        state['output']+=length
        # Independent recurrence, deliberately different from the circuit's weighted sum.
        for byte in segment_plain:
            state['a']=(state['a']+byte)%65521; state['b']=(state['b']+state['a'])%65521
        if last:
            assert state['b']*65536+state['a']==int.from_bytes(data[-4:],'big')
            assert (state['pos']+7)//8==len(data)-4 and token_cursor==len(tokens)
        event_owner=[]
        for k in range(length):
            owner=next(i for i,(a,b) in enumerate(zip(starts,ends)) if a<=k<b)
            event_owner.append(owner)
            expected=symbols[owner] if dists[owner]==0 else plain[index*P+k-dists[owner]]
            assert expected==segment_plain[k]
        while len(events)<E:
            events.append(dict(action=0,token=zero_token())); lens.append(0); distances.append(0)
            starts.append(produced); ends.append(produced); dists.append(0); symbols.append(0)
        ll,dd=deepcopy(rl),deepcopy(rd)
        for header in selected:
            l,d=tables(full,blocks.index(next(b for b in blocks if b['start']==header['start'])))
            for key in ll: ll[key]+=l[key]; dd[key]+=d[key]
        for _ in range(B-header_count):
            for key in ll: ll[key]+=[0]*288; dd[key]+=[0]*32
        selected += [blank_header() for _ in range(B-header_count)]
        cp=plain_commit(h,salt,index,segment_plain,P)
        current=dict(domain=DOMAIN,circuit=CIRCUIT0 if index==0 else CIRCUIT,index=index,first=index==0,last=last,cz=cz,
            sin=0 if index==0 else previous[-1]['sout'],sout=state_commit(h,salt,state),cp=cp,
            previous=[previous[j]['cp'] if j>=0 else 0 for j in range(index-W,index)],
            salt=salt,data=list(data)+[0]*(compressed_capacity-len(data)),data_len=len(data),incoming=incoming,
            resumed_l=rl,resumed_d=rd,headers=selected,header_count=header_count,events=events,event_count=event_count,
            hints=dict(ll_lengths=ll['lengths'],ll_codes=ll['codes'],dd_lengths=dd['lengths'],dd_codes=dd['codes'],
                starts=starts,ends=ends,distances=dists,symbols=symbols,lengths=lens,token_distances=distances),
            history=[list(plain[j*P:(j+1)*P]) if j>=0 else [0]*P for j in range(index-W,index)],
            plain=list(segment_plain)+[0]*(P-length),plain_len=length,owners=event_owner+[0]*(P-length))
        if index==0:
            del current["history"]; del current["previous"]
        result.append(current); previous.append(current)
        if last: break
    verify_chain(result,h,P)
    return result

def verify_chain(chain,h,P):
    """Reference verifier: recompute openings and enforce all public joins/order."""
    if not chain: raise ValueError('Empty chain')
    W=(32768+P-1)//P
    for i,s in enumerate(chain):
        assert s['salt']==chain[0]['salt']
        W=0 if i==0 else (32768+P-1)//P
        assert len(s['plain'])==P and len(s.get('history',[]))==W and len(s.get('previous',[]))==W
        assert s['plain'][s['plain_len']:]==[0]*(P-s['plain_len'])
        assert s['data'][s['data_len']:]==[0]*(len(s['data'])-s['data_len'])
        assert s['index']==i and s['first']==(i==0) and s['last']==(i+1==len(chain))
        assert s['domain']==DOMAIN and s['circuit']==(CIRCUIT0 if i==0 else CIRCUIT)
        assert s['cz']==chain[0]['cz']==byte_commit(h,s['salt'],bytes(s['data'][:s['data_len']]),len(s['data']))
        assert s['cp']==plain_commit(h,s['salt'],i,bytes(s['plain'][:s['plain_len']]),P)
        assert s['sin']==(0 if i==0 else chain[i-1]['sout'])
        if i: assert s['sin']==state_commit(h,s['salt'],s['incoming'])
        for w,j in enumerate(range(i-W,i)):
            assert s['previous'][w]==(chain[j]['cp'] if j>=0 else 0)
            assert s['history'][w]==(chain[j]['plain'] if j>=0 else [0]*P)
            if j>=0: assert plain_commit(h,s['salt'],j,bytes(s['history'][w]),P)==s['previous'][w]
    actual=b''.join(bytes(s['plain'][:s['plain_len']]) for s in chain)
    raw=bytes(chain[0]['data'][:chain[0]['data_len']])
    assert actual==zlib.decompress(raw)
    blocks,tokens,_,_=witness(raw)
    checksum=zlib.adler32(actual)
    final=dict(pos=blocks[-1]['end'],output=len(actual),tokens=len(tokens),blocks=len(blocks),
        phase=2,kind=blocks[-1]['kind'],final_block=True,table_commitment=0,
        pending_len=0,pending_dist=0,a=checksum&65535,b=checksum>>16,
        stored_end=blocks[-1]['end'] if blocks[-1]['kind']==0 else 0)
    assert chain[-1]['sout']==state_commit(h,chain[-1]['salt'],final)
    return True

FIELD_KEYS={'domain','circuit','cz','sin','sout','cp','salt','table_commitment'}
def toml(value,key=''):
    if isinstance(value,bool): return str(value).lower()
    if isinstance(value,dict): return '{ '+', '.join(k+' = '+(json.dumps(hex(v)) if k in {'font','name'} and isinstance(v,int) else toml(v,k)) for k,v in value.items())+' }'
    if isinstance(value,list): return '['+', '.join(toml(x,key) for x in value)+']'
    if key in FIELD_KEYS or key in {'previous','values','font_fp','font_power','name_fp','name_power','field_fp'} or (key in {'font','name'} and value>255): return json.dumps(hex(value))
    return str(value)
def write(path,fields):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text('\n'.join(k+' = '+toml(v,k) for k,v in fields.items())+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bb-js',type=Path,required=True,help='Pinned bb.js 2.1.9 dest/node/index.js')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--input',type=Path,help='Optional synthetic RFC 1950 stream; never prints its contents')
    p.add_argument('--plain',type=int,default=2048); p.add_argument('--tokens',type=int,default=288)
    p.add_argument('--tokens0',type=int,default=1024)
    p.add_argument('--blocks',type=int,default=1); p.add_argument('--compressed',type=int,default=8192)
    p.add_argument('--kind',choices=('fixed','dynamic','stored'),default='fixed')
    p.add_argument('--length',type=int,default=6000)
    a=p.parse_args(); h=Poseidon(a.bb_js)
    try:
        payload=(b'Synthetic segment stream. '*((a.length+25)//26+1))[:a.length]
        if a.input: data=a.input.read_bytes()
        elif a.kind=='stored': data=compressed(payload,level=0)
        else: data=compressed(payload,zlib.Z_FIXED if a.kind=='fixed' else zlib.Z_DEFAULT_STRATEGY)
        chain=segments(data,h,a.plain,a.tokens,a.blocks,a.compressed,token0_capacity=a.tokens0)
        for i,s in enumerate(chain): write(a.output/f'segment-{i:03}/Prover.toml',s)
        public=[{k:([hex(x) for x in s[k]] if k=='previous' else hex(s[k]) if k in FIELD_KEYS else s[k])
            for k in ('domain','circuit','index','first','last','cz','sin','sout','cp','previous') if k in s} for s in chain]
        (a.output/'chain.json').write_text(json.dumps(public,indent=2)+'\n')
        print(f'{len(chain)} synthetic segments; reference chain verified')
    finally: h.close()
if __name__=='__main__': main()

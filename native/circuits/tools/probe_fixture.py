#!/usr/bin/env python3
"""Inputs for the constrained small-capacity inflate harness."""
import argparse
import zlib
from pathlib import Path
from fixtures import witness, compressed

def small_dynamic():
    bits=[]
    def put(value,width): bits.extend((value>>i)&1 for i in range(width))
    def code(value,width): bits.extend((value>>i)&1 for i in reversed(range(width)))
    put(1,1); put(2,2); put(0,5); put(0,5); put(14,4)
    order=[16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1]
    for symbol in order: put({18:1,0:2,1:2}.get(symbol,0),3)
    code(0,1); put(65-11,7)
    code(3,2)
    code(0,1); put(138-11,7)
    code(0,1); put(52-11,7)
    code(3,2); code(2,2)
    code(0,1); code(1,1)
    payload=bytes(sum(b<<j for j,b in enumerate(bits[i:i+8])) for i in range(0,len(bits),8))
    data=b'\x78\x01'+payload+zlib.adler32(b'A').to_bytes(4,'big')
    assert zlib.decompress(data)==b'A'
    return data

def write(path,data,capacity=128,plain_capacity=128,token_capacity=32,mutation=None):
    blocks,tokens,owners,plain=witness(data)
    assert len(blocks)==1 and len(tokens)<=token_capacity and len(data)<=capacity and len(plain)<=plain_capacity
    data=list(data)
    if mutation=='checksum': data[-1]^=1
    if mutation=='gap': tokens[1][1]+=1
    if mutation=='owner': owners[0]=1
    fields={'data':data+[0]*(capacity-len(data)),'data_len':len(data),'plain_len':len(plain),
        'owners':owners+[0]*(plain_capacity-len(owners)),'expected':list(plain)+[0]*(plain_capacity-len(plain))}
    lines=[f'{k} = {v}' for k,v in fields.items()]
    for b in blocks:
        lines.append('[[blocks]]')
        lines.extend(f'{k} = {v}' for k,v in b.items() if k!='kind')
    keys=['block','start','symbol','width','distance_symbol','distance_width']
    for token in tokens+[[0]*6]*(token_capacity-len(tokens)):
        lines.append('[[tokens]]')
        lines.extend(f'{k} = {v}' for k,v in zip(keys,token))
    path.write_text('\n'.join(lines)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('output',type=Path)
    p.add_argument('--kind',choices=['fixed','stored','dynamic','empty'],default='fixed')
    p.add_argument('--mutation',choices=['checksum','gap','owner'])
    a=p.parse_args()
    data={'fixed':compressed(b'ABRACADABRA '*8,zlib.Z_FIXED),'stored':compressed(b'synthetic stored',level=0),
          'dynamic':small_dynamic(),'empty':compressed(b'')}[a.kind]
    write(a.output,data,mutation=a.mutation)

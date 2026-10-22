#!/usr/bin/env python3
"""Synthetic SHA-256 compression benchmark inputs, independent of Noir."""
import argparse
import hashlib
from pathlib import Path

K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
IV=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
MASK=(1<<32)-1

def rotate(x,n): return (x>>n | x<<(32-n))&MASK

def compress(state,block):
    w=[int.from_bytes(block[i:i+4],'big') for i in range(0,64,4)]
    for i in range(16,64):
        x,y=w[i-15],w[i-2]
        w.append((w[i-16]+(rotate(x,7)^rotate(x,18)^(x>>3))+w[i-7]+(rotate(y,17)^rotate(y,19)^(y>>10)))&MASK)
    a,b,c,d,e,f,g,h=state
    for k,v in zip(K,w):
        t1=(h+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^((~e)&g))+k+v)&MASK
        t2=((rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c)))&MASK
        a,b,c,d,e,f,g,h=(t1+t2)&MASK,a,b,c,(d+t1)&MASK,e,f,g
    return [(x+y)&MASK for x,y in zip(state,[a,b,c,d,e,f,g,h])]

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('blocks',type=int,choices=[65,130,260])
    args=parser.parse_args()
    data=bytes((i*73+19)%256 for i in range(args.blocks*64))
    state=IV[:]
    for i in range(0,len(data),64): state=compress(state,data[i:i+64])
    padded=b'\x80'+bytes(55)+(len(data)*8).to_bytes(8,'big')
    digest=b''.join(x.to_bytes(4,'big') for x in compress(state,padded))
    assert digest==hashlib.sha256(data).digest()
    path=Path(__file__).resolve().parents[1]/'bench'/f'sha256_{args.blocks}'/'Prover.toml'
    path.write_text('bytes = '+str(list(data))+'\nmid_in = '+str(IV)+'\nmid_out = '+str(state)+'\n')

if __name__=='__main__': main()

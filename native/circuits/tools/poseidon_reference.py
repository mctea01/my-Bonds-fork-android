"""Standard-library BN254 Poseidon2 reference; constants licensed in NOTICE."""
import json
from pathlib import Path
P=21888242871839275222246405745257275088548364400416034343698204186575808495617
PARAMS=json.loads(Path(__file__).with_name('poseidon2_constants.json').read_text())
DIAG=[int(x,16) for x in PARAMS['diagonal']]
ROUNDS=[[int(x,16) for x in row] for row in PARAMS['rounds']]
M=((5,7,1,3),(4,6,1,1),(1,3,5,7),(1,1,4,6))
def external(s):return [sum(a*b for a,b in zip(row,s))%P for row in M]
def permutation(s):
    s=external(s)
    for i,rc in enumerate(ROUNDS):
        if i<4 or i>=60:s=external([pow((a+b)%P,5,P) for a,b in zip(s,rc)])
        else:
            s[0]=pow((s[0]+rc[0])%P,5,P);total=sum(s)
            s=[(a*b+total)%P for a,b in zip(s,DIAG)]
    return s
class Poseidon:
    def __init__(self):self.cache={}
    def hash(self,fields):
        key=tuple(map(int,fields))
        if key not in self.cache:
            assert all(0<=x<P for x in key)
            state=[0,0,0,len(key)<<64]
            for i in range(0,max(1,len(key)),3):
                for j,x in enumerate(key[i:i+3]):state[j]=(state[j]+x)%P
                state=permutation(state)
            self.cache[key]=state[0]
        return self.cache[key]
    def commit(self,tag,salt,fields):return self.hash([tag,salt,len(fields),*fields])
    def close(self):pass
    def self_test(self):
        assert self.commit(1,42,[0,1,2])==0x0e38abf00bd0aeb288ed74a01e99cec931b4904f6ba8aec4b9aa762107256dea
        assert self.commit(2,42,[])==0x2bea62b95fd366e7903877a49f491dcbb320cd4c7d1b26bb9ed8baa75a564cdf

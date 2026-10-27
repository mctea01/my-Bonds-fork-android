#!/usr/bin/env python3
"""Synthetic inflate/lex/claim witness chain. Run with python3 -I; no input logging."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sys
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parent))
from segment_reference import Poseidon,segments,verify_chain as verify_inflate,pack31,plain_commit,write,FIELD_KEYS,DOMAIN,ROOT
from fixtures import compressed
MOD=21888242871839275222246405745257275088548364400416034343698204186575808495617
PRED=int.from_bytes(b'pdf_pred_v1','big')
LEX=int.from_bytes(b'pdf_lex_seg_v1','big'); CLAIM=int.from_bytes(b'pdf_claim_v1','big')
FIELD_KEYS.update({'lin','lout','cg','pi','r','raw_fp','raw_power','strings_fp','strings_power'})
BASE=('pos','mode','depth','escaped','dict','array','closed','bt','font_len','name_len','word','word_len','long_word','pending','kind','raw_fp','raw_power','raw_len','ops','pi','r')

def fp(data,r):
    x=0
    for b in data:x=(x*r+b)%MOD
    return x

def record(font,kind,raw):
    strings=[raw] if isinstance(raw,bytes) else raw
    assert 1<=len(strings)<=255
    return bytes([len(font)])+font+bytes([kind,len(strings)])+b''.join(len(x).to_bytes(2,'big')+x for x in strings)

def initial(pi,r,A,C):
    s={k:0 for k in BASE};s.update(pi=pi,r=r,raw_power=1,strings_fp=0,strings_power=1,strings_len=0,strings=0,font=0,name=0,font_fp=0,font_power=1,name_fp=0,name_power=1,counts=[0]*A,ordinals=[0]*A,values=[0]*C,lengths=[0]*C,slot=0,field_fp=0,field_len=0)
    for k in ('escaped','array','closed','bt','long_word','pending'):s[k]=False
    return s

def state_commit(h,salt,s):
    fields=[s[k] for k in BASE]+[s[k] for k in ('font','name','font_fp','font_power','name_fp','name_power')]
    fields += [x for pair in zip(s['counts'],s['ordinals']) for x in pair]
    fields += [x for pair in zip(s['values'],s['lengths']) for x in pair]
    fields += [s['slot'],s['field_fp'],s['field_len'],s['strings_fp'],s['strings_power'],s['strings_len'],s['strings']]
    return h.commit(5,salt,fields)

def plan_commit(h,salt,p):
    fields=p['anchor_ops'][:]
    for n,b in zip(p['lengths'],p['records']):fields += [n,*pack31(bytes(b))]
    return h.commit(6,salt,fields)

def challenge(h,cz,pi,anchors,slots):
    data=b''
    for a in anchors:
        data+=bytes([a['enabled']])+a['len'].to_bytes(2,'big')+bytes(a['raw'])
    for s in slots:data+=bytes([s['enabled']])+s['before'].to_bytes(4,'big')+s['after'].to_bytes(4,'big')
    return h.hash([7,cz,pi,h.hash(pack31(data))])

def result_commit(h,salt,s):return h.commit(8,salt,[x for pair in zip(s['values'],s['lengths']) for x in pair])

class Scanner:
    """Deterministic streaming oracle, retaining records for an independent range check."""
    def __init__(self,pi,r,anchors,slots,plan,max_ops=512):
        self.s=initial(pi,r,len(anchors),len(slots)); self.anchors=anchors;self.slots=slots;self.plan=plan;self.records=[];self.raw=bytearray();self.strings=[];self.max_ops=max_ops
        self.s['slot']=next((i for i,x in enumerate(slots) if x['enabled']),len(slots))
        self.anchor_fp=[fp(bytes(a['raw'][:a['len']]),r) if a['enabled'] else 0 for a in anchors]
    def raw_byte(self,b):
        s=self.s;self.raw.append(b);s['raw_fp']=(s['raw_fp']*s['r']+b)%MOD;s['raw_power']=s['raw_power']*s['r']%MOD;s['raw_len']+=1;assert s['raw_len']<=65535
    def begin(self,kind):
        s=self.s;assert s['bt'] and not s['dict'] and not s['closed']
        if s['pending']:assert s['kind']==kind
        s['kind']=kind;s['pending']=True
    def word(self):
        s=self.s;w=0 if s['long_word'] else s['word'];show=w in (0x546a,0x544a,39,34)
        assert w!=0x4249
        if s['pending']:assert show
        if show:
            assert s['bt'] and s['font_len'] and s['pending'] and not s['array'] and not s['dict']
            assert (w==0x544a)==s['closed'];assert len(self.records)<self.max_ops
            data=record(s['font'].to_bytes(s['font_len'],'big'),s['kind'],self.strings);value=fp(data,s['r']);power=pow(s['r'],len(data),MOD)
            self.records.append(data)
            s.update(pending=False,closed=False,strings_fp=0,strings_power=1,strings_len=0,strings=0,kind=0);self.strings.clear()
        else:
            assert not s['array'] and not s['closed']
            if w==0x4254:assert not s['bt'] and not s['dict'];s.update(bt=True,font=0,font_len=0,font_fp=0,font_power=1)
            if w==0x4554:assert s['bt'] and not s['dict'];s['bt']=False
            if w==0x5466:assert s['bt'] and not s['dict'] and s['name_len'];s['font']=s['name'];s['font_len']=s['name_len'];s['font_fp']=s['name_fp'];s['font_power']=s['name_power']
        s.update(word=0,word_len=0,long_word=False,mode=0)
    def end_string(self):
        s=self.s;data=len(self.raw).to_bytes(2,'big')+bytes(self.raw)
        self.strings.append(bytes(self.raw));self.raw.clear()
        s['strings_fp']=(s['strings_fp']*pow(s['r'],len(data),MOD)+fp(data,s['r']))%MOD
        s['strings_power']=s['strings_power']*pow(s['r'],len(data),MOD)%MOD
        s['strings_len']+=len(data);s['strings']+=1;assert s['strings']<=255
        s.update(raw_fp=0,raw_power=1,raw_len=0)
    def aggregate(self,records):
        s=self.s
        for data in records:
            value=fp(data,s['r']);power=pow(s['r'],len(data),MOD)
            for a,x in enumerate(self.anchors):
                if x['enabled']:
                    equal=value==self.anchor_fp[a] and len(data)==x['len']
                    s['counts'][a]+=equal
                    if s['ops']==self.plan['anchor_ops'][a]:assert equal;s['ordinals'][a]=s['counts'][a]
            c=s['slot']
            if c<len(self.slots):
                x=self.slots[c];begin,end=self.plan['anchor_ops'][x['before']],self.plan['anchor_ops'][x['after']]
                if begin<s['ops']<end:s['field_fp']=(s['field_fp']*power+value)%MOD;s['field_len']+=len(data)
                if s['ops']==end:
                    s['values'][c]=s['field_fp'];s['lengths'][c]=s['field_len'];s['field_fp']=0;s['field_len']=0
                    s['slot']=next((i for i in range(c+1,len(self.slots)) if self.slots[i]['enabled']),len(self.slots))
            s['ops']+=1
    def step(self,b):
        s=self.s;white=b in (0,9,10,12,13,32);end=white or b in b'%()<>[]/'
        if s['mode'] in (4,5,6) and end:
            if s['mode']==6:self.word()
            else:s['mode']=0
        m=s['mode']
        if m==1:
            if b in (10,13):s['mode']=0
        elif m==2:
            if s['escaped']:self.raw_byte(b);s['escaped']=False
            elif b==92:self.raw_byte(b);s['escaped']=True
            elif b==40:s['depth']+=1;self.raw_byte(b)
            elif b==41:
                s['depth']-=1
                if not s['depth']:s['mode']=0;self.end_string()
                else:self.raw_byte(b)
            else:self.raw_byte(b)
        elif m==3:
            if b==62:s['mode']=0;self.end_string()
            else:assert white or chr(b) in '0123456789abcdefABCDEF';self.raw_byte(b)
        elif m==7:
            if b==60:assert not s['pending'] and not s['array'];s['dict']+=1;s['mode']=0
            else:
                self.begin(1);s['mode']=3
                if b==62:s['mode']=0;self.end_string()
                else:assert white or chr(b) in '0123456789abcdefABCDEF';self.raw_byte(b)
        elif m==8:assert b==62 and s['dict'];s['dict']-=1;s['mode']=0
        elif m==4:assert s['name_len']<16;s['name']=s['name']*256+b;s['name_fp']=(s['name_fp']*s['r']+b)%MOD;s['name_power']=s['name_power']*s['r']%MOD;s['name_len']+=1
        elif m==5:assert b in b'+-.0123456789'
        elif m==6:
            if s['word_len']<3:s['word']=s['word']*256+b;s['word_len']+=1
            else:s['long_word']=True
        else:
            assert m==0
            if white:pass
            elif b==37:s['mode']=1
            elif b==40:self.begin(0);s.update(mode=2,depth=1)
            elif b==60:s['mode']=7
            elif b==62:s['mode']=8
            elif b==91:assert not s['array'] and not s['closed'] and not s['pending'] and not s['dict'];s['array']=True
            elif b==93:assert s['array'] and not s['dict'];s.update(array=False,closed=True)
            elif b==47:assert not s['pending'] and not s['closed'];s.update(mode=4,name=0,name_len=0,name_fp=0,name_power=1)
            elif b==41:raise ValueError('Unmatched delimiter')
            elif b in b'+-.0123456789':s['mode']=5
            else:s.update(mode=6,word=b,word_len=1,long_word=False)
    def eof(self):
        if self.s['mode'] in (1,4,5,6):self.step(10)
        s=self.s;assert s['mode']==0 and not any(s[k] for k in ('pending','bt','array','closed','dict'))

# Obvious synthetic names/identifiers only. Each BT has one Tf and one show.
def text(raw,font=b'FakeFont',kind=0,tj=False):
    payload=(b'('+raw+b')') if kind==0 else b'<'+raw+b'>'
    if tj:payload=b'['+payload+b' -20 '+(b'(\\050FAKE\\051)' if kind==0 else b'<0020>')+b']'
    return b'BT /'+font+b' 12 Tf '+payload+(b' TJ' if tj else b' Tj')+b' ET\n'

def synthetic(style='word'):
    if style=='word':
        content=text(b'FAKE START')+text(b'2020\\05501\\05502')+text(b'FAKE END')+text(b'FAKE NAME \\(NOT REAL\\)',tj=True)+text(b'00460041004B0045',b'FakeCID',1)+text(b'FAKE START')
        return content,[0,2],[(0,1)]
    content=b''
    for row in range(3):
        content+=text(b'FAKE ROW')+text(b'0032003000320030002D00300031002D00300032',b'FakeCID',1)+text(b'FAKE END')
    return content,[0,2,3,5,6,8],[(0,1),(2,3),(4,5)]

def empty_anchor(R):return dict(enabled=False,len=0,raw=[0]*R,ordinal=0,total=0)
def decode_record(data):
    n=data[0];assert 1<=n<=16
    font=data[1:1+n];kind=data[1+n];count=data[2+n];assert count>0 and kind<=1
    cursor=n+3;strings=[]
    for _ in range(count):
        assert cursor+2<=len(data)
        length=int.from_bytes(data[cursor:cursor+2],'big');cursor+=2
        assert cursor+length<=len(data)
        strings.append(data[cursor:cursor+length]);cursor+=length
    assert cursor==len(data)
    return font,kind,strings

def operator_capacity(P,K):return 64*((P*K+2047)//2048)

def build(content,h,P=2048,K=1,A=16,C=12,Q=384,R=96,anchor_ops=None,ranges=None,T=352,T0=1024,N=8192,claim_slots=None):
    anchor_ops=[] if anchor_ops is None else anchor_ops;ranges=[] if ranges is None else ranges
    # First pass collects exact record bytes, independently of their fingerprints.
    scan=Scanner(0,3,[],[],dict(anchor_ops=[]));
    for b in content:scan.step(b)
    scan.eof();records=scan.records
    anchors=[empty_anchor(R) for _ in range(A)]
    for a,i in enumerate(anchor_ops):
        raw=records[i];assert len(raw)<=R
        anchors[a]=dict(enabled=True,len=len(raw),raw=list(raw)+[0]*(R-len(raw)),ordinal=sum(x==records[i] for x in records[:i+1]),total=records.count(records[i]))
    slots=[dict(enabled=False,before=0,after=0) for _ in range(C)]
    plan=dict(anchor_ops=anchor_ops+[0]*(A-len(anchor_ops)),lengths=[0]*C,records=[[0]*Q for _ in range(C)])
    for c,(before,after) in enumerate(ranges):
        data=b''.join(records[anchor_ops[before]+1:anchor_ops[after]]);assert len(data)<=Q
        slots[c]=dict(enabled=True,before=before,after=after);plan['lengths'][c]=len(data);plan['records'][c]=list(data)+[0]*(Q-len(data))
    chain=segments(compressed(content,zlib.Z_FIXED),h,P,T,1,N,token0_capacity=T0)
    cz=chain[0]['cz'];salt=42;pi=plan_commit(h,salt,plan);r=challenge(h,cz,pi,anchors,slots)
    scan=Scanner(pi,r,anchors,slots,plan);lex=[]
    for j,start in enumerate(range(0,len(chain),K)):
        group=chain[start:start+K];incoming=deepcopy(scan.s)
        positions=[];record_start=len(scan.records)
        for k,segment in enumerate(group):
            for i,byte in enumerate(segment['plain'][:segment['plain_len']]):
                before=len(scan.records);scan.step(byte);scan.s['pos']+=1
                if len(scan.records)>before:positions.append(k*P+i)
        last=start+K>=len(chain)
        if last:scan.eof()
        assert len(scan.records)-record_start==len(positions)
        scan.aggregate(scan.records[record_start:]);assert len(positions)<=operator_capacity(P,K)
        assert scan.s['lengths']==[min(x,y) for x,y in zip(scan.s['lengths'],plan['lengths'])]
        lex.append(dict(domain=DOMAIN,circuit=LEX,index=j,first=j==0,last=last,cz=cz,lin=0 if j==0 else lex[-1]['lout'],lout=state_commit(h,salt,scan.s),cp=[x['cp'] for x in group]+[0]*(K-len(group)),anchors=deepcopy(anchors),slots=deepcopy(slots),cg=result_commit(h,salt,scan.s) if last else 0,salt=salt,plain=[x['plain'] for x in group]+[[0]*P for _ in range(K-len(group))],lengths=[x['plain_len'] for x in group]+[0]*(K-len(group)),incoming=incoming,plan=deepcopy(plan),used=len(positions),positions=positions+[0]*(operator_capacity(P,K)-len(positions))))
    fonts=[]
    for name,width in [(b'FakeFont',1),(b'FakeCID',2)]:fonts.append(dict(enabled=True,len=len(name),name=list(name)+[0]*(16-len(name)),width=width,digits=list(range(48,58))))
    fonts += [dict(enabled=False,len=0,name=[0]*16,width=0,digits=[0]*10) for _ in range(2)]
    predicates=[dict(enabled=bool(ranges),kind=0,slot=0,format=0,cutoff=20210101),dict(enabled=False,kind=0,slot=0,format=0,cutoff=0)]
    salts=[[c+1]*16 for c in range(C)]
    digests=[list(hashlib.sha256(b'diw-zkpdf-claim-v1'+bytes([c])+bytes(salts[c])+plan['lengths'][c].to_bytes(2,'big')+bytes(plan['records'][c])).digest()) if slots[c]['enabled'] else [0]*32 for c in range(C)]
    claim=dict(domain=DOMAIN,circuit=CLAIM,beta=[7]*32,start=0,count=C,cz=cz,anchors=anchors,slots=slots,cg=lex[-1]['cg'],digests=digests,salt=salt,plan=plan,claim_salts=salts)
    pred=dict(domain=DOMAIN,circuit=PRED,beta=[7]*32,cz=cz,anchors=anchors,slots=slots,cg=lex[-1]['cg'],fonts=fonts,predicates=predicates,salt=salt,plan=plan)
    result=dict(inflate=chain,lex=lex,claim=claim,pred=pred,claims=split_claims(claim,C if claim_slots is None else claim_slots));verify_chain(result,h,P,K);return result

def split_claims(claim,count):
    capacity=len(claim['slots']);assert 1<=count<=capacity
    result=[]
    for start in range(0,capacity,count):
        x=deepcopy(claim);size=min(count,capacity-start)
        x.update(start=start,count=size,digests=claim['digests'][start:start+size],claim_salts=claim['claim_salts'][start:start+size])
        result.append(x)
    return result

def decode_literal(raw):
    out=bytearray();i=0
    escapes={110:10,114:13,116:9,98:8,102:12}
    while i<len(raw):
        b=raw[i];i+=1
        if b!=92:
            out.append(10 if b==13 else b)
            if b==13 and i<len(raw) and raw[i]==10:i+=1
            continue
        if i==len(raw):raise ValueError('Incomplete literal escape')
        b=raw[i];i+=1
        if 48<=b<=55:
            digits=bytes([b])
            while i<len(raw) and len(digits)<3 and 48<=raw[i]<=55:digits+=raw[i:i+1];i+=1
            out.append(int(digits,8)%256)
        elif b==13:
            if i<len(raw) and raw[i]==10:i+=1
        elif b!=10:out.append(escapes.get(b,b))
    return bytes(out)

def decode_string(raw,kind):
    if kind==0:return decode_literal(raw)
    assert kind==1
    digits=bytes(b for b in raw if b not in (0,9,10,12,13,32))
    if len(digits)%2:digits+=b'0'
    return bytes.fromhex(digits.decode('ascii'))

def reference_date(data,fonts):
    import datetime
    cursor=0;chars=''
    while cursor<len(data):
        n=data[cursor];assert 1<=n<=16;name=data[cursor+1:cursor+1+n];kind=data[cursor+1+n]
        count=data[cursor+n+2];assert count>0;cursor+=n+3
        matches=[f for f in fonts if f['enabled'] and bytes(f['name'][:f['len']])==name];assert len(matches)==1
        font=matches[0];width=font['width']
        for _ in range(count):
            assert cursor+2<=len(data)
            length=int.from_bytes(data[cursor:cursor+2],'big');cursor+=2
            raw=data[cursor:cursor+length];assert len(raw)==length;cursor+=length
            decoded=decode_string(raw,kind)
            assert len(decoded)%width==0
            for i in range(0,len(decoded),width):
                code=int.from_bytes(decoded[i:i+width],'big')
                chars+=str(font['digits'].index(code)) if code in font['digits'] else ' '
    pieces=chars.split();assert len(pieces)==3 and len(pieces[0])==4 and 1<=len(pieces[1])<=2 and 1<=len(pieces[2])<=2
    year,month,day=map(int,pieces);datetime.date(year,month,day)
    return year*10000+month*100+day

def verify_chain(bundle,h,P,K):
    inf,lex,claim=bundle['inflate'],bundle['lex'],bundle['claim'];verify_inflate(inf,h,P)
    content=b''.join(bytes(s['plain'][:s['plain_len']]) for s in inf)
    a,c,p=claim['anchors'],claim['slots'],claim['plan'];pi=plan_commit(h,claim['salt'],p);r=challenge(h,claim['cz'],pi,a,c)
    scan=Scanner(pi,r,a,c,p)
    offset=0
    for j,x in enumerate(lex):
        assert x['index']==j and x['first']==(j==0) and x['last']==(j==len(lex)-1)
        assert x['cz']==inf[0]['cz']==claim['cz'] and x['anchors']==a and x['slots']==c and x['plan']==p
        assert x['lin']==(0 if j==0 else lex[j-1]['lout'])
        if j:assert state_commit(h,x['salt'],x['incoming'])==x['lin']
        positions=[];record_start=len(scan.records)
        for k,cp in enumerate(x['cp']):
            i=j*K+k;assert cp==(inf[i]['cp'] if i<len(inf) else 0)
            if i<len(inf):assert cp==plain_commit(h,x['salt'],i,bytes(x['plain'][k][:x['lengths'][k]]),P)
            else:assert x['lengths'][k]==0 and not any(x['plain'][k])
            for i,byte in enumerate(x['plain'][k][:x['lengths'][k]]):
                before=len(scan.records);scan.step(byte);scan.s['pos']+=1;offset+=1
                if len(scan.records)>before:positions.append(k*P+i)
        if x['last']:scan.eof()
        assert x['used']==len(positions) and x['positions']==positions+[0]*(operator_capacity(P,K)-len(positions))
        scan.aggregate(scan.records[record_start:])
        assert state_commit(h,x['salt'],scan.s)==x['lout']
    assert offset==len(content) and len(lex)==(len(inf)+K-1)//K
    assert result_commit(h,claim['salt'],scan.s)==claim['cg']==lex[-1]['cg']
    assert scan.s['counts']==[x['total'] for x in a] and scan.s['ordinals']==[x['ordinal'] for x in a]
    previous_end=None
    for slot in c:
        if slot['enabled']:
            begin,end=p['anchor_ops'][slot['before']],p['anchor_ops'][slot['after']]
            assert begin<end and (previous_end is None or begin>=previous_end)
            previous_end=end
    for i,slot in enumerate(c):
        exact=b''.join(scan.records[p['anchor_ops'][slot['before']]+1:p['anchor_ops'][slot['after']]]) if slot['enabled'] else b''
        assert exact==bytes(p['records'][i][:p['lengths'][i]])
        if slot['enabled']:
            expected=hashlib.sha256(b'diw-zkpdf-claim-v1'+bytes([i])+bytes(claim['claim_salts'][i])+len(exact).to_bytes(2,'big')+bytes(p['records'][i])).digest()
            assert expected==bytes(claim['digests'][i])
    coverage=0
    for part in bundle['claims']:
        for key in ('cz','anchors','slots','cg','beta','plan','salt'):assert part[key]==claim[key]
        start,count=part['start'],part['count']
        assert start==coverage and 0<count<=len(c)-start
        assert part['digests']==claim['digests'][start:start+count]
        assert part['claim_salts']==claim['claim_salts'][start:start+count]
        coverage+=count
    assert coverage==len(c)
    statement=bundle['pred']
    for key in ('cz','anchors','slots','cg','beta','plan','salt'):assert statement[key]==claim[key]
    for pred in statement['predicates']:
        if pred['enabled']:
            assert pred['format']==0 and c[pred['slot']]['enabled']
            slot=pred['slot'];value=reference_date(bytes(p['records'][slot][:p['lengths'][slot]]),statement['fonts'])
            assert value<=pred['cutoff'] if pred['kind']==0 else value>=pred['cutoff']
    return True

def package(path,kind,P=64,K=1,A=4,C=2,Q=96,R=32,start=0,count=None):
    path=Path(path);(path/'src').mkdir(parents=True,exist_ok=True)
    name={'lex':'pdf_lex_seg_v1','claim':'pdf_claim_v1','pred':'pdf_pred_v1'}[kind];source=(ROOT/name/'src/main.nr').read_text()
    for key,value in dict(SEG_PLAIN=P,K=K,SEG_OPS=operator_capacity(P,K),MAX_ANCHORS=A,MAX_CLAIMS=C,MAX_CLAIM_SRC=Q,MAX_ANCHOR_SRC=R,SLOT_START=start,SLOT_COUNT=C if count is None else count).items():
        source=re.sub(r'(global '+key+r':u32=)\d+',lambda m:m[1]+str(value),source)
    (path/'src/main.nr').write_text(source);(path/'Nargo.toml').write_text('[package]\nname="text_regression"\ntype="bin"\nauthors=[]\n[dependencies]\npdf_text_v1={path='+json.dumps(str(ROOT/'pdf_text_v1'))+'}\n');return path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--bb-js',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--plain',type=int,default=2048);parser.add_argument('--k',type=int,default=1);parser.add_argument('--claim-slots',type=int,default=12);parser.add_argument('--style',choices=['word','table'],default='word')
    parser.add_argument('--tokens',type=int,help='General inflate capacity; defaults to 352 (2048 bytes) or 576 (4096 bytes)')
    parser.add_argument('--tokens0',type=int,help='First inflate capacity; defaults to 1024 (2048 bytes) or 1536 (4096 bytes)')
    args=parser.parse_args();h=Poseidon(args.bb_js)
    try:
        tokens=args.tokens if args.tokens is not None else (576 if args.plain==4096 else 352)
        tokens0=args.tokens0 if args.tokens0 is not None else (1536 if args.plain==4096 else 1024)
        content,anchors,ranges=synthetic(args.style);bundle=build(content,h,args.plain,args.k,anchor_ops=anchors,ranges=ranges,claim_slots=args.claim_slots,T=tokens,T0=tokens0)
        for name in ('inflate','lex'):
            for i,x in enumerate(bundle[name]):write(args.output/f'{name}-{i:03}'/'Prover.toml',x)
        for i,part in enumerate(bundle['claims']):write(args.output/f'claim-{i:03}'/'Prover.toml',part)
        write(args.output/'pred-000'/'Prover.toml',bundle['pred'])
        print('Synthetic inflate/lex/claim/pred chain verified; witnesses written')
    finally:h.close()
if __name__=='__main__':main()

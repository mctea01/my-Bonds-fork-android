#!/usr/bin/env python3
"""Reference witness producer for the five committed, fictional M3d PDFs only.

Run with python3 -I. Uses only Python's standard library and the pinned nargo
executable. Private witness data and subprocess diagnostics are never printed.
This deliberately bounded PDF reader is not a general-purpose production parser.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parent))
from poseidon_reference import Poseidon
from sha_fixture import IV,compress
from segment_reference import ROOT,DOMAIN,pack31,byte_commit,write,segments
from lex_reference import Scanner,decode_record,decode_string,build,package,verify_chain
from segment_regressions import package as inflate_package

FIXTURES=ROOT.parents[1]/'test-servers/src/test/resources/zkpdf'
PAD=bytes.fromhex('28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a')
WS=b'\x00\t\n\x0c\r '
DELIM=WS+b'()<>[]{}/%'

class Unsupported(ValueError):pass

class Reader:
    def __init__(self,data,pos=0):self.data=data;self.pos=pos
    def space(self):
        while self.pos<len(self.data):
            if self.data[self.pos] in WS:self.pos+=1
            elif self.data[self.pos]==37:
                while self.pos<len(self.data) and self.data[self.pos] not in b'\r\n':self.pos+=1
            else:break
    def token(self):
        self.space();start=self.pos
        while self.pos<len(self.data) and self.data[self.pos] not in DELIM:self.pos+=1
        if self.pos==start:raise Unsupported('Unexpected PDF token')
        return self.data[start:self.pos]
    def value(self):
        self.space();d=self.data;p=self.pos
        if d[p:p+2]==b'<<':
            self.pos+=2;result={}
            while True:
                self.space()
                if d[self.pos:self.pos+2]==b'>>':self.pos+=2;return result
                key=self.value()
                if not isinstance(key,str) or not key.startswith('/'):raise Unsupported('Invalid dictionary key')
                if key in result:raise Unsupported('Duplicate dictionary key')
                result[key]=self.value()
        if d[p:p+1]==b'[':
            self.pos+=1;result=[]
            while True:
                self.space()
                if d[self.pos:self.pos+1]==b']':self.pos+=1;return result
                result.append(self.value())
        if d[p:p+1]==b'/':
            self.pos+=1;start=self.pos
            while self.pos<len(d) and d[self.pos] not in DELIM:self.pos+=1
            return '/'+re.sub(rb'#([0-9A-Fa-f]{2})',lambda m:bytes([int(m[1],16)]),d[start:self.pos]).decode('latin1')
        if d[p:p+1]==b'<':
            end=d.index(b'>',p);self.pos=end+1;raw=re.sub(rb'\s',b'',d[p+1:end]);return bytes.fromhex((raw+b'0'*(len(raw)%2)).decode())
        if d[p:p+1]==b'(':
            from lex_reference import decode_literal
            self.pos+=1;start=self.pos;depth=1
            while depth:
                b=d[self.pos];self.pos+=1
                if b==92:self.pos+=1
                elif b==40:depth+=1
                elif b==41:depth-=1
            return decode_literal(d[start:self.pos-1])
        word=self.token()
        if re.fullmatch(rb'[+-]?\d+',word):
            n=int(word);saved=self.pos
            try:
                second=self.token();third=self.token()
                if re.fullmatch(rb'\d+',second) and third==b'R':return (n,int(second))
            except (ValueError,IndexError):pass
            self.pos=saved;return n
        if word==b'true':return True
        if word==b'false':return False
        if word==b'null':return None
        if re.fullmatch(rb'[+-]?\d*\.\d+',word):return float(word)
        raise Unsupported('Unsupported PDF value')

def rc4(key,data):
    s=list(range(256));j=0
    for i in range(256):j=(j+s[i]+key[i%len(key)])%256;s[i],s[j]=s[j],s[i]
    out=bytearray();i=j=0
    for b in data:
        i=(i+1)%256;j=(j+s[i])%256;s[i],s[j]=s[j],s[i];out.append(b^s[(s[i]+s[j])%256])
    return bytes(out)

class Pdf:
    def __init__(self,data):
        self.data=data;self.xref={};self.cache={};self.key=None;self.trailer={}
        starts=list(re.finditer(rb'startxref\s+(\d+)\s+%%EOF',data))
        if not starts:raise Unsupported('Missing signed-revision xref')
        offset=int(starts[-1][1]);seen=set()
        while offset is not None:
            if offset in seen:raise Unsupported('Cyclic xref chain')
            seen.add(offset);entries,trailer=self.read_xref(offset)
            for n,e in entries.items():self.xref.setdefault(n,e)
            for k,v in trailer.items():self.trailer.setdefault(k,v)
            offset=trailer.get('/Prev')
        if '/Encrypt' in self.trailer:
            enc=self.get(self.trailer['/Encrypt'])
            if (enc.get('/Filter'),enc.get('/V'),enc.get('/R'),enc.get('/Length'))!=('/Standard',2,3,128):raise Unsupported('Only Standard V2 R3 RC4 is supported')
            digest=hashlib.md5(PAD+enc['/O']+(enc['/P']&0xffffffff).to_bytes(4,'little')+self.trailer['/ID'][0]).digest()
            for _ in range(50):digest=hashlib.md5(digest[:16]).digest()
            self.key=digest[:16]
            u=rc4(self.key,hashlib.md5(PAD+self.trailer['/ID'][0]).digest())
            for i in range(1,20):u=rc4(bytes(x^i for x in self.key),u)
            if u!=enc['/U'][:16]:raise Unsupported('Empty user password verification failed')
    def indirect(self,offset,expected=None):
        r=Reader(self.data,offset);n=int(r.token());g=int(r.token());assert r.token()==b'obj'
        if expected is not None:assert (n,g)==expected
        value=r.value();r.space()
        if self.data[r.pos:r.pos+6]==b'stream':
            r.pos+=6
            if self.data[r.pos:r.pos+2]==b'\r\n':r.pos+=2
            elif self.data[r.pos:r.pos+1] in (b'\r',b'\n'):r.pos+=1
            else:raise Unsupported('Missing stream EOL')
            length=value['/Length'];length=self.get(length) if isinstance(length,tuple) else length
            assert isinstance(length,int) and length>=0
            start=r.pos;end=start+length
            assert self.data[end:].lstrip(WS).startswith(b'endstream')
            return dict(meta=value,start=start,end=end,ref=(n,g))
        return value
    def read_xref(self,offset):
        r=Reader(self.data,offset);entries={}
        if self.data[offset:offset+4]==b'xref':
            r.token()
            while True:
                r.space()
                if self.data[r.pos:r.pos+7]==b'trailer':r.token();return entries,r.value()
                start=int(r.token());count=int(r.token())
                for n in range(start,start+count):
                    off=int(r.token());gen=int(r.token());flag=r.token();entries[n]=(1,off,gen) if flag==b'n' else (0,off,gen)
        stream=self.indirect(offset);meta=stream['meta'];assert meta['/Type']=='/XRef'
        raw=self.data[stream['start']:stream['end']]
        if meta.get('/Filter')=='/FlateDecode':raw=zlib.decompress(raw)
        elif meta.get('/Filter') is not None:raise Unsupported('Unsupported xref filter')
        if meta.get('/DecodeParms') is not None:raise Unsupported('Xref predictors outside fixture profile')
        widths=meta['/W'];indices=meta.get('/Index',[0,meta['/Size']]);p=0
        for start,count in zip(indices[::2],indices[1::2]):
            for n in range(start,start+count):
                row=[]
                for i,w in enumerate(widths):row.append(int.from_bytes(raw[p:p+w],'big') if w else (1 if i==0 else 0));p+=w
                entries[n]=tuple(row)
        assert p==len(raw);return entries,meta
    def get(self,ref):
        if not isinstance(ref,tuple):return ref
        if ref in self.cache:return self.cache[ref]
        kind,a,b=self.xref[ref[0]]
        if kind==1:
            assert ref[1]==b;value=self.indirect(a,ref)
        elif kind==2:
            assert ref[1]==0
            stream=self.get((a,0));assert stream['meta']['/Type']=='/ObjStm'
            data=self.decoded(stream);r=Reader(data);pairs=[(int(r.token()),int(r.token())) for _ in range(stream['meta']['/N'])]
            assert pairs[b][0]==ref[0];value=Reader(data,stream['meta']['/First']+pairs[b][1]).value()
        else:raise Unsupported('Reference to free object')
        self.cache[ref]=value;return value
    def keystream(self,ref,length):
        if self.key is None:return bytes(length)
        n,g=ref;key=hashlib.md5(self.key+n.to_bytes(3,'little')+g.to_bytes(2,'little')).digest()[:min(len(self.key)+5,16)]
        return rc4(key,bytes(length))
    def decoded(self,stream):
        raw=self.data[stream['start']:stream['end']];key=self.keystream(stream['ref'],len(raw));raw=bytes(x^y for x,y in zip(raw,key))
        filt=stream['meta'].get('/Filter')
        if filt=='/FlateDecode':return zlib.decompress(raw)
        if filt is None:return raw
        raise Unsupported('Unsupported stream filter')
    def page(self):
        catalog=self.get(self.trailer['/Root']);assert catalog['/Type']=='/Catalog'
        node=self.get(catalog['/Pages']);resources=None;seen=set()
        while node['/Type']=='/Pages':
            resources=node.get('/Resources',resources);ref=node['/Kids'][0]
            if ref in seen:raise Unsupported('Cyclic page tree')
            seen.add(ref);node=self.get(ref)
        assert node['/Type']=='/Page'
        resources=self.get(node.get('/Resources',resources));content=self.get(node['/Contents'])
        assert content['meta']['/Filter']=='/FlateDecode'
        opaque=[]
        for name,ref in self.get(resources.get('/XObject',{})).items():
            image=self.get(ref)
            if name=='/Qr':assert image['meta']['/Subtype']=='/Image';opaque.append(image)
        assert len(opaque)<=1
        return content,opaque,resources
    def fonts(self,resources):
        result={}
        for name,ref in self.get(resources['/Font']).items():
            font=self.get(ref)
            if font.get('/Encoding')=='/WinAnsiEncoding':result[name[1:].encode()]=(1,{i:bytes([i]).decode('cp1252',errors='replace') for i in range(256)})
            elif font.get('/Encoding')=='/Identity-H':
                cmap=self.decoded(self.get(font['/ToUnicode']));mapping={}
                for body in re.findall(rb'beginbfchar(.*?)endbfchar',cmap,re.S):
                    for a,b in re.findall(rb'<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>',body):mapping[int(a,16)]=bytes.fromhex(b.decode()).decode('utf-16-be')
                if not mapping:raise Unsupported('Missing fixture CMap')
                result[name[1:].encode()]=(2,mapping)
            else:raise Unsupported('Unsupported font encoding')
        return result

def der(data,pos=0):
    start=pos;tag=data[pos];pos+=1;length=data[pos];pos+=1
    if length&128:
        n=length&127;assert n>0;length=int.from_bytes(data[pos:pos+n],'big');pos+=n
    end=pos+length;assert end<=len(data)
    children=[]
    if tag&32:
        cursor=pos
        while cursor<end:
            child,cursor=der(data,cursor);children.append(child)
        assert cursor==end
    return dict(tag=tag,value=data[pos:end],children=children,encoded=data[start:end]),end

def message_digest(cms):
    root,_=der(cms);found=[]
    def walk(node):
        c=node['children']
        if node['tag']==0x30 and len(c)==2 and c[0]['tag']==6 and c[0]['value']==bytes.fromhex('2a864886f70d010904'):
            assert c[1]['tag']==0x31 and len(c[1]['children'])==1
            value=c[1]['children'][0];assert value['tag']==4 and len(value['value'])==32;found.append(value['value'])
        for child in c:walk(child)
    walk(root);assert len(found)==1;return found[0]

def signed_pdf(path):
    data=path.read_bytes();matches=list(re.finditer(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]',data));assert len(matches)==1
    a,b,c,d=map(int,matches[0].groups());assert a==0 and 0<b<c<c+d<=len(data)
    revision=data[:c+d];cms=Reader(data,b).value();assert isinstance(cms,bytes)
    message=data[:b]+data[c:c+d];digest=message_digest(cms);assert hashlib.sha256(message).digest()==digest
    return Pdf(revision),message,digest,(b,c,d)

def window(pdf,stream,message,br,kind,h):
    b,c,d=br;start,end=stream['start'],stream['end']
    assert 0<=start<end<=len(pdf.data)
    if end<=b:offset=start
    elif start>=c and end<=c+d:offset=start-(c-b)
    else:raise Unsupported('Stream crosses unsigned signature gap')
    left=offset//64*64;right=(offset+end-start+63)//64*64
    if right>len(message)//64*64:raise Unsupported('Private window intersects SHA padding')
    blocks=(right-left)//64;limit=130 if kind=='content' else 128
    if blocks>limit:raise Unsupported('SHA block capacity exceeded')
    state=IV[:]
    for i in range(0,left,64):state=compress(state,message[i:i+64])
    finish=state[:]
    for i in range(left,right,64):finish=compress(finish,message[i:i+64])
    head=message[left:offset];tail=message[offset+end-start:right]
    w=dict(domain=DOMAIN,circuit=int.from_bytes(('pdf_sha_'+kind+'_v1').encode(),'big'),mid_in=state,mid_out=finish,blocks=blocks,head_len=len(head),head=[hex(x) for x in pack31(head+bytes(63-len(head)))],tail_len=len(tail),tail=[hex(x) for x in pack31(tail+bytes(63-len(tail)))],bytes=list(message[left:right])+[0]*((limit-blocks)*64))
    if kind=='content':
        n=end-start
        if not 0<n<=8192:raise Unsupported('Compressed stream exceeds MAX_COMPRESSED=8192')
        key=pdf.keystream(stream['ref'],n);z=bytes(x^y for x,y in zip(pdf.data[start:end],key))
        w.update(encrypted=pdf.key is not None,keystream=[hex(x) for x in pack31(key+bytes(8192-n))],cz=byte_commit(h,42,z,8192),salt=42)
    return dict(left=left,right=right,offset=offset,length=end-start,kind=kind,witness=w)

def unpack_public(packed,size):
    result=bytearray()
    for i,x in enumerate(packed):
        width=min(31,size-i*31);value=int(x,16) if isinstance(x,str) else x
        assert 0<=value<1<<(width*8);result.extend(value.to_bytes(width,'big'))
    assert len(result)==size;return bytes(result)

def check_sha_chain(message,digest,windows):
    state=IV[:];cursor=0
    for entry in sorted(windows,key=lambda x:x['left']):
        assert cursor<=entry['left'] and entry['left']%64==entry['right']%64==0
        for i in range(cursor,entry['left'],64):state=compress(state,message[i:i+64])
        w=entry['witness'];assert state==w['mid_in']
        assert w['blocks']*64==entry['right']-entry['left']
        assert w['head_len']==entry['offset']-entry['left'] and w['tail_len']==entry['right']-entry['offset']-entry['length']
        assert unpack_public(w['head'],63)[:w['head_len']]==message[entry['left']:entry['offset']]
        assert unpack_public(w['tail'],63)[:w['tail_len']]==message[entry['offset']+entry['length']:entry['right']]
        state=w['mid_out'];cursor=entry['right']
    padded=message+b'\x80'+bytes((55-len(message))%64)+(len(message)*8).to_bytes(8,'big')
    for i in range(cursor,len(padded),64):state=compress(state,padded[i:i+64])
    assert b''.join(x.to_bytes(4,'big') for x in state)==digest

def check_public_chain(bundle,windows,expected_anchors,expected_slots,expected_fonts):
    """Verifier joins use public inputs only, without opening Pi, S or Lambda."""
    from formal_profiles import BASE
    inf,lex=bundle['inflate'],bundle['lex'];claim,pred=bundle['claim'],bundle['pred']
    assert 1<=len(inf)<=20 and len(lex)==len(inf) and len(bundle['claims'])==1
    content=[x for x in windows if x['kind']=='content'];opaque=[x for x in windows if x['kind']=='opaque']
    assert len(content)==1 and len(opaque)<=1 and len(windows)==len(content)+len(opaque)
    cz=content[0]['witness']['cz']
    def identity(w,kind):
        assert w['domain']==DOMAIN and w['circuit']==int.from_bytes(BASE[kind].encode(),'big')
    for x in windows:identity(x['witness'],'sha_'+x['kind'])
    for i,w in enumerate(inf):
        identity(w,'inflate0' if i==0 else 'inflate')
        assert w['index']==i and w['first']==(i==0) and w['last']==(i==len(inf)-1)
        assert w['cz']==cz and w['sin']==(inf[i-1]['sout'] if i else 0)
        if i:assert w['previous']==[inf[j]['cp'] if j>=0 else 0 for j in range(i-16,i)]
    def anchor_inputs(anchors):return [{k:v for k,v in a.items() if k not in ('ordinal','total')} for a in anchors]
    for j,w in enumerate(lex):
        identity(w,'lex')
        assert w['index']==j and w['first']==(j==0) and w['last']==(j==len(lex)-1)
        assert w['cz']==cz and w['lin']==(lex[j-1]['lout'] if j else 0) and w['cp']==[inf[j]['cp']]
        assert w['slots']==expected_slots and anchor_inputs(w['anchors'])==anchor_inputs(expected_anchors)
        if w['last']:assert w['anchors']==expected_anchors
        else:assert w['cg']==0 and all(a['ordinal']==a['total']==0 for a in w['anchors'])
    assert claim['start']==0 and claim['count']==12
    for kind,w in [('claim',claim),('pred',pred)]:
        identity(w,kind)
        assert w['cz']==cz and w['cg']==lex[-1]['cg'] and w['beta']==[7]*32
        assert w['anchors']==expected_anchors and w['slots']==expected_slots
    assert pred['fonts']==expected_fonts
    assert pred['predicates']==[dict(enabled=True,kind=0,slot=1,format=0,cutoff=20050101),dict(enabled=False,kind=0,slot=0,format=0,cutoff=0)]
    return True

def decode_text(raw,fonts):
    font,kind,strings=decode_record(raw);width,mapping=fonts[font];text=[]
    for source in strings:
        data=decode_string(source,kind);assert len(data)%width==0
        text.extend(mapping[int.from_bytes(data[i:i+width],'big')] for i in range(0,len(data),width))
    return ''.join(text)

def execute(nargo,root,label,w,reject=False):
    write(root/'Prover.toml',w)
    p=subprocess.run([nargo,'execute','--program-dir',str(root),'--pedantic-solving'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    constrained=p.returncode==1 and 'Cannot satisfy constraint' in p.stdout
    if reject and constrained and ('inline-image' in label or 'actual-text' in label):
        source=(ROOT/'pdf_text_v1/src/lex_segment.nr').read_text().splitlines()
        needle='w!=0x4249' if 'inline-image' in label else '(s.bt|bt)'
        line=next(i+1 for i,s in enumerate(source) if needle in s)
        constrained=bool(re.search(r'lex_segment\.nr:'+str(line)+r'[:\)]',p.stdout))
    if not (constrained if reject else p.returncode==0):raise RuntimeError(label+': unexpected circuit result; diagnostics suppressed')
    print(label+(': constraint rejection' if reject else ': accepted'),flush=True)
    return dict(case=label,outcome='constraint_rejection' if reject else 'accepted')

def sha_package(path,kind):
    import shutil
    path.mkdir(parents=True,exist_ok=True);(path/'src').mkdir(exist_ok=True)
    source=ROOT/('pdf_sha_'+kind+'_v1')
    shutil.copyfile(source/'src/main.nr',path/'src/main.nr')
    (path/'Nargo.toml').write_text('[package]\nname="sha_fixture"\ntype="bin"\nauthors=[]\n[dependencies]\npdf_text_v1={path='+json.dumps(str(ROOT/'pdf_text_v1'))+'}\n')
    return path

def export_m3c(directory, filename, bundle, windows):
    """Export only the authorized synthetic fixtures, without running nargo."""
    from lex_reference import decode_record
    def record(raw):
        font,kind,strings=decode_record(bytes(raw))
        return dict(font=list(font),kind=kind,strings=[list(x) for x in strings])
    def mid(words):return list(b''.join(x.to_bytes(4,'big') for x in words))
    private_windows=[];public_windows=[]
    for window in windows:
        w=window['witness'];n=window['length'];head=w['head_len']
        common=dict(role=window['kind'],mid_in=mid(w['mid_in']),head=list(unpack_public(w['head'],63)[:head]),
                    tail=list(unpack_public(w['tail'],63)[:w['tail_len']]),
                    key_stream=list(unpack_public(w['keystream'],8192)[:n]) if w.get('encrypted') else None)
        private_windows.append(dict(**common,private_data=w['bytes'][head:head+n]))
        public_windows.append(dict(**common,blocks=w['blocks']))
    claim=bundle['claim'];anchors=[];public_anchors=[];slots=[];public_slots=[]
    for a in claim['anchors']:
        if a['enabled']:
            encoded=record(a['raw'][:a['len']]);anchors.append(dict(record=encoded))
            public_anchors.append(dict(record=encoded,ordinal=a['ordinal'],total=a['total']))
    for i,s in enumerate(claim['slots']):
        if s['enabled']:
            public=dict(slot=i,before_anchor=s['before'],after_anchor=s['after'])
            public_slots.append(public);slots.append(dict(**public,salt=claim['claim_salts'][i]))
    fonts=[dict(font=f['name'][:f['len']],width=f['width'],codes=f['digits']) for f in bundle['pred']['fonts'] if f['enabled']]
    predicates=[{k:v for k,v in p.items() if k!='enabled'} for p in bundle['pred']['predicates'] if p['enabled']]
    common=dict(composition='zkpdf-v1-phone',binding=claim['beta'],digit_tables=fonts,predicates=predicates)
    result=dict(input=dict(**common,windows=private_windows,anchors=anchors,slots=slots,assets_dir=''),
                spec=dict(**common,windows=public_windows,anchors=public_anchors,slots=public_slots),
                reference_salt='0x2a',reference_public_inputs=[])
    def scalar(x):return int(x,16) if isinstance(x,str) else int(x)
    def anchor(a):return [a['enabled'],a['len'],*a['raw'],a['ordinal'],a['total']]
    def slot(s):return [s['enabled'],s['before'],s['after']]
    stages=[('sha_'+x['kind'],i,x['witness']) for i,x in enumerate(windows)]
    stages += [('inflate0' if i==0 else 'inflate',i,w) for i,w in enumerate(bundle['inflate'])]
    stages += [('lex',i,w) for i,w in enumerate(bundle['lex'])]
    stages += [('claim',0,claim),('pred',0,bundle['pred'])]
    for kind,index,w in stages:
        fields=[w['domain'],w['circuit']]
        if kind.startswith('sha_'):
            fields += w['mid_in']+w['mid_out']+[w['blocks'],w['head_len']]+w['head']+[w['tail_len']]+w['tail']
            if kind=='sha_content':fields += [w['encrypted']]+w['keystream']+[w['cz']]
        elif kind.startswith('inflate'):
            fields += [w[k] for k in ('index','first','last','cz','sin','sout','cp')]+w.get('previous',[])
        else:
            if kind=='lex':fields += [w[k] for k in ('index','first','last','cz','lin','lout')]+w['cp']
            elif kind=='claim':fields += w['beta']+[w['start'],w['count'],w['cz']]
            else:fields += w['beta']+[w['cz']]
            fields += [x for a in w['anchors'] for x in anchor(a)]+[x for s in w['slots'] for x in slot(s)]+[w['cg']]
            if kind=='claim':fields += [x for d in w['digests'] for x in d]
            if kind=='pred':
                fields += [x for f in w['fonts'] for x in [f['enabled'],f['len'],*f['name'],f['width'],*f['digits']]]
                fields += [x for p in w['predicates'] for x in [p[k] for k in ('enabled','kind','slot','format','cutoff')]]
        encoded=b''.join(scalar(x).to_bytes(32,'big') for x in fields)
        result['reference_public_inputs'].append(dict(kind=kind,index=index,bytes=len(encoded),sha256=hashlib.sha256(encoded).hexdigest()))
    directory.mkdir(parents=True,exist_ok=True)
    (directory/(filename.removesuffix('.pdf')+'.json')).write_text(json.dumps(result,indent=2)+'\n')

def main():
    if not __debug__:raise RuntimeError("Reference checks require normal Python assertion mode")
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--nargo',default='nargo');parser.add_argument('--output',type=Path,default=ROOT/'target/pdf-fixture-chain');parser.add_argument('--export-json',type=Path,help='Export the two positive synthetic WP3b inputs and verifier specifications');args=parser.parse_args()
    version=subprocess.check_output([args.nargo,'--version'],text=True);assert version.splitlines()[0]=='nargo version = 1.0.0-beta.15'
    from formal_profiles import validate
    validate('phone')
    h=Poseidon();h.self_test();args.output.mkdir(parents=True,exist_ok=True)
    cache=Path(tempfile.gettempdir())/('diw-pdf-fixtures-'+hashlib.sha256(str(ROOT).encode()).hexdigest()[:16])
    roots={k:package(cache/k,k,P=2048,A=16,C=12,Q=384,R=96) for k in ('lex','claim','pred')}
    roots['inflate0']=inflate_package(cache/'inflate0',2048,1024,1,8192,first=True)
    roots['inflate']=inflate_package(cache/'inflate',2048,352,1,8192)
    for k in ('content','opaque'):roots[k]=sha_package(cache/k,k)
    results=[]
    for filename in ('student.pdf','travel-rc4.pdf','student-inline-image.pdf','student-actual-text.pdf','student-oversized.pdf'):
        if args.export_json and filename not in ('student.pdf','travel-rc4.pdf'):continue
        pdf,message,digest,br=signed_pdf(FIXTURES/filename);stream,opaque,resources=pdf.page();plain=pdf.decoded(stream)
        if len(plain)>40960:
            assert filename=='student-oversized.pdf';reason=f'Plaintext length {len(plain)} exceeds MAX_PLAIN=40960 before witness generation'
            results.append(dict(fixture=filename,outcome='parameter_rejection',reason=reason));print(filename+': '+reason,flush=True);continue
        windows=[window(pdf,stream,message,br,'content',h)]+[window(pdf,x,message,br,'opaque',h) for x in opaque]
        check_sha_chain(message,digest,windows)
        # V5 must work from public structure, with stream payloads redacted.
        masked=bytearray(pdf.data)
        for obj in [stream,*opaque]:masked[obj['start']:obj['end']]=bytes(obj['end']-obj['start'])
        public=Pdf(bytes(masked));pc,po,pr=public.page()
        assert [(x['ref'],x['start'],x['end']) for x in [pc,*po]]==[(x['ref'],x['start'],x['end']) for x in [stream,*opaque]]
        assert public.fonts(pr)==pdf.fonts(resources)
        b,c,d=br;check_sha_chain(bytes(masked[:b]+masked[c:c+d]),digest,windows)
        if filename in ('student-inline-image.pdf','student-actual-text.pdf'):
            # Open the real SHA-bound plaintext. Empty plan, zero output state
            # are deliberate: additionally require a source location in the
            # lexical Word-rule assertion, not a later output commitment check.
            chain=segments(bytes(x^y for x,y in zip(pdf.data[stream['start']:stream['end']],pdf.keystream(stream['ref'],stream['end']-stream['start']))),h,2048,352,1,8192,token0_capacity=1024)
            from lex_reference import initial,plan_commit,challenge,empty_anchor,LEX
            anchors=[empty_anchor(96) for _ in range(16)];slots=[dict(enabled=False,before=0,after=0) for _ in range(12)]
            plan=dict(anchor_ops=[0]*16,lengths=[0]*12,records=[[0]*384 for _ in range(12)])
            pi=plan_commit(h,42,plan);r=challenge(h,chain[0]['cz'],pi,anchors,slots)
            assert len(chain)==1
            w=dict(domain=DOMAIN,circuit=LEX,index=0,first=True,last=True,cz=chain[0]['cz'],lin=0,lout=0,cp=[chain[0]['cp']],anchors=anchors,slots=slots,cg=0,salt=42,plain=[chain[0]['plain']],lengths=[chain[0]['plain_len']],incoming=initial(pi,r,16,12),plan=plan,positions=[0]*64,used=0)
            write(args.output/filename/'lex-000/Prover.toml',w)
            results.append(dict(fixture=filename,**execute(args.nargo,roots['lex'],filename+'/lex',w,True)));continue
        fonts=pdf.fonts(resources);scan=Scanner(0,3,[],[],dict(anchor_ops=[]))
        for b in plain:scan.step(b)
        scan.eof();labels=[decode_text(x,fonts) for x in scan.records]
        after='科系' if filename=='student.pdf' else '序號'
        selected=('姓名','學號' if filename=='student.pdf' else '證件號','出生日期',after)
        assert all(labels.count(x)==1 for x in selected)
        indices=[labels.index(x) for x in selected]
        z=bytes(x^y for x,y in zip(pdf.data[stream['start']:stream['end']],pdf.keystream(stream['ref'],stream['end']-stream['start'])))
        digit_fonts=[]
        for name,(width,mapping) in fonts.items():
            assert all(list(mapping.values()).count(str(i))==1 for i in range(10))
            inv={v:k for k,v in mapping.items()};digit_fonts.append(dict(enabled=True,len=len(name),name=list(name)+[0]*(16-len(name)),width=width,digits=[inv[str(i)] for i in range(10)]))
        digit_fonts += [dict(enabled=False,len=0,name=[0]*16,width=0,digits=[0]*10)]*(4-len(digit_fonts))
        bundle=build(plain,h,anchor_ops=indices,ranges=[(0,1),(2,3)],compressed_data=z,fonts_override=digit_fonts,predicate_slot=1,cutoff=20050101)
        assert bundle['inflate'][0]['cz']==windows[0]['witness']['cz']
        verify_chain(bundle,h,2048,1)
        expected_anchors=deepcopy(bundle['claim']['anchors']);expected_slots=deepcopy(bundle['claim']['slots'])
        check_public_chain(bundle,windows,expected_anchors,expected_slots,digit_fonts)
        public_rejections=[]
        for case in ('cz','cp','beta','missing_lex','missing_sha'):
            bad=deepcopy(bundle);bad_windows=deepcopy(windows)
            if case=='cz':bad['claim']['cz']+=1
            elif case=='cp':bad['lex'][0]['cp'][0]+=1
            elif case=='beta':bad['pred']['beta'][0]^=1
            elif case=='missing_lex':bad['lex']=[]
            else:bad_windows=[w for w in bad_windows if w['kind']!='content']
            try:check_public_chain(bad,bad_windows,expected_anchors,expected_slots,digit_fonts)
            except AssertionError:public_rejections.append(case)
            else:raise RuntimeError('Public join mutation accepted: '+case)
        bad_windows=deepcopy(windows);bad_windows[0]['witness']['mid_out'][0]^=1
        try:check_sha_chain(message,digest,bad_windows)
        except AssertionError:public_rejections.append('sha_midstate')
        else:raise RuntimeError('SHA join mutation accepted')
        assert decode_text(bytes(bundle['claim']['plan']['records'][0][:bundle['claim']['plan']['lengths'][0]]),fonts)=='林測試'
        if args.export_json:
            export_m3c(args.export_json,filename,bundle,windows)
            print(filename+': synthetic WP3b JSON exported',flush=True)
            continue
        stages=[]
        for x in windows:stages.append((x['kind'],x['kind'],x['witness']))
        stages += [('inflate0' if i==0 else 'inflate',f'inflate-{i:03}',w) for i,w in enumerate(bundle['inflate'])]
        stages += [('lex',f'lex-{i:03}',w) for i,w in enumerate(bundle['lex'])]
        stages += [('claim','claim',bundle['claim']),('pred','pred',bundle['pred'])]
        for kind,label,w in stages:
            write(args.output/filename/label/'Prover.toml',w);execute(args.nargo,roots[kind],filename+'/'+label,w)
        results.append(dict(fixture=filename,outcome='accepted',sha_segments=len(windows),inflate_segments=len(bundle['inflate']),lex_segments=len(bundle['lex']),claim_segments=1,predicate_segments=1,public_join_rejections=public_rejections,date_digit_width=1 if filename=='student.pdf' else 2,joins='SHA digest, boundaries, C_z, S, history C_p, Lambda, coverage, anchors, C_g, beta, claim opening and date checked'))
    if args.export_json:return
    (args.output/'results.json').write_text(json.dumps(dict(scope='Synthetic fixtures; nargo constrained execution, not ZK proofs or production CMS trust verification',results=results),indent=2)+'\n')
    print('Five fixture outcomes verified; private witnesses remain local and untracked')
if __name__=='__main__':
    try:main()
    except Exception as error:
        print('Fixture reference failed ('+type(error).__name__+'); private diagnostics suppressed',file=sys.stderr)
        raise SystemExit(1) from None

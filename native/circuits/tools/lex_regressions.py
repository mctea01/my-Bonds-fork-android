#!/usr/bin/env python3
"""Constrained synthetic lexical/claim regressions; parse failures never count."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from lex_reference import build,synthetic,text,package,write,plain_commit,verify_chain,Poseidon,ROOT,fp,plan_commit,challenge,result_commit
from segment_regressions import package as inflate_package

def run(nargo,module,output):
    h=Poseidon(module);results=[]
    cache=Path(tempfile.gettempdir())/('diw-text-regressions-'+hashlib.sha256(str(ROOT).encode()).hexdigest()[:16])
    lexroot=package(cache/'lex','lex',P=64,A=8,C=4,Q=128,R=64)
    claimroot=package(cache/'claim','claim',A=8,C=4,Q=128,R=64)
    infroot=inflate_package(cache/'inflate',64,96,1,1024)
    inf0root=inflate_package(cache/'inflate0',64,96,1,1024,first=True)
    def execute(root,name,w,reject=False):
        write(root/'Prover.toml',w)
        p=subprocess.run([nargo,'execute','--program-dir',str(root),'--pedantic-solving'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        passed=(p.returncode==1 and 'Cannot satisfy constraint' in p.stdout) if reject else p.returncode==0
        results.append(dict(case=name,expected='reject' if reject else 'accept',passed=passed))
        print(name+(': pass' if passed else ': FAIL'),flush=True)
        if not passed:
            (ROOT/'target/text-failure.log').write_text(json.dumps(dict(case=name,exit_code=p.returncode,constraint_failed='Cannot satisfy constraint' in p.stdout))+'\n')
            raise RuntimeError('Unexpected constrained result; private diagnostic suppressed')
    def bundle(content,anchors,ranges):return build(content,h,P=64,A=8,C=4,Q=128,R=64,anchor_ops=anchors,ranges=ranges,T=96,T0=96,N=1024)
    try:
        control=None
        for style in ('word','table'):
            content,a,c=synthetic(style);b=bundle(content,a,c)
            for j,w in enumerate(b['inflate']):execute(inf0root if j==0 else infroot,f'{style}_inflate_{j}',w)
            for j,w in enumerate(b['lex']):execute(lexroot,f'{style}_lex_{j}',w)
            execute(claimroot,f'{style}_claim',b['claim'])
            if style=='word':control=b
        content,a,c=synthetic('word')
        wide=build(content,h,P=64,K=2,A=8,C=4,Q=128,R=64,anchor_ops=a,ranges=c,T=96,T0=96,N=1024)
        wide_root=package(cache/'lex2','lex',P=64,K=2,A=8,C=4,Q=128,R=64)
        for j,w in enumerate(wide['lex']):execute(wide_root,f'k2_padding_{j}',w)
        assert wide['lex'][-1]['cp'][-1]==0
        # Force each required token type across a boundary; no hints describe tokens.
        content,a,c=synthetic('word')
        for label,token in [('name',b'FakeFont'),('string',b'FAKE START'),('operator',b'Tj')]:
            prefix=(63-content.index(token))%64
            b=bundle(b' '*prefix+content,a,c)
            for j,w in enumerate(b['lex']):execute(lexroot,f'cross_{label}_{j}',w)
            assert any(w['incoming']['mode']=={'name':4,'string':2,'operator':6}[label] for w in b['lex'][1:])
        # Separate date groups are complete records in the same claim. Padding
        # forces a boundary while the current field already contains a record.
        content=text(b'FAKE START')+text(b'2020-')+b' '*64+text(b'01-')+text(b'02')+text(b'FAKE END')
        cross_field=bundle(content,[0,4],[(0,1)])
        assert any(w['incoming']['field_len']>0 for w in cross_field['lex'][1:])
        for j,w in enumerate(cross_field['lex']):execute(lexroot,f'cross_field_{j}',w)
        execute(claimroot,'cross_field_claim',cross_field['claim'])
        # Keep all non-mutated ABI values valid; replace and reopen plaintext so
        # syntax attacks cannot fail merely because C_p was left stale.
        def malformed(name,data):
            w=deepcopy(control['lex'][0]);raw=(data+b' '*64)[:64];w['plain'][0]=list(raw)
            w['cp'][0]=plain_commit(h,w['salt'],0,raw,64);execute(lexroot,name,w,True)
        malformed('rejects_BI',b'BI ')
        malformed('rejects_dictionary_string',b'BT /FakeFont 12 Tf << /ActualText (FAKE) >> BDC ')
        malformed('rejects_TJ_outside_array',b'BT /FakeFont 12 Tf (FAKE) TJ ')
        malformed('rejects_show_without_Tf',b'BT (FAKE) Tj ')
        malformed('rejects_mixed_string_kinds',b'BT /FakeFont 12 Tf [(FAKE)<0041>] TJ ')
        def lex_attack(name,base,mutate):
            w=deepcopy(base);mutate(w);execute(lexroot,name,w,True)
        lex_attack('rejects_wrong_anchor_operator',control['lex'][0],lambda w:w['plan']['anchor_ops'].__setitem__(0,1))
        lex_attack('rejects_anchor_ordinal',control['lex'][-1],lambda w:w['anchors'][0].__setitem__('ordinal',2))
        lex_attack('rejects_anchor_total',control['lex'][-1],lambda w:w['anchors'][0].__setitem__('total',1))
        lex_attack('rejects_plain_commitment',control['lex'][0],lambda w:w['plain'][0].__setitem__(0,w['plain'][0][0]^1))
        def overlap(w):w['slots'][1]=deepcopy(w['slots'][0])
        lex_attack('rejects_overlapping_ranges',control['lex'][0],overlap)
        def unfinished(w):
            raw=b'BT /FakeFont 12 Tf (UNFINISHED';w['plain'][0]=list(raw)+[0]*(64-len(raw));w['lengths'][0]=len(raw);w['last']=True
            w['cp'][0]=plain_commit(h,w['salt'],0,raw,64)
        lex_attack('rejects_final_inside_string',control['lex'][0],unfinished)
        def claim_attack(name,mutate):
            w=deepcopy(control['claim']);mutate(w);execute(claimroot,name,w,True)
        claim_attack('rejects_claim_byte',lambda w:w['plan']['records'][0].__setitem__(20,w['plan']['records'][0][20]^1))
        claim_attack('rejects_changed_plan_anchor',lambda w:w['plan']['anchor_ops'].__setitem__(0,1))
        claim_attack('rejects_date_cutoff',lambda w:w['predicates'][0].__setitem__('cutoff',20190101))
        claim_attack('rejects_sha_commitment',lambda w:w['digests'][0].__setitem__(0,w['digests'][0][0]^1))
        w=deepcopy(control['claim']);w['predicates'][0].update(kind=1,cutoff=20190101);execute(claimroot,'date_ge_control',w)
        w['predicates'][0]['cutoff']=20210101;execute(claimroot,'rejects_date_ge',w,True)
        # Identity-H literal octal decoding, escaped parentheses as separators.
        raw=b'\\0002\\0000\\0002\\0000\\000\\(\\0000\\0001\\000\\)\\0000\\0002'
        content=text(b'FAKE START')+text(raw,b'FakeCID')+text(b'FAKE END')
        b=bundle(content,[0,2],[(0,1)])
        for j,w in enumerate(b['lex']):execute(lexroot,f'cid_literal_lex_{j}',w)
        execute(claimroot,'cid_literal_date',b['claim'])
        bad=deepcopy(control);bad['lex'][1]['lin']+=1
        try:verify_chain(bad,h,64,1)
        except AssertionError:results.append(dict(case='reference_rejects_lex_join',expected='reject',passed=True))
        else:raise RuntimeError('Reference accepted a broken lexical join')
    finally:
        h.close();output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(results,indent=2)+'\n')

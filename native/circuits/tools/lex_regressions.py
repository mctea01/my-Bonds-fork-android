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
    predroot=package(cache/'pred','pred',A=8,C=4,Q=128,R=64)
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
            execute(predroot,f'{style}_pred',b['pred'])
            if style=='table':
                two=deepcopy(b['pred']);two['predicates'][1].update(enabled=True,slot=1,kind=1,cutoff=20200102)
                execute(predroot,'two_predicates_control',two)
                two['predicates'][1]['cutoff']=20200103;execute(predroot,'rejects_second_predicate_cutoff',two,True)
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
        execute(predroot,'cross_field_pred',cross_field['pred'])
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
        w=deepcopy(control['pred']);w['predicates'][0]['cutoff']=20190101;execute(predroot,'rejects_date_cutoff',w,True)
        claim_attack('rejects_sha_commitment',lambda w:w['digests'][0].__setitem__(0,w['digests'][0][0]^1))
        w=deepcopy(control['pred']);w['predicates'][0].update(kind=1,cutoff=20190101);execute(predroot,'date_ge_control',w)
        w['predicates'][0]['cutoff']=20210101;execute(predroot,'rejects_date_ge',w,True)
        # Identity-H literal octal decoding, escaped parentheses as separators.
        raw=b'\\0002\\0000\\0002\\0000\\000\\(\\0000\\0001\\000\\)\\0000\\0002'
        content=text(b'FAKE START')+text(raw,b'FakeCID')+text(b'FAKE END')
        b=bundle(content,[0,2],[(0,1)])
        for j,w in enumerate(b['lex']):execute(lexroot,f'cid_literal_lex_{j}',w)
        execute(claimroot,'cid_literal_claim',b['claim'])
        execute(predroot,'cid_literal_date',b['pred'])
        from lex_reference import split_claims
        divided=deepcopy(control);divided['claims']=split_claims(control['claim'],2)
        verify_chain(divided,h,64,1)
        for j,part in enumerate(divided['claims']):
            root=package(cache/f'claim-split-{j}','claim',A=8,C=4,Q=128,R=64,start=part['start'],count=part['count'])
            execute(root,f'split_claim_{j}',part)
        broken=deepcopy(divided);broken['claims'][1]['start']=1
        try:verify_chain(broken,h,64,1)
        except AssertionError:results.append(dict(case='reference_rejects_claim_coverage',expected='reject',passed=True))
        else:raise RuntimeError('Reference accepted overlapping claim coverage')
        dense=bundle(b'BT /FakeFont 1 Tf (A) Tj (B) Tj ET',[],[])
        w=dense['lex'][0];assert w['used']==2
        execute(lexroot,'operator_slots_control',w)
        def omit(x):
            from lex_reference import Scanner,state_commit
            pi=plan_commit(h,x['salt'],x['plan']);r=challenge(h,x['cz'],pi,x['anchors'],x['slots'])
            scan=Scanner(pi,r,x['anchors'],x['slots'],x['plan'])
            for byte in x['plain'][0][:x['lengths'][0]]:scan.step(byte);scan.s['pos']+=1
            scan.eof();scan.aggregate(scan.records);scan.s['ops']=1
            x['lout']=state_commit(h,x['salt'],scan.s);x['used']=1;x['positions'][1]=0
        lex_attack('rejects_omitted_end_position',w,omit)
        lex_attack('rejects_non_end_position',w,lambda x:x['positions'].__setitem__(0,0))
        lex_attack('rejects_duplicate_end_position',w,lambda x:x['positions'].__setitem__(1,x['positions'][0]))
        def reverse(x):x['positions'][:2]=x['positions'][:2][::-1]
        lex_attack('rejects_decreasing_end_positions',w,reverse)
        lex_attack('rejects_nonzero_unused_position',w,lambda x:x['positions'].__setitem__(2,1))
        claim_attack('rejects_public_slot_start',lambda x:x.__setitem__('start',1))
        claim_attack('rejects_public_slot_count',lambda x:x.__setitem__('count',3))
        w=deepcopy(control['pred']);w['cg']+=1;execute(predroot,'rejects_predicate_result_commitment',w,True)
        # The same multi-string operator serves as two anchors with ordinal 1/2.
        multi=b'BT /FakeFont 1 Tf [(FAKE)( ANCHOR)] TJ ET\n'
        b=bundle(multi+text(b'2020-01-02')+multi,[0,2],[(0,1)])
        for j,x in enumerate(b['lex']):execute(lexroot,f'multi_string_anchor_{j}',x)
        execute(claimroot,'multi_string_anchor_claim',b['claim'])
        execute(predroot,'multi_string_anchor_pred',b['pred'])
        show=b'BT /FakeFont 12 Tf [(2020-01-)(\\7)(1)] TJ ET\n'
        b=bundle(text(b'FAKE START')+show+text(b'FAKE END'),[0,2],[(0,1)])
        for j,x in enumerate(b['lex']):execute(lexroot,f'v2_octal_boundary_lex_{j}',x)
        execute(claimroot,'v2_octal_boundary_claim',b['claim'])
        w=deepcopy(b['pred']);w['predicates'][0].update(kind=1,cutoff=20200101)
        execute(predroot,'v2_octal_boundary_date_ge',w)
        w['predicates'][0]['cutoff']=20200105;execute(predroot,'rejects_cross_string_octal',w,True)
        from lex_reference import decode_string,record
        raw=b'BT /FakeFont 1 Tf [<3><1>] TJ ET\n'
        b=bundle(raw,[],[])
        for j,x in enumerate(b['lex']):execute(lexroot,f'v2_odd_hex_lex_{j}',x)
        assert decode_string(b'3',1)+decode_string(b'1',1)==bytes([0x30,0x10])
        # Reopen all transcript commitments when testing only predicate decoding.
        # This prevents a stale C_g from masquerading as a decoder rejection.
        def predicate_record(data,font=None):
            w=deepcopy(control['pred']);p=w['plan'];p['records'][0]=list(data)+[0]*(128-len(data));p['lengths'][0]=len(data)
            if font is not None:w['fonts'][0]=font
            pi=plan_commit(h,w['salt'],p);r=challenge(h,w['cz'],pi,w['anchors'],w['slots'])
            w['cg']=result_commit(h,w['salt'],dict(values=[fp(bytes(x[:n]),r) for x,n in zip(p['records'],p['lengths'])],lengths=p['lengths']))
            return w
        font=deepcopy(control['pred']['fonts'][0]);font['digits']=[65,48,66,67,68,69,70,71,72,73]
        data=record(b'FakeFont',1,[b'424142412D41302D',b'3',b'1'])
        w=predicate_record(data,font);execute(predroot,'v2_per_string_odd_hex_date',w)
        # Build actual odd-length decoded strings without changing v2 lengths.
        data=record(b'FakeCID',1,[b'00',b'32003000320030002D00300031002D00300032'])
        w=predicate_record(data);execute(predroot,'rejects_odd_identity_string',w,True)
        cases=[('literal_continuations',0,[b'2020-0'+bytes([92,13,10])+b'1-0'+bytes([92,10])+b'2']),
               ('literal_line_endings',0,[b'2020'+bytes([13,10])+b'01'+bytes([13])+b'02']),
               ('hex_whitespace',1,[b'32 30'+bytes([9])+b'32'+bytes([13,10])+b'30 2d 30 31 2d 30 32'])]
        for name,kind,parts in cases:
            w=predicate_record(record(b'FakeFont',kind,parts));execute(predroot,name,w)
        # Valid 255-string control; change the final four-space string into
        # three empty strings, preserving byte length and the prior state.
        content=b'BT /FakeFont 1 Tf ['+b'()'*254+b'(    )] TJ ET'
        b=bundle(content,[],[])
        for j,x in enumerate(b['lex']):execute(lexroot,f'string_count_255_{j}',x)
        start=content.index(b'(    )');segment=start//64
        assert start%64+6<=64
        w=deepcopy(b['lex'][segment]);w['plain'][0][start%64:start%64+6]=list(b'()()()')
        w['cp'][0]=plain_commit(h,w['salt'],segment,bytes(w['plain'][0][:w['lengths'][0]]),64)
        execute(lexroot,'rejects_more_than_255_strings',w,True)
        bad=deepcopy(control);bad['lex'][1]['lin']+=1
        try:verify_chain(bad,h,64,1)
        except AssertionError:results.append(dict(case='reference_rejects_lex_join',expected='reject',passed=True))
        else:raise RuntimeError('Reference accepted a broken lexical join')
    finally:
        h.close();output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(results,indent=2)+'\n')

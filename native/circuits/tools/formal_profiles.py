"""Pinned candidate composition profiles and public ABI package selection."""
from pathlib import Path
import re
from segment_reference import ROOT
KINDS=('sha_content','sha_opaque','inflate0','inflate','lex','claim','pred')
BASE=dict(sha_content='pdf_sha_content_v1',sha_opaque='pdf_sha_opaque_v1',inflate0='pdf_inflate_seg0_v1',inflate='pdf_inflate_seg_v1',lex='pdf_lex_seg_v1',claim='pdf_claim_v1',pred='pdf_pred_v1')
PARAMS={'phone':dict(P=2048,T0=1024,T=352,W=16,O=64),'desktop':dict(P=4096,T0=1536,T=576,W=8,O=128)}
def location(tier,kind):
    assert tier in PARAMS and kind in KINDS
    return ROOT/'profiles/desktop'/BASE[kind] if tier=='desktop' and kind in ('inflate0','inflate','lex') else ROOT/BASE[kind]
def package_name(tier,kind):return BASE[kind]+('_desktop' if tier=='desktop' and kind in ('inflate0','inflate','lex') else '')
def constants(path):return {k:int(v) for k,v in re.findall(r'global\s+(\w+):u32=(\d+);',(path/'src/main.nr').read_text())}
def validate(tier,overrides=None):
    c={k:constants(location(tier,k)) for k in KINDS}
    if overrides:
        for kind,changes in overrides.items():c[kind].update(changes)
    p=PARAMS[tier]
    assert all(c[k]['MAX_COMPRESSED']==8192 for k in ('sha_content','inflate0','inflate'))
    assert all(c[k]['SEG_PLAIN']==p['P'] for k in ('inflate0','inflate','lex'))
    assert all(c[k]['MAX_OPS']==512 for k in ('lex','claim','pred'))
    assert c['inflate0']['SEG0_TOKENS']==p['T0'] and c['inflate']['SEG_TOKENS']==p['T']
    assert c['lex']['K']==1 and c['lex']['SEG_OPS']==p['O']
    assert all(c[k]['SEG_BLOCK_STARTS']==1 for k in ('inflate0','inflate'))
    for key,value in [('MAX_ANCHORS',16),('MAX_CLAIMS',12),('MAX_CLAIM_SRC',384),('MAX_ANCHOR_SRC',96)]:assert all(c[k][key]==value for k in ('lex','claim','pred'))
    assert c['claim']['SLOT_START']==0 and c['claim']['SLOT_COUNT']==12
    assert c['pred']['MAX_PREDICATES']==2 and c['pred']['MAX_DIGIT_FONTS']==4
    assert c['sha_content']['MAX_SHA_BLOCKS']==130 and c['sha_opaque']['MAX_SHA_BLOCKS']==128
    return True

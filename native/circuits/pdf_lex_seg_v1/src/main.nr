use pdf_text_v1::text_plan::{Anchor,Slot,Plan};
use pdf_text_v1::lex_segment::{LexState,lex_segment};
global K:u32=1;
global SEG_PLAIN:u32=2048;
global MAX_OPS:u32=512;
global MAX_ANCHORS:u32=16;
global MAX_CLAIMS:u32=12;
global MAX_CLAIM_SRC:u32=384;
global MAX_ANCHOR_SRC:u32=64;
fn main(domain:pub Field,circuit:pub Field,index:pub u32,first:pub bool,last:pub bool,
    cz:pub Field,lin:pub Field,lout:pub Field,cp:pub [Field;K],
    anchors:pub [Anchor<MAX_ANCHOR_SRC>;MAX_ANCHORS],slots:pub [Slot;MAX_CLAIMS],cg:pub Field,
    salt:Field,plain:[[u8;SEG_PLAIN];K],lengths:[u32;K],incoming:LexState<MAX_ANCHORS,MAX_CLAIMS>,
    plan:Plan<MAX_ANCHORS,MAX_CLAIMS,MAX_CLAIM_SRC>) {
    assert_eq(domain,0x6469772d7a6b7064662d7631);
    assert_eq(circuit,0x7064665f6c65785f7365675f7631);
    lex_segment::<K,SEG_PLAIN,MAX_OPS,MAX_ANCHORS,MAX_CLAIMS,MAX_CLAIM_SRC,MAX_ANCHOR_SRC>(
        index,first,last,cz,lin,lout,cp,anchors,slots,cg,salt,plain,lengths,incoming,plan);
}

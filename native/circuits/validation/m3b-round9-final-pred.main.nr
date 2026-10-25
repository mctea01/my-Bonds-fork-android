use pdf_text_v1::text_plan::{Anchor,Slot,Plan};
use pdf_text_v1::claim::{DigitFont,Predicate,pred};
global MAX_ANCHORS:u32=16;
global MAX_CLAIMS:u32=12;
global MAX_CLAIM_SRC:u32=384;
global MAX_ANCHOR_SRC:u32=96;
global MAX_DIGIT_FONTS:u32=4;
global MAX_PREDICATES:u32=2;
fn main(domain:pub Field,circuit:pub Field,beta:pub [u8;32],
    cz:pub Field,anchors:pub [Anchor<MAX_ANCHOR_SRC>;MAX_ANCHORS],slots:pub [Slot;MAX_CLAIMS],cg:pub Field,
    fonts:pub [DigitFont;MAX_DIGIT_FONTS],predicates:pub [Predicate;MAX_PREDICATES],
    salt:Field,plan:Plan<MAX_ANCHORS,MAX_CLAIMS,MAX_CLAIM_SRC>) {
    assert_eq(domain,0x6469772d7a6b7064662d7631);
    assert_eq(circuit,0x7064665f707265645f7631);
    let _binding=beta;
    pred(cz,anchors,slots,cg,fonts,predicates,salt,plan);
}

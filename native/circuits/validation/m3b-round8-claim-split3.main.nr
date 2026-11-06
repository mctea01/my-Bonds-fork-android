use pdf_text_v1::text_plan::{Anchor,Slot,Plan};
use pdf_text_v1::claim::{DigitFont,Predicate,claim};
global MAX_ANCHORS:u32=16;
global MAX_CLAIMS:u32=12;
global MAX_CLAIM_SRC:u32=384;
global MAX_ANCHOR_SRC:u32=64;
global MAX_DIGIT_FONTS:u32=4;
global MAX_PREDICATES:u32=2;
global SLOT_START:u32=0;
global SLOT_COUNT:u32=3;
fn main(domain:pub Field,circuit:pub Field,beta:pub [u8;32],start:pub u32,count:pub u32,
    cz:pub Field,anchors:pub [Anchor<MAX_ANCHOR_SRC>;MAX_ANCHORS],slots:pub [Slot;MAX_CLAIMS],cg:pub Field,
    digests:pub [[u8;32];SLOT_COUNT],fonts:pub [DigitFont;MAX_DIGIT_FONTS],predicates:pub [Predicate;MAX_PREDICATES],
    salt:Field,plan:Plan<MAX_ANCHORS,MAX_CLAIMS,MAX_CLAIM_SRC>,claim_salts:[[u8;16];SLOT_COUNT]) {
    assert_eq(domain,0x6469772d7a6b7064662d7631);
    assert_eq(circuit,0x7064665f636c61696d5f7631);
    assert_eq(start,SLOT_START);assert_eq(count,SLOT_COUNT);
    // beta is a statement-binding public input, as required by section 3.1.7.
    let _binding=beta;
    claim::<MAX_ANCHORS,MAX_CLAIMS,MAX_CLAIM_SRC,MAX_ANCHOR_SRC,MAX_DIGIT_FONTS,MAX_PREDICATES,SLOT_START,SLOT_COUNT>(
        cz,anchors,slots,cg,digests,fonts,predicates,salt,plan,claim_salts);
}

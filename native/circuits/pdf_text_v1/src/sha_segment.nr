use crate::sha256_window::{sha256_window,sha256_content_window};

// A fixed-capacity pack31 value has one canonical byte representation. The
// final group uses its actual width, with left rather than right zero padding.
pub fn unpack31<let N:u32>(packed:[Field;(N+30)/31])->[u8;N] {
    let mut bytes=[0u8;N];
    for g in 0..((N+30)/31) {
        let width=if (g+1)*31<=N {31} else {N-g*31};
        // Two 128-bit limbs keep decomposition defined for every Field input.
        // A noncanonical pack fails a constraint, not a witness directive.
        let low=packed[g] as u128;
        let high=(packed[g]-(low as Field))/0x100000000000000000000000000000000;
        let hi=high.to_be_bytes::<16>();
        let lo=(low as Field).to_be_bytes::<16>();
        assert_eq(hi[0],0);
        let mut group=[0u8;31];
        for j in 0..15 {group[j]=hi[j+1];}
        for j in 0..16 {group[j+15]=lo[j];}
        for j in 0..31 { if j<31-width {assert_eq(group[j],0);} }
        for j in 0..31 { if j<width {bytes[g*31+j]=group[31-width+j];} }
    }
    bytes
}

pub fn content<let B:u32,let N:u32>(
    mid_in:[u32;8],mid_out:[u32;8],blocks:u32,
    head_len:u32,head:[u8;63],tail_len:u32,tail:[u8;63],
    encrypted:bool,keystream:[Field;(N+30)/31],cz:Field,
    bytes:[u8;B*64],salt:Field) {
    assert(B>0 & B<=130 & N>0 & N<=8192);
    assert(blocks>0 & blocks<=B & head_len<64 & tail_len<64);
    assert(head_len+tail_len<blocks*64);
    let n=blocks*64-head_len-tail_len;
    assert(n<=N);
    let key=unpack31::<N>(keystream);
    for i in 0..((N+30)/31) { if !encrypted {assert_eq(keystream[i],0);} }
    assert_eq(sha256_content_window(bytes,blocks,mid_in,mid_out,
        head,head_len,tail,tail_len,n,key,salt),cz);
}

pub fn opaque<let B:u32>(mid_in:[u32;8],mid_out:[u32;8],blocks:u32,
    head_len:u32,head:[u8;63],tail_len:u32,tail:[u8;63],bytes:[u8;B*64]) {
    assert(B>0 & B<=128);
    assert(blocks>0 & blocks<=B & head_len<64 & tail_len<64);
    assert(head_len+tail_len<blocks*64);
    sha256_window(bytes,blocks,mid_in,mid_out,head,head_len,tail,tail_len,
        blocks*64-head_len-tail_len);
}

#[test]
fn unpack_short_final_group() {
    let x=unpack31::<33>([1,0x0203]);
    assert_eq(x[30],1);assert_eq(x[31],2);assert_eq(x[32],3);
}
#[test(should_fail)]
fn rejects_noncanonical_final_group() { let _x=unpack31::<33>([0,0x10000]); }

#[test]
fn unpack_maximum_full_group() {
    let x=unpack31::<31>([0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff]);
    for i in 0..31 {assert_eq(x[i],255);}
}

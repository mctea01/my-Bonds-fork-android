use pdf_text_v1::sha_segment::content;
global MAX_SHA_BLOCKS:u32=130;
global MAX_COMPRESSED:u32=8192;
fn main(domain:pub Field,circuit:pub Field,mid_in:pub [u32;8],mid_out:pub [u32;8],blocks:pub u32,
    head_len:pub u32,head:pub [u8;63],tail_len:pub u32,tail:pub [u8;63],
    encrypted:pub bool,keystream:pub [Field;(MAX_COMPRESSED+30)/31],cz:pub Field,
    bytes:[u8;MAX_SHA_BLOCKS*64],salt:Field) {
    assert_eq(domain,0x6469772d7a6b7064662d7631);
    assert_eq(circuit,0x7064665f7368615f636f6e74656e745f7631);
    content::<MAX_SHA_BLOCKS,MAX_COMPRESSED>(mid_in,mid_out,blocks,head_len,head,tail_len,tail,encrypted,keystream,cz,bytes,salt);
}

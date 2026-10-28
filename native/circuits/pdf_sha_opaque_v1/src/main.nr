use pdf_text_v1::sha_segment::{opaque,unpack31};
global MAX_SHA_BLOCKS:u32=128;
fn main(domain:pub Field,circuit:pub Field,mid_in:pub [u32;8],mid_out:pub [u32;8],blocks:pub u32,
    head_len:pub u32,head:pub [Field;3],tail_len:pub u32,tail:pub [Field;3],
    bytes:[u8;MAX_SHA_BLOCKS*64]) {
    assert_eq(domain,0x6469772d7a6b7064662d7631);
    assert_eq(circuit,0x7064665f7368615f6f70617175655f7631);
    opaque(mid_in,mid_out,blocks,head_len,unpack31::<63>(head),tail_len,unpack31::<63>(tail),bytes);
}

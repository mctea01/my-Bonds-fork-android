// Synthetic component benchmark; not the PDF proof public ABI.
// Capacities: one block, 128 compressed bytes, 192 tokens, 40960 output bytes.
use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint};
fn main(data:[u8;128],data_len:u32,blocks:[BlockHint;1],tokens:[TokenHint;192],owners:[u32;40960],plain_len:u32,expected:[u8;40960]) {
    assert_eq(inflate(data,data_len,blocks,1,tokens,owners,plain_len),expected);
}

use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint,InflateHints};
fn main(data:[u8;128],data_len:u32,blocks:[BlockHint;1],tokens:[TokenHint;32],owners:[u32;128],plain_len:u32,hints:InflateHints<32,1>,expected:[u8;128]) {
    assert_eq(inflate(data,data_len,blocks,1,tokens,owners,plain_len,expected,hints),expected);
}

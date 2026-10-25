use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint};

fn main(data:[u8;128],data_len:u32,blocks:[BlockHint;3],block_count:u32,
    tokens:[TokenHint;64],owners:[u32;128],plain_len:u32,expected:[u8;128]) {
    assert_eq(inflate(data,data_len,blocks,block_count,tokens,owners,plain_len),expected);
}

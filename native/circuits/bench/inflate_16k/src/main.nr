// Synthetic component benchmark; not the PDF proof public ABI.
// Capacities: one block, 128 compressed bytes, 192 tokens, 16384 output bytes.
use pdf_text_v1::inflate::{inflate,BlockHint,TokenHint,InflateHints};
fn main(data:[u8;128],data_len:u32,blocks:[BlockHint;1],tokens:[TokenHint;192],owners:[u32;16384],plain_len:u32,hints:InflateHints<192,1>,expected:[u8;16384]) {
    assert_eq(inflate(data,data_len,blocks,1,tokens,owners,plain_len,expected,hints),expected);
}

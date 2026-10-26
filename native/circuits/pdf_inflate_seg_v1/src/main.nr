use pdf_text_v1::inflate::{BlockHint,Huffman};
use pdf_text_v1::inflate_segment::{inflate_segment,State,Event,SegmentHints};
global SEG_PLAIN:u32=2048;
global SEG_TOKENS:u32=288;
global SEG_BLOCK_STARTS:u32=1;
global MAX_COMPRESSED:u32=8192;
global W:u32=(32768+SEG_PLAIN-1)/SEG_PLAIN;
fn main(
    domain:pub Field, circuit:pub Field,
    index:pub u32, first:pub bool, last:pub bool,
    cz:pub Field, sin:pub Field, sout:pub Field, cp:pub Field, previous:pub [Field;W],
    salt:Field, data:[u8;MAX_COMPRESSED], data_len:u32, incoming:State,
    resumed_l:Huffman<288>, resumed_d:Huffman<32>, headers:[BlockHint;SEG_BLOCK_STARTS], header_count:u32,
    events:[Event;SEG_TOKENS+SEG_BLOCK_STARTS], event_count:u32,
    hints:SegmentHints<SEG_TOKENS+SEG_BLOCK_STARTS,SEG_BLOCK_STARTS>,
    history:[[u8;SEG_PLAIN];W], plain:[u8;SEG_PLAIN], plain_len:u32, owners:[u32;SEG_PLAIN],
) {
    // ASCII big-endian constants; verifier must pin this parameterized circuit.
    assert_eq(domain,0x6469772d7a6b7064662d7631);
    assert_eq(circuit,0x7064665f696e666c6174655f7365675f7631);
    inflate_segment::<MAX_COMPRESSED,SEG_PLAIN,SEG_TOKENS,SEG_BLOCK_STARTS,W>(
        index,first,last,cz,sin,sout,cp,previous,salt,data,data_len,incoming,
        resumed_l,resumed_d,headers,header_count,events,event_count,hints,history,plain,plain_len,owners);
}

// Synthetic component benchmark; this is not a PDF proof ABI.
use pdf_text_v1::sha256_window::sha256_window;
fn main(bytes: [u8;8320], mid_in: pub [u32;8], mid_out: pub [u32;8]) {
    sha256_window(bytes,130,mid_in,mid_out,[0;63],0,[0;63],0,8320);
}

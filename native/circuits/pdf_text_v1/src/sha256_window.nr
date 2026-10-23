// FIPS 180-4 compression over an aligned window; padding belongs to the caller's
// public message. The enclosing circuit must expose the boundary arguments.
pub fn sha256_window<let B: u32>(
    bytes: [u8; B * 64], blocks: u32, mid_in: [u32; 8], mid_out: [u32; 8],
    head: [u8; 63], head_len: u32, tail: [u8; 63], tail_len: u32,
    private_len: u32,
) {
    assert(blocks > 0 & blocks <= B);
    assert(head_len < 64 & tail_len < 64);
    assert(private_len > 0 & private_len <= B * 64);
    assert_eq(head_len + private_len + tail_len, blocks * 64);
    for i in 0..63 {
        if i < head_len { assert_eq(bytes[i], head[i]); }
        else { assert_eq(head[i], 0); }
        if i < tail_len { assert_eq(bytes[blocks * 64 - tail_len + i], tail[i]); }
        else { assert_eq(tail[i], 0); }
    }
    let mut state = mid_in;
    for b in 0..B {
        let mut words = [0u32; 16];
        for w in 0..16 {
            let p = b * 64 + w * 4;
            words[w] = (bytes[p] as u32) * 16777216 + (bytes[p + 1] as u32) * 65536
                + (bytes[p + 2] as u32) * 256 + bytes[p + 3] as u32;
        }
        if b < blocks { state = std::hash::sha256_compression(words, state); }
        else { for i in 0..64 { assert_eq(bytes[b * 64 + i], 0); } }
    }
    assert_eq(state, mid_out);
}

#[test]
fn nist_abc() {
    let mut bytes = [0u8; 64];
    bytes[0] = 97; bytes[1] = 98; bytes[2] = 99; bytes[3] = 128; bytes[63] = 24;
    // A compression known-answer test, not a valid PDF window (padding is public).
    sha256_window(bytes, 1,
        [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
        [0xba7816bf,0x8f01cfea,0x414140de,0x5dae2223,0xb00361a3,0x96177a9c,0xb410ff61,0xf20015ad],
        [0;63],0,[0;63],0,64);
}

fn boundary_case(bad_head: bool, bad_tail: bool) {
    let mut bytes = [0u8;64];
    bytes[0]=97; bytes[1]=98; bytes[2]=99; bytes[3]=128; bytes[63]=24;
    let mut head=[0u8;63]; head[0]=if bad_head { 96 } else { 97 };
    let mut tail=[0u8;63]; tail[0]=if bad_tail { 25 } else { 24 };
    sha256_window(bytes,1,
        [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
        [0xba7816bf,0x8f01cfea,0x414140de,0x5dae2223,0xb00361a3,0x96177a9c,0xb410ff61,0xf20015ad],
        head,1,tail,1,62);
}
#[test]
fn public_boundaries_match() { boundary_case(false,false); }
#[test(should_fail)]
fn head_mismatch() { boundary_case(true,false); }
#[test(should_fail)]
fn tail_mismatch() { boundary_case(false,true); }

#[test(should_fail)]
fn rejects_empty_window() {
    sha256_window([0;64],0,[0;8],[0;8],[0;63],0,[0;63],0,0);
}

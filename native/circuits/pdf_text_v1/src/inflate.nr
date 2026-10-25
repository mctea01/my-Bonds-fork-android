// RFC 1950/1951. All hints are private and checked against the compressed bytes.
// No unconstrained function participates in acceptance.
pub struct BlockHint {
    pub start: u32,
    pub end: u32,
    pub first_token: u32,
    pub tokens: u32,
    // Indexed by expanded code-length position; entries inside repeats are unused.
    pub code_symbols: [u16; 320],
    pub code_widths: [u8; 320],
}

pub struct TokenHint {
    pub block: u32,
    pub start: u32,
    pub symbol: u16,
    pub width: u8,
    pub distance_symbol: u8,
    pub distance_width: u8,
}

struct Huffman<let N: u32> {
    lengths: [u8; N],
    codes: [u32; N],
}

fn bits<let N: u32>(data: [u8; N], limit: u32, pos: u32, width: u32) -> u32 {
    assert(width <= 16);
    assert(pos <= limit & width <= limit - pos);
    let offset = pos / 8;
    let mut word = 0u32;
    for i in 0..4 {
        let index = offset + i;
        let safe_index = if index < N { index } else { 0 };
        let byte = if index < N { data[safe_index] as u32 } else { 0 };
        word = word | (byte << (i * 8));
    }
    (word >> (pos % 8)) & ((1u32 << width) - 1)
}

fn table<let N: u32>(lengths: [u8; N], allow_single: bool, allow_empty: bool) -> Huffman<N> {
    let mut counts = [0u32;16];
    let mut used = 0u32;
    for i in 0..N {
        assert(lengths[i] <= 15);
        let present = if lengths[i] != 0 { 1 } else { 0 };
        counts[lengths[i] as u32] += present;
        used += present;
    }
    let mut next = [0u32;16];
    let mut code = 0u32;
    for i in 1..16 {
        code = (code + counts[i - 1]) * 2;
        assert(code + counts[i] <= (1u32 << i));
        next[i] = code;
    }
    assert((code + counts[15] == 32768)
        | (allow_single & (used == 1) & (counts[1] == 1))
        | (allow_empty & (used == 0)));
    let mut codes = [0u32;N];
    for i in 0..N {
        let width = lengths[i] as u32;
        codes[i] = if width != 0 { next[width] } else { 0 };
        next[width] += if width != 0 { 1 } else { 0 };
    }
    Huffman { lengths, codes }
}

fn symbol<let N: u32, let S: u32>(
    data: [u8;N], limit: u32, pos: u32, h: Huffman<S>, value: u32, width: u32,
) -> u32 {
    symbol_at(data, limit, pos, h, 0, S, value, width)
}

// Select only the two scalar entries needed for this symbol. Selecting an
// entire block's Huffman struct before indexing it expands private array
// selection for every token in the compiler's SSA.
fn symbol_at<let N: u32, let S: u32>(
    data: [u8;N], limit: u32, pos: u32, h: Huffman<S>,
    offset: u32, alphabet: u32, value: u32, width: u32,
) -> u32 {
    assert(alphabet <= S & offset <= S - alphabet);
    assert(value < alphabet & width > 0 & width <= 15);
    let index = offset + value;
    assert_eq(h.lengths[index] as u32, width);
    let mut raw = bits(data, limit, pos, width);
    raw = ((raw & 0x55555555) << 1) | ((raw >> 1) & 0x55555555);
    raw = ((raw & 0x33333333) << 2) | ((raw >> 2) & 0x33333333);
    raw = ((raw & 0x0f0f0f0f) << 4) | ((raw >> 4) & 0x0f0f0f0f);
    raw = ((raw & 0x00ff00ff) << 8) | ((raw >> 8) & 0x00ff00ff);
    raw = (raw << 16) | (raw >> 16);
    let reversed = raw >> (32 - width);
    assert_eq(reversed, h.codes[index]);
    pos + width
}

fn dynamic_tables<let N: u32>(data: [u8;N], limit: u32, start: u32, hint: BlockHint)
    -> (Huffman<288>, Huffman<32>, u32) {
    let hlit = bits(data,limit,start,5) + 257;
    let hdist = bits(data,limit,start+5,5) + 1;
    let hclen = bits(data,limit,start+10,4) + 4;
    assert(hlit <= 286);
    let order: [u32;19] = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
    let mut cl = [0u8;19];
    for i in 0..19 {
        if i < hclen { cl[order[i]] = bits(data,limit,start+14+i*3,3) as u8; }
    }
    let ch = table(cl,false,false);
    let mut pos = start + 14 + hclen * 3;
    let mut lengths = [0u8;320];
    let mut repeat = 0u32;
    let mut value = 0u8;
    for i in 0..320 {
        if i < hlit + hdist {
            if repeat == 0 {
                let s = hint.code_symbols[i] as u32;
                pos = symbol(data,limit,pos,ch,s,hint.code_widths[i] as u32);
                if s <= 15 { value = s as u8; repeat = 1; }
                else if s == 16 {
                    assert(i > 0);
                    repeat = 3 + bits(data,limit,pos,2); pos += 2;
                } else if s == 17 {
                    value = 0; repeat = 3 + bits(data,limit,pos,3); pos += 3;
                } else {
                    assert_eq(s,18);
                    value = 0; repeat = 11 + bits(data,limit,pos,7); pos += 7;
                }
                assert(repeat <= hlit + hdist - i);
            }
            repeat -= 1;
        }
        lengths[i] = if i < hlit + hdist { value } else { 0 };
    }
    assert_eq(repeat,0);
    let mut ll = [0u8;288];
    let mut dd = [0u8;32];
    for i in 0..288 { ll[i] = if i < hlit { lengths[i] } else { 0 }; }
    for i in 0..32 { dd[i] = if i < hdist { lengths[hlit+i] } else { 0 }; }
    assert(ll[256] != 0);
    (table(ll,true,false),table(dd,true,true),pos)
}

fn fixed_tables() -> (Huffman<288>, Huffman<32>) {
    let mut ll = [0u8;288];
    for i in 0..288 { ll[i] = if i < 144 { 8 } else if i < 256 { 9 } else if i < 280 { 7 } else { 8 }; }
    (table(ll,false,false),table([5;32],false,false))
}

// Private owner hints select the token that produces each output byte. Prefix
// sums make token output intervals disjoint and exhaustive; backward RAM reads
// enforce LZ77, including overlapping matches.
pub fn inflate<let N: u32, let P: u32, let T: u32, let B: u32>(
    data: [u8;N], data_len: u32, blocks: [BlockHint;B], block_count: u32,
    tokens: [TokenHint;T], owners: [u32;P], plain_len: u32,
) -> [u8;P] {
    assert(N <= 8192 & P <= 40960 & T <= 20480 & B <= 8);
    assert(data_len >= 6 & data_len <= N);
    assert(block_count > 0 & block_count <= B & plain_len <= P);
    assert_eq(data[0] & 15,8);
    assert((data[0] >> 4) <= 7);
    assert_eq(data[1] & 32,0);
    assert_eq(((data[0] as u32)*256 + data[1] as u32)%31,0);
    let window = 1u32 << ((data[0] as u32 >> 4) + 8);
    let limit = (data_len - 4) * 8;
    let empty_l = Huffman { lengths: [0u8;288], codes: [0u32;288] };
    let empty_d = Huffman { lengths: [0u8;32], codes: [0u32;32] };
    let mut ll = Huffman { lengths: [0u8;B*288], codes: [0u32;B*288] };
    let mut dd = Huffman { lengths: [0u8;B*32], codes: [0u32;B*32] };
    let mut body = [0u32;B];
    let mut kinds = [0u32;B];
    let mut total_tokens = 0u32;
    let mut end = 16u32;
    for b in 0..B {
        let mut block_ll = empty_l;
        let mut block_dd = empty_d;
        if b < block_count {
            let h = blocks[b];
            assert_eq(h.start,end);
            assert(h.end >= h.start & h.end <= limit);
            assert_eq(h.first_token,total_tokens);
            assert(h.tokens <= T - total_tokens);
            total_tokens += h.tokens;
            assert_eq(bits(data,limit,h.start,1),if b+1 == block_count {1} else {0});
            let kind = bits(data,limit,h.start+1,2);
            assert(kind < 3);
            kinds[b] = kind;
            let mut pos = h.start + 3;
            if kind == 0 {
                pos = ((pos + 7)/8)*8;
                let len = bits(data,limit,pos,16);
                let nlen = bits(data,limit,pos+16,16);
                assert_eq(len ^ nlen,65535);
                pos += 32;
                assert_eq(h.tokens,len);
                assert_eq(h.end,pos+len*8);
            } else if kind == 1 {
                let (l,d) = fixed_tables(); block_ll = l; block_dd = d;
                assert(h.tokens > 0);
            } else {
                let (l,d,p) = dynamic_tables(data,limit,pos,h);
                block_ll = l; block_dd = d; pos = p;
                assert(h.tokens > 0);
            }
            body[b] = pos;
            end = h.end;
        }
        for j in 0..288 {
            ll.lengths[b*288+j] = block_ll.lengths[j];
            ll.codes[b*288+j] = block_ll.codes[j];
        }
        for j in 0..32 {
            dd.lengths[b*32+j] = block_dd.lengths[j];
            dd.codes[b*32+j] = block_dd.codes[j];
        }
    }
    // Exactly one zlib stream: only the final partial byte may be ignored.
    assert_eq((end+7)/8,data_len-4);
    let length_base: [u32;29] = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
    let length_extra: [u32;29] = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
    let distance_base: [u32;30] = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
    let distance_extra: [u32;30] = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
    let mut starts = [0u32;T];
    let mut lengths = [0u32;T];
    let mut distances = [0u32;T];
    let mut output_len = 0u32;
    let mut previous_end = 16u32;
    for i in 0..T {
        let mut token_start = 0u32;
        let mut token_len = 0u32;
        let mut token_distance = 0u32;
        if i < total_tokens {
            let t = tokens[i];
            assert(t.block < block_count);
            let b = t.block;
            let h = blocks[b];
            assert(i >= h.first_token & i < h.first_token+h.tokens);
            assert_eq(t.start,if i == h.first_token {body[b]} else {previous_end});
            let mut pos = t.start;
            let s = t.symbol as u32;
            let mut len = 0u32;
            let mut dist = 0u32;
            if kinds[b] == 0 {
                assert_eq(s,bits(data,limit,pos,8)); pos += 8; len = 1;
            } else {
                pos = symbol_at(data,limit,pos,ll,b*288,288,s,t.width as u32);
                if s < 256 { len = 1; }
                else if s == 256 { assert_eq(i+1,h.first_token+h.tokens); }
                else {
                    assert(s <= 285);
                    let code = s-257;
                    len = length_base[code]+bits(data,limit,pos,length_extra[code]);
                    pos += length_extra[code];
                    let ds = t.distance_symbol as u32;
                    assert(ds < 30);
                    pos = symbol_at(data,limit,pos,dd,b*32,32,ds,t.distance_width as u32);
                    dist = distance_base[ds]+bits(data,limit,pos,distance_extra[ds]);
                    pos += distance_extra[ds];
                    assert(dist <= window & dist <= output_len);
                }
                if i+1 == h.first_token+h.tokens { assert_eq(s,256); }
            }
            if i+1 == h.first_token+h.tokens { assert_eq(pos,h.end); }
            assert(pos <= h.end);
            token_start = output_len; token_len = len; token_distance = dist;
            assert(len <= P-output_len);
            output_len += len;
            previous_end = pos;
        }
        starts[i] = token_start; lengths[i] = token_len; distances[i] = token_distance;
    }
    assert_eq(output_len,plain_len);
    let mut out = [0u8;P];
    let mut a = 1u32;
    let mut b = 0u32;
    for k in 0..P {
        // Keep the array write outside conditional branches. Merging whole
        // output arrays per byte makes the compiler's SSA grow quadratically.
        let byte = if k < plain_len {
            let owner = owners[k];
            assert(owner < total_tokens);
            assert(k >= starts[owner] & k < starts[owner]+lengths[owner]);
            let dist = distances[owner];
            if dist == 0 { tokens[owner].symbol as u8 }
            else { assert(dist <= k); out[k-dist] }
        } else { 0 };
        out[k] = byte;
        if k < plain_len {
            a = (a + byte as u32)%65521;
            b = (b+a)%65521;
        }
    }
    let p = data_len-4;
    let checksum = (data[p] as u32)*16777216 + (data[p+1] as u32)*65536
        + (data[p+2] as u32)*256 + data[p+3] as u32;
    assert_eq(b*65536+a,checksum);
    for i in 0..N { if i >= data_len { assert_eq(data[i],0); } }
    out
}

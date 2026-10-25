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
    pub cl_lengths: [u8; 19],
    pub cl_codes: [u32; 19],
    pub expanded_lengths: [u8; 320],
    pub cl_prefixes: [u16; 19*15],
    pub ll_prefixes: [u16; 288*15],
    pub dd_prefixes: [u16; 32*15],
    pub cl_first: [u32;16],
    pub ll_first: [u32;16],
    pub dd_first: [u32;16],
    pub header_repeats: [u8;320],
    pub header_prefixes: [u8;320],
    pub header_suffixes: [u32;320],
}

pub struct TokenHint {
    pub block: u32,
    pub start: u32,
    pub symbol: u16,
    pub width: u8,
    pub distance_symbol: u8,
    pub distance_width: u8,
}

// Immutable advice arrays are bound at constant indices before private reads.
pub struct InflateHints<let T: u32, let B: u32> {
    pub ll_lengths: [u8; B*288],
    pub ll_codes: [u32; B*288],
    pub dd_lengths: [u8; B*32],
    pub dd_codes: [u32; B*32],
    pub body: [u32; B],
    pub kinds: [u32; B],
    pub starts: [u32; T],
    pub lengths: [u32; T],
    pub distances: [u32; T],
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
    // At most 16 bits starting at bit offset 7 occupy 23 bits: three bytes.
    // A fourth byte cannot affect the masked result.
    for i in 0..3 {
        let index = offset + i;
        // Every caller uses limit=(data_len-4)*8 with data_len<=N.
        // Thus offset<=N-4, including a zero-width read at the limit.
        // The three indices are in range; keep the array's bounds constraints.
        let byte = data[index] as u32;
        word = word | (byte << (i * 8));
    }
    let powers: [u32;17] = [1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536];
    (word / powers[pos % 8]) % powers[width]
}

// Stored codes use the same low-bit-first representation as the bitstream.
fn reverse_code(code: u32, width: u32) -> u32 {
    let mut raw = code;
    raw = ((raw & 0x5555) << 1) | ((raw >> 1) & 0x5555);
    raw = ((raw & 0x3333) << 2) | ((raw >> 2) & 0x3333);
    raw = ((raw & 0x0f0f) << 4) | ((raw >> 4) & 0x0f0f);
    raw = ((raw & 0x00ff) << 8) | ((raw >> 8) & 0x00ff);
    let powers: [u32;17] = [1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536];
    raw / powers[16-width]
}

fn table<let N: u32>(lengths: [u8; N], prefixes: [u16;N*15], first_codes: [u32;16],
    allow_single: bool, allow_empty: bool) -> Huffman<N> {
    assert(N > 0 & N <= 320);
    assert_eq(first_codes[0],0);
    let mut first: Field = 0;
    let mut used: Field = 0;
    let mut ones: Field = 0;
    for width in 1..16 {
        assert_eq(first_codes[width] as Field,first);
        let first_code = first_codes[width] as Field;
        let mut count: Field = 0;
        for i in 0..N {
            // Immutable counters are bound at every constant index, including
            // the initial zero. They count earlier symbols of this exact width.
            let prefix = prefixes[i*15+width-1] as Field;
            assert_eq(prefix,count);
            let present = lengths[i] as u32 == width;
            count = prefix + if present { 1 } else { 0 };
        }
        // Prefix recurrences imply count<=N. Even before the tree checks,
        // first+count<=N*2^15<2^32, so the cast cannot hide overflow.
        assert((first_code+count) as u32 <= (1u32 << width));
        if width == 1 { ones = count; }
        used += count;
        first = (first_code+count)*2;
    }
    assert((first == 65536)
        | (allow_single & (used == 1) & (ones == 1))
        | (allow_empty & (used == 0)));
    let mut codes = [0u32;N];
    for i in 0..N {
        assert(lengths[i] <= 15);
        let width = lengths[i] as u32;
        let safe_width = if width == 0 {1} else {width};
        let rank = prefixes[i*15+safe_width-1] as u32;
        let canonical = if width == 0 {0} else {first_codes[width]+rank};
        codes[i] = reverse_code(canonical,width);
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
    assert_eq(bits(data, limit, pos, width), h.codes[index]);
    pos + width
}

// A code-length symbol (<=7 bits) and its repeat extra (<=7 bits)
// are checked together against one three-byte window.
fn header_window<let N: u32>(data: [u8;N], limit: u32, pos: u32,
    width: u32, encoded: Field, prefix: u8, suffix: u32) {
    assert(width <= 14 & pos <= limit & width <= limit-pos);
    let powers: [u32;25] = [1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536,131072,262144,524288,1048576,2097152,4194304,8388608,16777216];
    let offset = pos/8;
    let shift = pos%8;
    let word = (data[offset] as Field)+256*(data[offset+1] as Field)
        +65536*(data[offset+2] as Field);
    assert((prefix as u32) < powers[shift]);
    assert(suffix < powers[24-shift-width]);
    assert_eq(word,(prefix as Field)+(powers[shift] as Field)
        *(encoded+(powers[width] as Field)*(suffix as Field)));
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
    let computed_ch = table(cl,hint.cl_prefixes,hint.cl_first,false,false);
    for i in 0..19 {
        assert_eq(hint.cl_lengths[i],computed_ch.lengths[i]);
        assert_eq(hint.cl_codes[i],computed_ch.codes[i]);
    }
    let ch = Huffman { lengths: hint.cl_lengths, codes: hint.cl_codes };
    let mut pos = start + 14 + hclen * 3;
    let lengths = hint.expanded_lengths;
    let mut repeat = 0u32;
    let mut value = 0u8;
    for i in 0..320 {
        if i < hlit + hdist {
            if repeat == 0 {
                let s = hint.code_symbols[i] as u32;
                let width = hint.code_widths[i] as u32;
                assert(s < 19 & width > 0 & width <= 7);
                assert_eq(ch.lengths[s] as u32,width);
                let mut extra = 0u32;
                let mut extra_width = 0u32;
                repeat = hint.header_repeats[i] as u32;
                if s <= 15 { value = s as u8; assert_eq(repeat,1); }
                else if s == 16 {
                    assert(i > 0 & repeat >= 3 & repeat <= 6);
                    extra = repeat-3; extra_width = 2;
                } else if s == 17 {
                    value = 0; assert(repeat >= 3 & repeat <= 10);
                    extra = repeat-3; extra_width = 3;
                } else {
                    assert_eq(s,18); value = 0;
                    assert(repeat >= 11 & repeat <= 138);
                    extra = repeat-11; extra_width = 7;
                }
                let powers: [u32;8] = [1,2,4,8,16,32,64,128];
                let encoded = (ch.codes[s] as Field)+(powers[width] as Field)*(extra as Field);
                header_window(data,limit,pos,width+extra_width,encoded,
                    hint.header_prefixes[i],hint.header_suffixes[i]);
                pos += width+extra_width;
                assert(repeat <= hlit + hdist - i);
            }
            repeat -= 1;
        }
        assert_eq(lengths[i],if i < hlit + hdist { value } else { 0 });
    }
    assert_eq(repeat,0);
    let mut ll = [0u8;288];
    let mut dd = [0u8;32];
    for i in 0..288 { ll[i] = if i < hlit { lengths[i] } else { 0 }; }
    for i in 0..32 { dd[i] = if i < hdist { lengths[hlit+i] } else { 0 }; }
    assert(ll[256] != 0);
    (table(ll,hint.ll_prefixes,hint.ll_first,true,false),table(dd,hint.dd_prefixes,hint.dd_first,true,true),pos)
}

fn fixed_tables() -> (Huffman<288>, Huffman<32>) {
    let mut lengths = [0u8;288];
    let mut codes = [0u32;288];
    for i in 0..288 {
        let width = if i < 144 {8} else if i < 256 {9} else if i < 280 {7} else {8};
        let code = if i < 144 {48+i} else if i < 256 {400+i-144}
            else if i < 280 {i-256} else {192+i-280};
        lengths[i] = width as u8;
        codes[i] = reverse_code(code,width);
    }
    let mut distances = [0u32;32];
    for i in 0..32 { distances[i] = reverse_code(i,5); }
    (Huffman { lengths, codes },Huffman { lengths: [5u8;32], codes: distances })
}

// Private owner hints select the token that produces each output byte. Prefix
// sums make token output intervals disjoint and exhaustive; backward reads from
// immutable plain advice enforce LZ77 by induction, including overlapping matches.
pub fn inflate<let N: u32, let P: u32, let T: u32, let B: u32>(
    data: [u8;N], data_len: u32, blocks: [BlockHint;B], block_count: u32,
    tokens: [TokenHint;T], owners: [u32;P], plain_len: u32,
    plain: [u8;P], hints: InflateHints<T,B>,
) -> [u8;P] {
    assert(N <= 8192 & P <= 40960 & T <= 6144 & B <= 4);
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
    let ll = Huffman { lengths: hints.ll_lengths, codes: hints.ll_codes };
    let dd = Huffman { lengths: hints.dd_lengths, codes: hints.dd_codes };
    let body = hints.body;
    let kinds = hints.kinds;
    let first_tokens = blocks.map(|h| h.first_token);
    let block_tokens = blocks.map(|h| h.tokens);
    let block_ends = blocks.map(|h| h.end);
    let symbols = tokens.map(|t| t.symbol);
    let mut total_tokens = 0u32;
    let mut end = 16u32;
    for b in 0..B {
        let mut block_body = 0u32;
        let mut block_kind = 0u32;
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
            block_kind = kind;
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
                let (l,d) = comptime { fixed_tables() }; block_ll = l; block_dd = d;
                assert(h.tokens > 0);
            } else {
                let (l,d,p) = dynamic_tables(data,limit,pos,h);
                block_ll = l; block_dd = d; pos = p;
                assert(h.tokens > 0);
            }
            block_body = pos;
            end = h.end;
        }
        assert_eq(body[b],block_body);
        assert_eq(kinds[b],block_kind);
        for j in 0..288 {
            assert_eq(ll.lengths[b*288+j],block_ll.lengths[j]);
            assert_eq(ll.codes[b*288+j],block_ll.codes[j]);
        }
        for j in 0..32 {
            assert_eq(dd.lengths[b*32+j],block_dd.lengths[j]);
            assert_eq(dd.codes[b*32+j],block_dd.codes[j]);
        }
    }
    // Exactly one zlib stream: only the final partial byte may be ignored.
    assert_eq((end+7)/8,data_len-4);
    let length_base: [u32;29] = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
    let length_extra: [u32;29] = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
    let distance_base: [u32;30] = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
    let distance_extra: [u32;30] = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
    let starts = hints.starts;
    let lengths = hints.lengths;
    let distances = hints.distances;
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
            let first = first_tokens[b];
            let count = block_tokens[b];
            let block_end = block_ends[b];
            assert(i >= first & i < first+count);
            assert_eq(t.start,if i == first {body[b]} else {previous_end});
            let mut pos = t.start;
            let s = t.symbol as u32;
            let mut len = 0u32;
            let mut dist = 0u32;
            if kinds[b] == 0 {
                assert_eq(s,bits(data,limit,pos,8)); pos += 8; len = 1;
            } else {
                pos = symbol_at(data,limit,pos,ll,b*288,288,s,t.width as u32);
                if s < 256 { len = 1; }
                else if s == 256 { assert_eq(i+1,first+count); }
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
                if i+1 == first+count { assert_eq(s,256); }
            }
            if i+1 == first+count { assert_eq(pos,block_end); }
            assert(pos <= block_end);
            token_start = output_len; token_len = len; token_distance = dist;
            assert(len <= P-output_len);
            output_len += len;
            previous_end = pos;
        }
        assert_eq(starts[i],token_start);
        assert_eq(lengths[i],token_len);
        assert_eq(distances[i],token_distance);
    }
    assert_eq(output_len,plain_len);
    let mut a: Field = 1;
    let mut weighted: Field = 0;
    for k in 0..P {
        // Earlier-byte dependencies uniquely determine the immutable advice,
        // including overlap. Every byte, including padding, is bound here.
        let byte = if k < plain_len {
            let owner = owners[k];
            assert(owner < total_tokens);
            assert(k >= starts[owner] & k < starts[owner]+lengths[owner]);
            let dist = distances[owner];
            if dist == 0 { symbols[owner] as u8 }
            else { assert(dist > 0 & dist <= k); plain[k-dist] }
        } else { 0 };
        assert_eq(plain[k],byte);
        a += plain[k] as Field;
        weighted += (k as Field) * (plain[k] as Field);
    }
    let p = data_len-4;
    let checksum = (data[p] as u32)*16777216 + (data[p+1] as u32)*65536
        + (data[p+2] as u32)*256 + data[p+3] as u32;
    // Padding is zero, so b = n + sum((n-k)*plain[k]) = n*a-weighted.
    // a <= 1+40960*255 and b <= 40960*a < 2^39: no field wrap.
    let b = (plain_len as Field)*a-weighted;
    let reduced_a = (a as u64)%65521;
    let reduced_b = (b as u64)%65521;
    assert_eq(reduced_b*65536+reduced_a,checksum as u64);
    for i in 0..N { if i >= data_len { assert_eq(data[i],0); } }
    plain
}

// The maximum-width unaligned read spans all three bytes. The fourth byte
// must not contribute, and zero-width reads at the deflate limit remain valid.
#[test]
fn bits_three_byte_boundary() {
    let data: [u8;8] = [0x80,0x12,0x34,0xaa,0,0,0,0];
    assert_eq(bits(data,32,7,16),0x6825);
}

#[test]
fn bits_zero_width_at_limit() {
    let data: [u8;8] = [0x80,0x12,0x34,0xaa,0xff,0xff,0xff,0xff];
    assert_eq(bits(data,32,32,0),0);
}

#[test(should_fail)]
fn bits_rejects_read_past_limit() {
    let data: [u8;8] = [0xff;8];
    let _ = bits(data,32,17,16);
}

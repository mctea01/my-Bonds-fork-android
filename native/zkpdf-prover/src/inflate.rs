//! Bounded RFC 1950/1951 decoder and immutable ACIR advice generation.
use crate::{
    field::{self, F},
    Error, Result,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const LB: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LE: [usize; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DB: [usize; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DE: [usize; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
fn ensure(ok: bool, code: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(code))
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    limit: usize,
}
impl Reader<'_> {
    fn bits(&mut self, width: usize) -> Result<usize> {
        ensure(self.pos + width <= self.limit, "zlib_truncated")?;
        let mut value = 0;
        for i in 0..width {
            value |= (((self.data[(self.pos + i) / 8] >> ((self.pos + i) % 8)) & 1) as usize) << i;
        }
        self.pos += width;
        Ok(value)
    }
    fn symbol(&mut self, table: &Table) -> Result<(usize, usize)> {
        let mut code = 0;
        for width in 1..16 {
            code = code * 2 + self.bits(1)?;
            if let Some(symbol) = table.lookup.get(&(width, code)) {
                return Ok((*symbol, width));
            }
        }
        Err(Error("huffman_symbol"))
    }
}
#[derive(Clone)]
struct Table {
    lengths: Vec<usize>,
    codes: Vec<usize>,
    first: Vec<usize>,
    prefixes: Vec<usize>,
    lookup: BTreeMap<(usize, usize), usize>,
}
impl Table {
    fn new(mut lengths: Vec<usize>, capacity: usize) -> Result<Self> {
        ensure(
            lengths.len() <= capacity && lengths.iter().all(|x| *x <= 15),
            "huffman_lengths",
        )?;
        lengths.resize(capacity, 0);
        let mut counts = [0usize; 16];
        let mut prefixes = Vec::new();
        for width in &lengths {
            prefixes.extend_from_slice(&counts[1..]);
            if *width != 0 {
                counts[*width] += 1;
            }
        }
        let mut first = vec![0usize; 16];
        for i in 1..16 {
            first[i] = (first[i - 1] + counts[i - 1]) * 2;
            ensure(first[i] + counts[i] <= 1 << i, "huffman_oversubscribed")?;
        }
        let mut next = first.clone();
        let mut codes = vec![0; capacity];
        let mut lookup = BTreeMap::new();
        for (symbol, width) in lengths.iter().copied().enumerate() {
            if width != 0 {
                lookup.insert((width, next[width]), symbol);
                codes[symbol] = next[width].reverse_bits() >> (usize::BITS as usize - width);
                next[width] += 1;
            }
        }
        Ok(Self {
            lengths,
            codes,
            first,
            prefixes,
            lookup,
        })
    }
    fn json(&self) -> Value {
        json!({"lengths":self.lengths,"codes":self.codes})
    }
    fn fields(&self) -> Vec<F> {
        self.lengths
            .iter()
            .chain(&self.codes)
            .map(|x| field::number(*x))
            .collect()
    }
}
struct Block {
    hint: Value,
    l: Table,
    d: Table,
    body: usize,
    end: usize,
    kind: usize,
    final_block: bool,
}
struct Token {
    advice: [u64; 8],
    length: usize,
    distance: usize,
    end: usize,
}
pub struct Decoded {
    pub plain: Vec<u8>,
    blocks: Vec<Block>,
    tokens: Vec<Token>,
}
fn window(data: &[u8], pos: usize, end: usize, size: usize) -> (u64, u64) {
    let mut raw = 0;
    for i in 0..size {
        raw |= (*data.get(pos / 8 + i).unwrap_or(&0) as u64) << (i * 8);
    }
    (raw % (1 << (pos % 8)), raw >> (pos % 8 + end - pos))
}

pub fn decode(data: &[u8]) -> Result<Decoded> {
    ensure(data.len() >= 6 && data.len() <= 8192, "compressed_length")?;
    ensure(
        data[0] & 15 == 8
            && data[0] >> 4 <= 7
            && data[1] & 32 == 0
            && (data[0] as usize * 256 + data[1] as usize) % 31 == 0,
        "zlib_header",
    )?;
    let max_distance = 1usize << ((data[0] >> 4) + 8);
    let mut r = Reader {
        data,
        pos: 16,
        limit: (data.len() - 4) * 8,
    };
    let mut plain = Vec::new();
    let mut blocks = Vec::new();
    let mut tokens = Vec::new();
    loop {
        ensure(blocks.len() < 4, "max_blocks")?;
        let start = r.pos;
        let final_block = r.bits(1)? == 1;
        let kind = r.bits(2)?;
        let first_token = tokens.len();
        let mut cs = vec![0usize; 320];
        let mut cw = vec![0usize; 320];
        let mut expanded = vec![0usize; 320];
        let mut repeats = vec![0usize; 320];
        let mut prefixes = vec![0u64; 320];
        let mut suffixes = vec![0u64; 320];
        let mut cl = Table::new(vec![], 19)?;
        let (l, d, body, stored_length) = match kind {
            0 => {
                r.pos = r.pos.div_ceil(8) * 8;
                let length = r.bits(16)?;
                let complement = r.bits(16)?;
                ensure(length ^ complement == 65535, "stored_length")?;
                (
                    Table::new(vec![], 288)?,
                    Table::new(vec![], 32)?,
                    r.pos,
                    Some(length),
                )
            }
            1 => {
                let mut lengths = vec![8; 144];
                lengths.extend(vec![9; 112]);
                lengths.extend(vec![7; 24]);
                lengths.extend(vec![8; 8]);
                (
                    Table::new(lengths, 288)?,
                    Table::new(vec![5; 32], 32)?,
                    r.pos,
                    None,
                )
            }
            2 => {
                let hlit = r.bits(5)? + 257;
                let hdist = r.bits(5)? + 1;
                let hclen = r.bits(4)? + 4;
                ensure(hlit <= 286 && hdist <= 30, "huffman_alphabet")?;
                let mut cl_lengths = vec![0; 19];
                for i in 0..hclen {
                    cl_lengths[ORDER[i]] = r.bits(3)?;
                }
                cl = Table::new(cl_lengths, 19)?;
                let mut lengths = Vec::new();
                while lengths.len() < hlit + hdist {
                    let begin = r.pos;
                    let index = lengths.len();
                    let (symbol, width) = r.symbol(&cl)?;
                    cs[index] = symbol;
                    cw[index] = width;
                    let (value, count) = match symbol {
                        0..=15 => (symbol, 1),
                        16 => (
                            *lengths.last().ok_or(Error("huffman_repeat"))?,
                            r.bits(2)? + 3,
                        ),
                        17 => (0, r.bits(3)? + 3),
                        18 => (0, r.bits(7)? + 11),
                        _ => return Err(Error("huffman_repeat")),
                    };
                    ensure(lengths.len() + count <= hlit + hdist, "huffman_repeat")?;
                    lengths.extend(vec![value; count]);
                    repeats[index] = count;
                    (prefixes[index], suffixes[index]) = window(data, begin, r.pos, 3);
                }
                expanded[..lengths.len()].copy_from_slice(&lengths);
                ensure(lengths[256] != 0, "huffman_eob")?;
                (
                    Table::new(lengths[..hlit].to_vec(), 288)?,
                    Table::new(lengths[hlit..].to_vec(), 32)?,
                    r.pos,
                    None,
                )
            }
            _ => return Err(Error("deflate_block")),
        };
        let mut remaining = stored_length.unwrap_or(0);
        while stored_length.is_none() || remaining > 0 {
            ensure(tokens.len() < 6144, "max_tokens")?;
            let pos = r.pos;
            let (symbol, width) = if stored_length.is_some() {
                (r.bits(8)?, 0)
            } else {
                r.symbol(&l)?
            };
            let mut ds = 0;
            let mut dw = 0;
            let (length, distance) = match symbol {
                0..=255 => (1, 0),
                256 => (0, 0),
                257..=285 => {
                    let length = LB[symbol - 257] + r.bits(LE[symbol - 257])?;
                    (ds, dw) = r.symbol(&d)?;
                    ensure(ds < 30, "distance_symbol")?;
                    (length, DB[ds] + r.bits(DE[ds])?)
                }
                _ => return Err(Error("length_symbol")),
            };
            ensure(plain.len() + length <= 40960, "max_plain")?;
            ensure(
                distance <= plain.len() && distance <= max_distance,
                "deflate_distance",
            )?;
            for _ in 0..length {
                let byte = if distance == 0 {
                    symbol as u8
                } else {
                    plain[plain.len() - distance]
                };
                plain.push(byte);
            }
            let (prefix, suffix) = window(data, pos, r.pos, 7);
            tokens.push(Token {
                advice: [
                    blocks.len() as u64,
                    pos as u64,
                    symbol as u64,
                    width as u64,
                    ds as u64,
                    dw as u64,
                    prefix,
                    suffix,
                ],
                length,
                distance,
                end: r.pos,
            });
            if stored_length.is_some() {
                remaining -= 1;
            } else if symbol == 256 {
                break;
            }
        }
        let hint = json!({"start":start,"end":r.pos,"first_token":first_token,"tokens":tokens.len()-first_token,
            "code_symbols":cs,"code_widths":cw,"cl_lengths":cl.lengths,"cl_codes":cl.codes,"expanded_lengths":expanded,
            "cl_prefixes":cl.prefixes,"ll_prefixes":if kind==2 {l.prefixes.clone()} else {vec![0;4320]},
            "dd_prefixes":if kind==2 {d.prefixes.clone()} else {vec![0;480]},"cl_first":cl.first,
            "ll_first":if kind==2 {l.first.clone()} else {vec![0;16]},"dd_first":if kind==2 {d.first.clone()} else {vec![0;16]},
            "header_repeats":repeats,"header_prefixes":prefixes,"header_suffixes":suffixes});
        blocks.push(Block {
            hint,
            l,
            d,
            body,
            end: r.pos,
            kind,
            final_block,
        });
        if final_block {
            break;
        }
    }
    ensure(r.pos.div_ceil(8) == data.len() - 4, "zlib_trailing")?;
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &plain {
        a = (a + *byte as u32) % 65521;
        b = (b + a) % 65521;
    }
    let trailer = &data[data.len() - 4..];
    ensure(
        [
            ((b >> 8) & 255) as u8,
            (b & 255) as u8,
            ((a >> 8) & 255) as u8,
            (a & 255) as u8,
        ] == trailer,
        "zlib_checksum",
    )?;
    Ok(Decoded {
        plain,
        blocks,
        tokens,
    })
}

#[derive(Clone)]
struct State {
    pos: usize,
    output: usize,
    tokens: usize,
    blocks: usize,
    phase: usize,
    kind: usize,
    final_block: bool,
    table: F,
    pending_len: usize,
    pending_dist: usize,
    a: usize,
    b: usize,
    stored_end: usize,
}
impl State {
    fn fields(&self) -> Vec<F> {
        vec![
            field::number(self.pos),
            field::number(self.output),
            field::number(self.tokens),
            field::number(self.blocks),
            field::number(self.phase),
            field::number(self.kind),
            field::number(self.final_block as usize),
            self.table,
            field::number(self.pending_len),
            field::number(self.pending_dist),
            field::number(self.a),
            field::number(self.b),
            field::number(self.stored_end),
        ]
    }
    fn json(&self) -> Value {
        json!({"pos":self.pos,"output":self.output,"tokens":self.tokens,"blocks":self.blocks,"phase":self.phase,"kind":self.kind,"final_block":self.final_block,"table_commitment":field::json(self.table),"pending_len":self.pending_len,"pending_dist":self.pending_dist,"a":self.a,"b":self.b,"stored_end":self.stored_end})
    }
}
fn token_json(t: &[u64; 8]) -> Value {
    json!({"block":t[0],"start":t[1],"symbol":t[2],"width":t[3],"distance_symbol":t[4],"distance_width":t[5],"prefix":t[6],"suffix":t[7]})
}

pub fn segments(
    data: &[u8],
    full: &Decoded,
    p: usize,
    t0: usize,
    t: usize,
    salt: F,
) -> Result<Vec<Value>> {
    let zero = field::number(0);
    let cz = field::bytes_commit(1, salt, None, data, 8192)?;
    let mut state = State {
        pos: 16,
        output: 0,
        tokens: 0,
        blocks: 0,
        phase: 0,
        kind: 0,
        final_block: false,
        table: zero,
        pending_len: 0,
        pending_dist: 0,
        a: 1,
        b: 0,
        stored_end: 0,
    };
    let mut result: Vec<Value> = Vec::new();
    let mut cp_values = Vec::new();
    let mut previous_state = zero;
    let mut cursor = 0;
    loop {
        let index = result.len();
        let incoming = state.clone();
        let capacity = if index == 0 { t0 } else { t };
        let e = capacity + 1;
        let w = if index == 0 { 0 } else { 32768 / p };
        let (rl, rd) = if state.phase == 1 && state.kind > 0 {
            (
                full.blocks[state.blocks - 1].l.clone(),
                full.blocks[state.blocks - 1].d.clone(),
            )
        } else {
            (Table::new(vec![], 288)?, Table::new(vec![], 32)?)
        };
        let mut selected = Vec::new();
        let mut events = Vec::new();
        let mut lengths = Vec::new();
        let mut distances = Vec::new();
        let mut starts = vec![0];
        let mut ends = vec![state.pending_len];
        let mut dists = vec![state.pending_dist];
        let mut symbols = vec![0];
        let mut produced = state.pending_len;
        let mut last_dist = state.pending_dist;
        let mut decoded = 0;
        while state.phase != 2 && produced <= p {
            if produced == p
                && (state.phase == 0 || full.tokens.get(cursor).is_some_and(|x| x.length > 0))
            {
                break;
            }
            ensure(events.len() < e, "segment_events")?;
            let before = produced;
            let (mut length, mut distance, mut symbol) = (0, 0, 0);
            if state.phase == 0 {
                ensure(selected.is_empty(), "segment_block_starts")?;
                let block = full
                    .blocks
                    .get(state.blocks)
                    .ok_or(Error("deflate_state"))?;
                selected.push(state.blocks);
                state.blocks += 1;
                state.pos = block.body;
                state.kind = block.kind;
                state.final_block = block.final_block;
                state.phase = 1;
                state.stored_end = if block.kind == 0 { block.end } else { 0 };
                if state.kind == 0 && state.pos == state.stored_end {
                    state.phase = if state.final_block { 2 } else { 0 };
                }
                events.push(json!({"action":1,"token":token_json(&[0;8])}));
            } else {
                ensure(decoded < capacity, "segment_tokens")?;
                let token = full.tokens.get(cursor).ok_or(Error("deflate_state"))?;
                length = token.length;
                distance = token.distance;
                symbol = token.advice[2] as usize;
                state.pos = token.end;
                cursor += 1;
                decoded += 1;
                state.tokens += 1;
                if (state.kind == 0 && state.pos == state.stored_end)
                    || (state.kind > 0 && symbol == 256)
                {
                    state.phase = if state.final_block { 2 } else { 0 };
                }
                events.push(json!({"action":2,"token":token_json(&token.advice)}));
                produced += length;
                if length != 0 {
                    last_dist = distance;
                }
            }
            starts.push(before);
            ends.push(produced);
            dists.push(distance);
            symbols.push(symbol);
            lengths.push(length);
            distances.push(distance);
        }
        let length = produced.min(p);
        let last = state.phase == 2;
        ensure(last || length == p, "segment_length")?;
        let plain = full
            .plain
            .get(index * p..index * p + length)
            .ok_or(Error("deflate_state"))?;
        state.pending_len = produced.saturating_sub(p);
        state.pending_dist = if produced > p { last_dist } else { 0 };
        state.table = if state.phase == 1 && state.kind > 0 {
            let block = &full.blocks[state.blocks - 1];
            let mut fields = block.l.fields();
            fields.extend(block.d.fields());
            field::commit(3, salt, &fields)?
        } else {
            zero
        };
        state.output += length;
        for byte in plain {
            state.a = (state.a + *byte as usize) % 65521;
            state.b = (state.b + state.a) % 65521;
        }
        let owners = (0..length)
            .map(|k| {
                starts
                    .iter()
                    .zip(&ends)
                    .position(|(a, b)| *a <= k && k < *b)
                    .ok_or(Error("deflate_owner"))
            })
            .collect::<Result<Vec<_>>>()?;
        let event_count = events.len();
        while events.len() < e {
            events.push(json!({"action":0,"token":token_json(&[0;8])}));
            lengths.push(0);
            distances.push(0);
            starts.push(produced);
            ends.push(produced);
            dists.push(0);
            symbols.push(0);
        }
        let mut ll = rl.lengths.clone();
        let mut lc = rl.codes.clone();
        let mut dd = rd.lengths.clone();
        let mut dc = rd.codes.clone();
        let headers = if let Some(b) = selected.first() {
            let block = &full.blocks[*b];
            ll.extend(&block.l.lengths);
            lc.extend(&block.l.codes);
            dd.extend(&block.d.lengths);
            dc.extend(&block.d.codes);
            vec![block.hint.clone()]
        } else {
            ll.resize(576, 0);
            lc.resize(576, 0);
            dd.resize(64, 0);
            dc.resize(64, 0);
            let mut blank = full.blocks[0].hint.clone();
            for value in blank
                .as_object_mut()
                .ok_or(Error("header_schema"))?
                .values_mut()
            {
                if let Some(a) = value.as_array_mut() {
                    a.iter_mut().for_each(|x| *x = json!(0));
                } else {
                    *value = json!(0);
                }
            }
            vec![blank]
        };
        let cp = field::bytes_commit(2, salt, Some(index), plain, p)?;
        let sout = field::commit(4, salt, &state.fields())?;
        let mut padded = data.to_vec();
        padded.resize(8192, 0);
        let mut padded_plain = plain.to_vec();
        padded_plain.resize(p, 0);
        let mut padded_owners = owners;
        padded_owners.resize(p, 0);
        let mut current = json!({"domain":field::json(field::ascii("diw-zkpdf-v1")),"circuit":field::json(field::ascii(if index==0 {"pdf_inflate_seg0_v1"} else {"pdf_inflate_seg_v1"})),"index":index,"first":index==0,"last":last,"cz":field::json(cz),"sin":field::json(previous_state),"sout":field::json(sout),"cp":field::json(cp),"salt":field::json(salt),"data":padded,"data_len":data.len(),"incoming":incoming.json(),"resumed_l":rl.json(),"resumed_d":rd.json(),"headers":headers,"header_count":selected.len(),"events":events,"event_count":event_count,"hints":{"ll_lengths":ll,"ll_codes":lc,"dd_lengths":dd,"dd_codes":dc,"starts":starts,"ends":ends,"distances":dists,"symbols":symbols,"lengths":lengths,"token_distances":distances},"plain":padded_plain,"plain_len":length,"owners":padded_owners});
        if index > 0 {
            let mut history = Vec::new();
            let mut previous = Vec::new();
            for j in 0..w {
                if index + j < w {
                    history.push(vec![0; p]);
                    previous.push(field::json(zero));
                } else {
                    let absolute = index + j - w;
                    history.push(full.plain[absolute * p..(absolute + 1) * p].to_vec());
                    previous.push(field::json(cp_values[absolute]));
                }
            }
            current["history"] = json!(history);
            current["previous"] = json!(previous);
        }
        result.push(current);
        cp_values.push(cp);
        previous_state = sout;
        if last {
            ensure(
                cursor == full.tokens.len() && state.pending_len == 0,
                "deflate_final",
            )?;
            break;
        }
        ensure(result.len() < 20, "max_plain")?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acvm::AcirField;
    use sha2::{Digest, Sha256};
    #[test]
    fn synthetic_public_inputs_match_python() {
        for source in [
            include_str!("../../../test-servers/src/test/resources/zkpdf/student.json"),
            include_str!("../../../test-servers/src/test/resources/zkpdf/travel-rc4.json"),
        ] {
            let reference: Value = serde_json::from_str(source).unwrap();
            let input: crate::ZkPdfProveInput =
                serde_json::from_value(reference["input"].clone()).unwrap();
            let window = input.windows.iter().find(|w| w.role == "content").unwrap();
            let data: Vec<u8> = window
                .private_data
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ window.key_stream.as_ref().map_or(0, |key| key[i]))
                .collect();
            let full = decode(&data).unwrap();
            let chain = segments(&data, &full, 2048, 1024, 352, field::number(42)).unwrap();
            for (index, witness) in chain.iter().enumerate() {
                let mut values = vec![&witness["domain"], &witness["circuit"]];
                values.extend(
                    ["index", "first", "last", "cz", "sin", "sout", "cp"].map(|key| &witness[key]),
                );
                if let Some(previous) = witness["previous"].as_array() {
                    values.extend(previous);
                }
                let mut encoded = Vec::new();
                for value in values {
                    let f = if let Some(s) = value.as_str() {
                        F::from_hex(s).unwrap()
                    } else if let Some(b) = value.as_bool() {
                        field::number(b as usize)
                    } else {
                        field::number(value.as_u64().unwrap() as usize)
                    };
                    encoded.extend(f.to_be_bytes());
                }
                let expected = reference["reference_public_inputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|x| {
                        x["kind"] == if index == 0 { "inflate0" } else { "inflate" }
                            && x["index"] == index
                    })
                    .unwrap();
                assert!(encoded.len() == expected["bytes"].as_u64().unwrap() as usize);
                assert!(
                    format!("{:x}", Sha256::digest(&encoded))
                        == expected["sha256"].as_str().unwrap()
                );
            }
        }
    }
    #[test]
    fn malformed_streams_are_bounded() {
        for input in [
            vec![],
            vec![0; 8193],
            vec![0; 6],
            vec![120, 156, 255, 0, 0, 0, 0],
        ] {
            assert!(decode(&input).is_err());
        }
    }
}

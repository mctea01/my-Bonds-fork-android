#!/usr/bin/env python3
"""Generate only synthetic RFC 1950/1951 witnesses and Noir regression tests."""
from pathlib import Path
import random
import zlib

LBASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
LEXTRA = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
DBASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
DEXTRA = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]
ORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]

class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 16
    def bits(self, n):
        value = sum(((self.data[(self.pos+i)//8] >> ((self.pos+i)%8)) & 1) << i for i in range(n))
        self.pos += n
        return value
    def symbol(self, table):
        code = 0
        for width in range(1, 16):
            code = (code << 1) | self.bits(1)
            if (width,code) in table:
                return table[width,code], width
        raise ValueError('invalid synthetic Huffman code')

def table(lengths):
    counts = [lengths.count(i) for i in range(16)]
    counts[0] = 0
    next_code = [0]*16
    for i in range(1,16):
        next_code[i] = (next_code[i-1]+counts[i-1])*2
    result = {}
    for symbol,width in enumerate(lengths):
        if width:
            result[width,next_code[width]] = symbol
            next_code[width] += 1
    return result

def first_codes(lengths):
    counts = [lengths.count(i) for i in range(16)]
    counts[0] = 0
    first = [0]*16
    for i in range(1,16): first[i] = (first[i-1]+counts[i-1])*2
    return first

def prefixes(lengths):
    counts, result = [0]*15, []
    for width in lengths:
        result.extend(counts)
        if width: counts[width-1] += 1
    return result

def witness(data, with_hints=False):
    r, blocks, tokens, owners, output = Reader(data), [], [], [], bytearray()
    hints = {name: [] for name in ("ll_lengths", "ll_codes", "dd_lengths", "dd_codes", "body", "kinds", "starts", "lengths", "ends", "distances")}
    token_ends = []
    final = False
    while not final:
        start = r.pos
        final, kind = r.bits(1), r.bits(2)
        cs, cw = [0]*320, [0]*320
        first = len(tokens)
        cl_lengths, cl_codes, expanded_lengths = [0]*19, [0]*19, [0]*320
        header_repeats, header_prefixes, header_suffixes = [0]*320, [0]*320, [0]*320
        if kind == 0:
            r.pos = ((r.pos+7)//8)*8
            length, complement = r.bits(16), r.bits(16)
            assert length ^ complement == 65535
            body = r.pos
            ll, dd = [0]*288, [0]*32
            for _ in range(length):
                hints["starts"].append(len(output)); hints["lengths"].append(1); hints["distances"].append(0)
                pos = r.pos
                s = r.bits(8)
                owners.append(len(tokens)); output.append(s)
                tokens.append([len(blocks),pos,s,0,0,0]); token_ends.append(r.pos)
        else:
            if kind == 1:
                ll, dd = [8]*144+[9]*112+[7]*24+[8]*8, [5]*32
            elif kind == 2:
                hlit, hdist, hclen = r.bits(5)+257, r.bits(5)+1, r.bits(4)+4
                cl = [0]*19
                for i in range(hclen): cl[ORDER[i]] = r.bits(3)
                ch, lengths = table(cl), []
                while len(lengths) < hlit+hdist:
                    header_start, expanded_start = r.pos, len(lengths)
                    s, width = r.symbol(ch)
                    cs[len(lengths)], cw[len(lengths)] = s, width
                    if s < 16: lengths.append(s)
                    elif s == 16: lengths.extend([lengths[-1]]*(r.bits(2)+3))
                    elif s == 17: lengths.extend([0]*(r.bits(3)+3))
                    else: lengths.extend([0]*(r.bits(7)+11))
                    header_repeats[expanded_start] = len(lengths)-expanded_start
                    offset,shift = divmod(header_start,8)
                    raw = int.from_bytes(data[offset:offset+3],'little')
                    header_prefixes[expanded_start] = raw % (1<<shift)
                    header_suffixes[expanded_start] = raw >> (shift+r.pos-header_start)
                assert len(lengths) == hlit+hdist
                ll, dd = lengths[:hlit], lengths[hlit:]
                cl_lengths = cl
                for (width, code), symbol in table(cl).items(): cl_codes[symbol] = int(f'{code:0{width}b}'[::-1],2)
                expanded_lengths = lengths + [0]*(320-len(lengths))
            else: raise ValueError('reserved block type')
            lt, dt = table(ll), table(dd)
            body = r.pos
            while True:
                pos = r.pos
                output_start, distance = len(output), 0
                s,width = r.symbol(lt)
                ds,dw = 0,0
                if s < 256:
                    owners.append(len(tokens)); output.append(s)
                elif s > 256:
                    length = LBASE[s-257]+r.bits(LEXTRA[s-257])
                    ds,dw = r.symbol(dt)
                    distance = DBASE[ds]+r.bits(DEXTRA[ds])
                    for _ in range(length):
                        owners.append(len(tokens)); output.append(output[-distance])
                hints["starts"].append(output_start)
                hints["lengths"].append(len(output)-output_start)
                hints["distances"].append(distance)
                tokens.append([len(blocks),pos,s,width,ds,dw]); token_ends.append(r.pos)
                if s == 256: break
        hints["body"].append(body); hints["kinds"].append(kind)
        for prefix, widths, capacity in (("ll", ll, 288), ("dd", dd, 32)):
            widths = widths + [0]*(capacity-len(widths))
            codes = [0]*capacity
            for (width, code), symbol in table(widths).items(): codes[symbol] = int(f'{code:0{width}b}'[::-1], 2)
            hints[prefix+"_lengths"].extend(widths)
            hints[prefix+"_codes"].extend(codes)
        blocks.append(dict(start=start,end=r.pos,first_token=first,tokens=len(tokens)-first,code_symbols=cs,code_widths=cw,kind=kind,cl_lengths=cl_lengths,cl_codes=cl_codes,expanded_lengths=expanded_lengths,cl_prefixes=prefixes(cl_lengths),ll_prefixes=prefixes(ll+[0]*(288-len(ll))) if kind == 2 else [0]*4320,dd_prefixes=prefixes(dd+[0]*(32-len(dd))) if kind == 2 else [0]*480,cl_first=first_codes(cl_lengths),ll_first=first_codes(ll) if kind == 2 else [0]*16,dd_first=first_codes(dd) if kind == 2 else [0]*16,header_repeats=header_repeats,header_prefixes=header_prefixes,header_suffixes=header_suffixes))
    assert (r.pos+7)//8 == len(data)-4
    assert output == zlib.decompress(data)
    hints["ends"] = [start+length for start,length in zip(hints["starts"],hints["lengths"])]
    for token,end in zip(tokens,token_ends):
        offset,shift = divmod(token[1],8)
        raw = int.from_bytes(data[offset:offset+7], 'little')
        token.extend([raw % (1<<shift), raw >> (shift+end-token[1])])
    result = (blocks,tokens,owners,bytes(output))
    return (*result,hints) if with_hints else result

def padded_hints(data, token_capacity, block_capacity):
    *_, hints = witness(data, with_hints=True)
    for key, values in hints.items():
        size = token_capacity if key in ('starts', 'lengths', 'ends', 'distances') else block_capacity * (288 if key.startswith('ll_') else 32 if key.startswith('dd_') else 1)
        assert len(values) <= size
        values.extend([0]*(size-len(values)))
    return hints

def array(values): return '['+','.join(map(str,values))+']'

def nr_fixture(name, data, mutation='', fail=False):
    blocks,tokens,owners,plain = witness(data)
    n,p,t,b = len(data),max(len(plain),1),max(len(tokens),1),len(blocks)
    lines = [f'#[test{"(should_fail)" if fail else ""}]',f'unconstrained fn {name}() {{',f'    let mut data = {array(data)};',
        f'    let mut blocks = [BlockHint {{ start:0,end:0,first_token:0,tokens:0,code_symbols:[0;320],code_widths:[0;320],cl_lengths:[0;19],cl_codes:[0;19],expanded_lengths:[0;320],cl_prefixes:[0;285],ll_prefixes:[0;4320],dd_prefixes:[0;480],cl_first:[0;16],ll_first:[0;16],dd_first:[0;16],header_repeats:[0;320],header_prefixes:[0;320],header_suffixes:[0;320] }};{b}];']
    for i,block in enumerate(blocks):
        for key,value in block.items():
            if key == 'kind': continue
            if isinstance(value,list):
                for j,x in enumerate(value):
                    if x: lines.append(f'    blocks[{i}].{key}[{j}] = {x};')
            else: lines.append(f'    blocks[{i}].{key} = {value};')
    lines.append(f'    let mut tokens = [TokenHint {{ block:0,start:0,symbol:0,width:0,distance_symbol:0,distance_width:0,prefix:0,suffix:0 }};{t}];')
    for i,token in enumerate(tokens):
        entries = ','.join(f'{k}:{v}' for k,v in zip(['block','start','symbol','width','distance_symbol','distance_width','prefix','suffix'],token))
        lines.append(f'    tokens[{i}] = TokenHint {{ {entries} }};')
    hints = padded_hints(data,t,b)
    lines.append(f'    let mut hints = InflateHints {{ '+','.join(key+':'+array(values) for key,values in hints.items())+' };')
    lines.append(f'    let mut plain: [u8;{p}] = {array(plain or [0])};')
    lines += [f'    let mut owners: [u32;{p}] = {array(owners or [0])};',f'    let mut plain_len = {len(plain)};',mutation,
        f'    let result = inflate(data,{n},blocks,{b},tokens,owners,plain_len,plain,hints);',f'    assert_eq(result,{array(plain or [0])});','}']
    return '\n'.join(lines)

def compressed(plain, strategy=zlib.Z_DEFAULT_STRATEGY, level=6):
    c=zlib.compressobj(level,zlib.DEFLATED,15,8,strategy)
    return c.compress(plain)+c.flush()

def repeat_dynamic():
    """One literal, with explicit repeat positions for targeted malformed inputs."""
    bits, positions = [], {}
    def put(value, width): bits.extend((value >> i) & 1 for i in range(width))
    def code(value, width): bits.extend((value >> i) & 1 for i in reversed(range(width)))
    put(1, 1); put(2, 2); put(0, 5); put(0, 5); put(14, 4)
    # Four two-bit canonical codes: 0 -> 00, 1 -> 01, 16 -> 10, 18 -> 11.
    for symbol in ORDER[:18]: put(2 if symbol in (0, 1, 16, 18) else 0, 3)
    positions['first_repeat'] = 16 + len(bits)
    code(3, 2); put(65 - 11, 7)
    code(1, 2)
    code(3, 2); put(138 - 11, 7)
    code(3, 2)
    positions['last_repeat_extra'] = 16 + len(bits)
    put(52 - 11, 7)
    positions['eob_length'] = 16 + len(bits)
    code(1, 2); code(0, 2)
    code(0, 1); code(1, 1)
    payload = bytes(sum(b << j for j, b in enumerate(bits[i:i+8])) for i in range(0, len(bits), 8))
    data = b'\x78\x01' + payload + zlib.adler32(b'A').to_bytes(4, 'big')
    assert zlib.decompress(data) == b'A'
    return data, positions

def set_bits(data, pos, width, value):
    for i in range(width):
        index, bit = divmod(pos + i, 8)
        data[index] = (data[index] & ~(1 << bit)) | (((value >> i) & 1) << bit)

def long_codes():
    """Complete canonical tree with two 15-bit codes, without real input data."""
    bits = []
    def put(value,width): bits.extend((value>>i)&1 for i in range(width))
    def code(value,width): bits.extend((value>>i)&1 for i in reversed(range(width)))
    put(1,1); put(2,2); put(0,5); put(0,5); put(15,4)
    cl = [4]*15+[5,0,0,5]
    for symbol in ORDER: put(cl[symbol],3)
    encoding = {symbol:(width,value) for (width,value),symbol in table(cl).items()}
    def emit(symbol):
        width,value = encoding[symbol]; code(value,width)
    emit(18); put(65-11,7)
    for width in range(1,16): emit(width)
    emit(18); put(138-11,7)
    emit(18); put(38-11,7)
    emit(15); emit(0)
    code(32766,15); code(32767,15)
    payload = bytes(sum(b<<j for j,b in enumerate(bits[i:i+8])) for i in range(0,len(bits),8))
    plain = bytes([79])
    data = b'\x78\x01'+payload+zlib.adler32(plain).to_bytes(4,'big')
    assert zlib.decompress(data) == plain
    return data

def regression_cases():
    """Return valid witnesses plus one targeted attack per negative case."""
    dynamic, positions = repeat_dynamic()
    long = long_codes()
    long_tokens = witness(long)[1]
    overlap = compressed(b'AB' * 40, zlib.Z_FIXED)
    match = next(i for i, token in enumerate(witness(overlap)[1]) if token[2] > 256)
    copied_byte = witness(overlap)[2].index(match)
    return [
        ('empty_stored', compressed(b'', level=0), None),
        ('repeat_dynamic', dynamic, None),
        ('rejects_hdist_31', dynamic, ('bits',24,5,30)),
        ('rejects_hdist_32', dynamic, ('bits',24,5,31)),
        ('long_huffman_codes', long, None),
        ('rejects_in_range_token_prefix', long, ('token', 0, 6, long_tokens[0][6]^1)),
        ('rejects_in_range_token_suffix', long, ('token', 0, 7, long_tokens[0][7]^1)),
        ('rejects_adler_collision_plain', overlap, ('plain_collision', copied_byte)),
        ('rejects_empty_stored_endpoint', compressed(b'', level=0), ('block', 0, 'end', 1)),
        ('rejects_empty_huffman_without_eob', compressed(b''), ('block', 0, 'tokens', -1)),
        ('rejects_overlap_owner', overlap, ('owner', copied_byte, match - 1)),
        ('rejects_overlap_distance', overlap, ('token', match, 4, 0)),
        ('rejects_dynamic_repeat_without_previous', dynamic,
         ('bits_hint', positions['first_repeat'], 2, 1, 0, 16)),
        ('rejects_dynamic_repeat_overrun', dynamic,
         ('bits_repeat', positions['last_repeat_extra'], 7, 127, 204, 138)),
        ('rejects_dynamic_missing_eob', dynamic,
         ('bits_hint', positions['eob_length'], 2, 0, 256, 0)),
        ('rejects_eob_endpoint', overlap, ('block', 0, 'end', 1)),
        ('rejects_plain_literal', overlap, ('plain', 0)),
        ('rejects_plain_copy', overlap, ('plain', copied_byte)),
        ('rejects_table_code', overlap, ('hint', 'll_codes', 65, 1)),
        ('rejects_literal_table_width', overlap, ('hint', 'll_lengths', 65, 1)),
        ('rejects_distance_table_code', overlap, ('hint', 'dd_codes', 0, 1)),
        ('rejects_table_width', overlap, ('hint', 'dd_lengths', 0, 1)),
        ('rejects_starts', overlap, ('hint', 'starts', match, 1)),
        ('rejects_ends', overlap, ('hint', 'ends', match, 1)),
        ('rejects_token_prefix', overlap, ('token', match, 6, 255)),
        ('rejects_token_suffix', overlap, ('token', match, 7, 1<<60)),
        ('rejects_lengths', overlap, ('hint', 'lengths', match, 1)),
        ('rejects_distances', overlap, ('hint', 'distances', match, 1)),
        ('rejects_block_body', overlap, ('hint', 'body', 0, 1)),
        ('rejects_block_kind', overlap, ('hint', 'kinds', 0, 1)),
        ('rejects_code_length_table', dynamic, ('block_array', 0, 'cl_codes', 18, 1)),
        ('rejects_code_length_width', dynamic, ('block_array', 0, 'cl_lengths', 18, 1)),
        ('rejects_expanded_lengths', dynamic, ('block_array', 0, 'expanded_lengths', 65, 1)),
        ('rejects_huffman_prefix', dynamic, ('block_array', 0, 'll_prefixes', 65*15, 1)),
        ('rejects_huffman_initial_prefix', dynamic, ('block_array', 0, 'cl_prefixes', 0, 1)),
        ('rejects_distance_initial_prefix', dynamic, ('block_array', 0, 'dd_prefixes', 0, 1)),
        ('rejects_huffman_first_code', dynamic, ('block_array', 0, 'll_first', 1, 1)),
        ('rejects_code_length_first_code', dynamic, ('block_array', 0, 'cl_first', 1, 1)),
        ('rejects_empty_distance_first_code', dynamic, ('block_array', 0, 'dd_first', 1, 1)),
        ('rejects_header_repeat', dynamic, ('block_array', 0, 'header_repeats', 0, 1)),
        ('rejects_header_prefix', dynamic, ('block_array', 0, 'header_prefixes', 0, 1)),
        ('rejects_header_suffix', dynamic, ('block_array', 0, 'header_suffixes', 0, 1)),
    ]

def multiblock_cases():
    """Exercise distinct Huffman tables and an empty stored block between runs."""
    streams = [compressed(b'AB' * 20, zlib.Z_FIXED), repeat_dynamic()[0]]
    joined, plain = [], b''
    for i, data in enumerate(streams):
        blocks, _, _, output = witness(data)
        assert len(blocks) == 1 and blocks[0]['kind'] != 0
        payload = [(data[j // 8] >> (j % 8)) & 1 for j in range(16, blocks[0]['end'])]
        payload[0] = int(i == len(streams) - 1)
        joined.extend(payload)
        plain += output
    payload = bytes(sum(b << j for j, b in enumerate(joined[i:i+8])) for i in range(0, len(joined), 8))
    different = b'\x78\x01' + payload + zlib.adler32(plain).to_bytes(4, 'big')
    blocks, tokens, _, actual = witness(different)
    assert actual == plain and [b['kind'] for b in blocks] == [1, 2]
    second = blocks[1]['first_token']
    c = zlib.compressobj()
    empty_middle = c.compress(b'first') + c.flush(zlib.Z_SYNC_FLUSH) + c.compress(b'second') + c.flush()
    middle = witness(empty_middle)[0]
    assert len(middle) == 3 and middle[1]['kind'] == 0 and middle[1]['tokens'] == 0
    return [
        ('different_huffman_tables', different, None),
        ('empty_middle_block', empty_middle, None),
        ('rejects_wrong_block_table', different, ('token', second, 3, tokens[0][3])),
        ('rejects_skipped_empty_block', empty_middle, ('block', 2, 'start', -8)),
    ]

def refresh_window_advice(original, changed, blocks, tokens):
    """Keep unconsumed lookahead honest so attacks exercise semantic constraints."""
    original_blocks, _, _, _ = witness(original)
    def extras(symbol): return 2 if symbol == 16 else 3 if symbol == 17 else 7 if symbol == 18 else 0
    def split(pos,width,size):
        offset,shift = divmod(pos,8)
        raw = int.from_bytes(bytes(changed[offset:offset+size]),'little')
        return raw % (1<<shift), raw >> (shift+width)
    for index, block in enumerate(original_blocks):
        if block['kind'] != 2: continue
        reader = Reader(original); reader.pos = block['start']+3
        reader.bits(5); reader.bits(5)
        hclen = reader.bits(4)+4
        pos = reader.pos+3*hclen
        target = blocks[index]
        for i,count in enumerate(block['header_repeats']):
            if not count: continue
            width = target['code_widths'][i]+extras(target['code_symbols'][i])
            target['header_prefixes'][i],target['header_suffixes'][i] = split(pos,width,3)
            pos += block['code_widths'][i]+extras(block['code_symbols'][i])
    for token in tokens:
        if blocks[token[0]]['kind'] == 0: width = 8
        else:
            width = token[3]
            if token[2] > 256:
                width += LEXTRA[token[2]-257]+token[5]+DEXTRA[token[4]]
        token[6],token[7] = split(token[1],width,7)

def mutate(data, blocks, tokens, owners, mutation):
    """Apply the same attack to Noir tests and the compiled ACIR harness."""
    if mutation is None: return
    kind, *args = mutation
    original = bytes(data)
    if kind == 'block':
        index, key, delta = args
        blocks[index][key] += delta
    elif kind == 'block_array':
        block,key,index,delta = args
        blocks[block][key][index] += delta
    elif kind == 'token':
        index, field, value = args
        tokens[index][field] = value
    elif kind == 'owner':
        index, value = args
        owners[index] = value
    elif kind in ('bits', 'bits_hint', 'bits_repeat'):
        set_bits(data, *args[:3])
        if kind == 'bits_hint': blocks[0]['code_symbols'][args[3]] = args[4]
        if kind == 'bits_repeat': blocks[0]['header_repeats'][args[3]] = args[4]
    elif kind in ('hint', 'plain', 'plain_collision'): pass
    else: raise ValueError('Unknown synthetic mutation')
    if kind in ('bits', 'bits_hint', 'bits_repeat') or (kind == 'token' and args[1] in (1,3,4,5)):
        refresh_window_advice(original,data,blocks,tokens)

def regression_nr(name, data, mutation):
    blocks, tokens, owners, _ = witness(data)
    changed = list(data)
    mutate(changed, blocks, tokens, owners, mutation)
    before_blocks, before_tokens, before_owners, _ = witness(data)
    lines = []
    if mutation and mutation[0] == 'hint':
        _,key,index,delta = mutation
        lines.append(f'    hints.{key}[{index}] += {delta};')
    if mutation and mutation[0] == 'plain_collision':
        for offset,delta in enumerate((1,-2,1)):
            index = mutation[1]+offset
            lines.append(f'    plain[{index}] = plain[{index}] {"+" if delta>0 else "-"} {abs(delta)};')
    if mutation and mutation[0] == 'plain':
        _,index = mutation
        lines.append(f'    plain[{index}] = plain[{index}] ^ 1;')
    for i, value in enumerate(changed):
        if value != data[i]: lines.append(f'    data[{i}] = {value};')
    for i, block in enumerate(blocks):
        for key, value in block.items():
            original = before_blocks[i][key]
            if isinstance(value, list):
                for j, item in enumerate(value):
                    if item != original[j]: lines.append(f'    blocks[{i}].{key}[{j}] = {item};')
            elif value != original: lines.append(f'    blocks[{i}].{key} = {value};')
    keys = ['block', 'start', 'symbol', 'width', 'distance_symbol', 'distance_width', 'prefix', 'suffix']
    for i, token in enumerate(tokens):
        for j, value in enumerate(token):
            if value != before_tokens[i][j]: lines.append(f'    tokens[{i}].{keys[j]} = {value};')
    for i, value in enumerate(owners):
        if value != before_owners[i]: lines.append(f'    owners[{i}] = {value};')
    return nr_fixture(name, data, '\n'.join(lines), mutation is not None)

def main():
    plain=b'ABRACADABRA '*30
    fixed=compressed(plain,zlib.Z_FIXED)
    stored=compressed(b'Synthetic stored payload',level=0)
    rng=random.Random(20261023)
    dynamic=compressed(bytes(rng.choices(b'abcdefghijklmnop',weights=range(1,17),k=512)))
    assert witness(dynamic)[0][0]['kind'] == 2
    c=zlib.compressobj()
    multi=c.compress(b'first synthetic block')+c.flush(zlib.Z_SYNC_FLUSH)+c.compress(b'second synthetic block')+c.flush()
    vectors = [('adler_wrap',compressed(bytes([255])*600)),('stored',stored),('fixed_overlap',fixed),('dynamic',dynamic),('multiple_blocks',multi),('empty',compressed(b''))]
    tests = [nr_fixture(name,data) for name,data in vectors]
    tests += [nr_fixture('rejects_checksum',fixed,f'    data[{len(fixed)-1}] = data[{len(fixed)-1}] ^ 1;',True),
        nr_fixture('rejects_token_gap',fixed,'    tokens[1].start += 1;',True),
        nr_fixture('rejects_wrong_owner',fixed,'    owners[0] = 1;',True),
        nr_fixture('rejects_output_overflow',fixed,'    plain_len += 1;',True),
        nr_fixture('rejects_output_length',fixed,'    plain_len -= 1;',True),
        nr_fixture('rejects_final_flag',fixed,'    data[2] = data[2] ^ 1;',True),
        nr_fixture('rejects_dynamic_hint',dynamic,'    blocks[0].code_widths[0] = 0;',True),
        nr_fixture('rejects_stored_length',stored,'    data[5] = data[5] ^ 1;',True),
        nr_fixture('rejects_fdict',fixed,'    data[1] = data[1] | 32;',True)]
    tests += [regression_nr(*case) for case in regression_cases()]
    tests += [regression_nr(*case) for case in multiblock_cases()]
    target=Path(__file__).resolve().parents[1]/'pdf_text_v1/src/fixtures.nr'
    target.write_text('// Generated by tools/fixtures.py from synthetic data.\nuse crate::inflate::{inflate,BlockHint,TokenHint,InflateHints};\n\n'+'\n\n'.join(tests)+'\n')

if __name__ == '__main__': main()

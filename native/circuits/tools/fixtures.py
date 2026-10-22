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

def witness(data):
    r, blocks, tokens, owners, output = Reader(data), [], [], [], bytearray()
    final = False
    while not final:
        start = r.pos
        final, kind = r.bits(1), r.bits(2)
        cs, cw = [0]*320, [0]*320
        first = len(tokens)
        if kind == 0:
            r.pos = ((r.pos+7)//8)*8
            length, complement = r.bits(16), r.bits(16)
            assert length ^ complement == 65535
            for _ in range(length):
                pos = r.pos
                s = r.bits(8)
                owners.append(len(tokens)); output.append(s)
                tokens.append([len(blocks),pos,s,0,0,0])
        else:
            if kind == 1:
                ll, dd = [8]*144+[9]*112+[7]*24+[8]*8, [5]*32
            elif kind == 2:
                hlit, hdist, hclen = r.bits(5)+257, r.bits(5)+1, r.bits(4)+4
                cl = [0]*19
                for i in range(hclen): cl[ORDER[i]] = r.bits(3)
                ch, lengths = table(cl), []
                while len(lengths) < hlit+hdist:
                    s, width = r.symbol(ch)
                    cs[len(lengths)], cw[len(lengths)] = s, width
                    if s < 16: lengths.append(s)
                    elif s == 16: lengths.extend([lengths[-1]]*(r.bits(2)+3))
                    elif s == 17: lengths.extend([0]*(r.bits(3)+3))
                    else: lengths.extend([0]*(r.bits(7)+11))
                assert len(lengths) == hlit+hdist
                ll, dd = lengths[:hlit], lengths[hlit:]
            else: raise ValueError('reserved block type')
            lt, dt = table(ll), table(dd)
            while True:
                pos = r.pos
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
                tokens.append([len(blocks),pos,s,width,ds,dw])
                if s == 256: break
        blocks.append(dict(start=start,end=r.pos,first_token=first,tokens=len(tokens)-first,code_symbols=cs,code_widths=cw,kind=kind))
    assert (r.pos+7)//8 == len(data)-4
    assert output == zlib.decompress(data)
    return blocks,tokens,owners,bytes(output)

def array(values): return '['+','.join(map(str,values))+']'

def nr_fixture(name, data, mutation='', fail=False):
    blocks,tokens,owners,plain = witness(data)
    n,p,t,b = len(data),max(len(plain),1),max(len(tokens),1),len(blocks)
    lines = [f'#[test{"(should_fail)" if fail else ""}]',f'unconstrained fn {name}() {{',f'    let mut data = {array(data)};',
        f'    let mut blocks = [BlockHint {{ start:0,end:0,first_token:0,tokens:0,code_symbols:[0;320],code_widths:[0;320] }};{b}];']
    for i,block in enumerate(blocks):
        for key,value in block.items():
            if key == 'kind': continue
            if isinstance(value,list):
                for j,x in enumerate(value):
                    if x: lines.append(f'    blocks[{i}].{key}[{j}] = {x};')
            else: lines.append(f'    blocks[{i}].{key} = {value};')
    lines.append(f'    let mut tokens = [TokenHint {{ block:0,start:0,symbol:0,width:0,distance_symbol:0,distance_width:0 }};{t}];')
    for i,token in enumerate(tokens):
        entries = ','.join(f'{k}:{v}' for k,v in zip(['block','start','symbol','width','distance_symbol','distance_width'],token))
        lines.append(f'    tokens[{i}] = TokenHint {{ {entries} }};')
    lines += [f'    let mut owners: [u32;{p}] = {array(owners or [0])};',f'    let mut plain_len = {len(plain)};',mutation,
        f'    let result = inflate(data,{n},blocks,{b},tokens,owners,plain_len);',f'    assert_eq(result,{array(plain or [0])});','}']
    return '\n'.join(lines)

def compressed(plain, strategy=zlib.Z_DEFAULT_STRATEGY, level=6):
    c=zlib.compressobj(level,zlib.DEFLATED,15,8,strategy)
    return c.compress(plain)+c.flush()

def main():
    plain=b'ABRACADABRA '*30
    fixed=compressed(plain,zlib.Z_FIXED)
    stored=compressed(b'Synthetic stored payload',level=0)
    rng=random.Random(20261023)
    dynamic=compressed(bytes(rng.choices(b'abcdefghijklmnop',weights=range(1,17),k=512)))
    assert witness(dynamic)[0][0]['kind'] == 2
    c=zlib.compressobj()
    multi=c.compress(b'first synthetic block')+c.flush(zlib.Z_SYNC_FLUSH)+c.compress(b'second synthetic block')+c.flush()
    vectors = [('stored',stored),('fixed_overlap',fixed),('dynamic',dynamic),('multiple_blocks',multi),('empty',compressed(b''))]
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
    target=Path(__file__).resolve().parents[1]/'pdf_text_v1/src/fixtures.nr'
    target.write_text('// Generated by tools/fixtures.py from synthetic data.\nuse crate::inflate::{inflate,BlockHint,TokenHint};\n\n'+'\n\n'.join(tests)+'\n')

if __name__ == '__main__': main()

use crate::commitment::{commit,commit_bytes,commit_plain};
use crate::inflate::{BlockHint,TokenHint,Huffman,bits,dynamic_tables,fixed_tables,checked_code,token_window,POWERS};

// Phase: 0 header, 1 body, 2 done. Blocks counts already started blocks.
// stored_end is necessary to resume an RFC 1951 stored block mid-body.
pub struct State {
    pub pos: u32, pub output: u32, pub tokens: u32, pub blocks: u32,
    pub phase: u8, pub kind: u8, pub final_block: bool,
    pub table_commitment: Field,
    pub pending_len: u32, pub pending_dist: u32,
    pub a: u32, pub b: u32, pub stored_end: u32,
}

pub fn state_commit(salt: Field, s: State) -> Field {
    commit(4,salt,[s.pos as Field,s.output as Field,s.tokens as Field,s.blocks as Field,
        s.phase as Field,s.kind as Field,s.final_block as Field,s.table_commitment,
        s.pending_len as Field,s.pending_dist as Field,s.a as Field,s.b as Field,s.stored_end as Field])
}

pub fn initial_state() -> State {
    State { pos:16,output:0,tokens:0,blocks:0,phase:0,kind:0,final_block:false,
        table_commitment:0,pending_len:0,pending_dist:0,a:1,b:0,stored_end:0 }
}

pub fn table_commit(salt: Field, l: Huffman<288>, d: Huffman<32>) -> Field {
    let mut fields = [0;640];
    for i in 0..288 { fields[i]=l.lengths[i] as Field; fields[288+i]=l.codes[i] as Field; }
    for i in 0..32 { fields[576+i]=d.lengths[i] as Field; fields[608+i]=d.codes[i] as Field; }
    commit(3,salt,fields)
}

// Events are headers (1), tokens (2), or canonical trailing inactive slots (0).
// Every private array read below targets immutable advice, inputs or constants.
pub struct Event { pub action: u8, pub token: TokenHint }
pub struct SegmentHints<let E:u32,let B:u32> {
    pub ll_lengths:[u8;(B+1)*288], pub ll_codes:[u32;(B+1)*288],
    pub dd_lengths:[u8;(B+1)*32], pub dd_codes:[u32;(B+1)*32],
    pub starts:[u32;E+1], pub ends:[u32;E+1], pub distances:[u32;E+1],
    pub symbols:[u16;E+1], pub lengths:[u32;E], pub token_distances:[u32;E],
}

pub fn inflate_segment<let N:u32,let P:u32,let T:u32,let B:u32,let W:u32>(
    index:u32, first:bool, last:bool, cz:Field, sin:Field, sout:Field, cp:Field, previous:[Field;W],
    salt:Field, data:[u8;N], data_len:u32, incoming:State,
    resumed_l:Huffman<288>, resumed_d:Huffman<32>,
    headers:[BlockHint;B], header_count:u32, events:[Event;T+B], event_count:u32,
    hints:SegmentHints<T+B,B>, history:[[u8;P];W], plain:[u8;P], plain_len:u32, owners:[u32;P],
) {
    assert(N>=6 & N<=8192 & P>0 & P<=8192 & T>0 & T<=6144 & B>0 & B<=4);
    assert_eq(W,(32768+P-1)/P);
    assert(index<=40960/P & plain_len<=P);
    assert_eq(first,index==0);
    assert(data_len>=6 & data_len<=N);
    assert_eq(commit_bytes(1,salt,data,data_len),cz);
    // Recheck the immutable header on all segments, including the window limit.
    assert_eq(data[0]&15,8); assert(data[0]>>4<=7);
    assert_eq(data[1]&32,0);
    assert_eq(((data[0] as u32)*256+data[1] as u32)%31,0);
    let window=1u32<<((data[0] as u32>>4)+8);
    let limit=(data_len-4)*8;
    let mut s = incoming;
    if first { s=initial_state(); assert_eq(sin,0); }
    else { assert_eq(state_commit(salt,incoming),sin); }
    assert_eq(s.output,index*P);
    assert(s.output<=40960 & s.tokens<=6144 & s.blocks<=4);
    assert(s.phase<2 & s.kind<3 & s.pos>=16 & s.pos<=limit);
    assert(s.a<65521 & s.b<65521 & s.pending_len<=257);
    assert(((s.pending_len==0) & (s.pending_dist==0))
        | (s.pending_len>0 & s.pending_dist>0 & s.pending_dist<=window & s.pending_dist<=s.output));
    if s.pending_len>0 { assert_eq(s.phase,1); assert(s.kind>0); }
    if (s.phase==1) & (s.kind>0) { assert_eq(table_commit(salt,resumed_l,resumed_d),s.table_commitment); }
    else { assert_eq(s.table_commitment,0); }
    // Missing history slots have the fixed empty commitment zero and zero bytes.
    let mut source=[0u8;(W+1)*P];
    for w in 0..W {
        if index+ w>=W {
            assert_eq(commit_plain(salt,index+w-W,P,history[w]),previous[w]);
        } else {
            assert_eq(previous[w],0);
            for k in 0..P { assert_eq(history[w][k],0); }
        }
        for k in 0..P { source[w*P+k]=history[w][k]; }
    }
    for k in 0..P { source[W*P+k]=plain[k]; }
    // Source is never written after this point.
    let ll=Huffman {lengths:hints.ll_lengths,codes:hints.ll_codes};
    let dd=Huffman {lengths:hints.dd_lengths,codes:hints.dd_codes};
    for j in 0..288 { assert_eq(ll.lengths[j],resumed_l.lengths[j]); assert_eq(ll.codes[j],resumed_l.codes[j]); }
    for j in 0..32 { assert_eq(dd.lengths[j],resumed_d.lengths[j]); assert_eq(dd.codes[j],resumed_d.codes[j]); }
    assert(header_count<=B & event_count<=T+B);
    let mut bodies=[0u32;B]; let mut kinds=[0u32;B]; let mut finals=[false;B];
    let mut stored_ends=[0u32;B]; let mut commitments=[0;B+1];
    commitments[0]=s.table_commitment;
    for b in 0..B {
        let mut l=Huffman {lengths:[0u8;288],codes:[0u32;288]};
        let mut d=Huffman {lengths:[0u8;32],codes:[0u32;32]};
        if b<header_count {
            let h=headers[b];
            finals[b]=bits(data,limit,h.start,1)==1;
            let kind=bits(data,limit,h.start+1,2); assert(kind<3); kinds[b]=kind;
            let mut pos=h.start+3;
            if kind==0 {
                pos=((pos+7)/8)*8;
                let len=bits(data,limit,pos,16); let complement=bits(data,limit,pos+16,16);
                assert_eq(len^complement,65535); pos+=32;
                stored_ends[b]=pos+len*8; assert(stored_ends[b]<=limit);
            } else if kind==1 { let (a,b)=comptime {fixed_tables()}; l=a; d=b; }
            else { let (a,b,p)=dynamic_tables(data,limit,pos,h); l=a; d=b; pos=p; }
            bodies[b]=pos;
            if kind>0 { commitments[b+1]=table_commit(salt,l,d); }
        }
        for j in 0..288 { assert_eq(ll.lengths[(b+1)*288+j],l.lengths[j]); assert_eq(ll.codes[(b+1)*288+j],l.codes[j]); }
        for j in 0..32 { assert_eq(dd.lengths[(b+1)*32+j],d.lengths[j]); assert_eq(dd.codes[(b+1)*32+j],d.codes[j]); }
    }
    let header_starts=headers.map(|h| h.start);
    let mut slot=0u32; let mut started=0u32; let mut decoded=0u32;
    let mut produced=s.pending_len;
    let mut last_dist=s.pending_dist;
    assert_eq(hints.starts[0],0); assert_eq(hints.ends[0],produced);
    assert_eq(hints.distances[0],s.pending_dist); assert_eq(hints.symbols[0],0);
    let length_base:[u32;29]=[3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
    let length_extra:[u32;29]=[0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
    let distance_base:[u32;30]=[1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
    let distance_extra:[u32;30]=[0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
    for e in 0..(T+B) {
        let event=events[e]; let mut len=0u32; let mut dist=0u32; let mut sym=0u16;
        let before=produced;
        if e<event_count {
            assert(produced<=P & s.phase<2);
            if event.action==1 {
                assert_eq(s.phase,0); assert(started<header_count & s.blocks<4);
                assert_eq(header_starts[started],s.pos);
                s.pos=bodies[started]; s.kind=kinds[started] as u8; s.final_block=finals[started];
                s.stored_end=stored_ends[started]; s.blocks+=1;
                slot=started+1; started+=1; s.phase=1;
                if (s.kind==0) & (s.pos==s.stored_end) { s.phase=if s.final_block {2} else {0}; }
            } else {
                assert_eq(event.action,2); assert_eq(s.phase,1); assert(decoded<T);
                let t=event.token; assert_eq(t.start,s.pos);
                sym=t.symbol; let value=sym as u32;
                let mut encoded:Field=0; let mut consumed=0u32;
                if s.kind==0 { assert(value<256); len=1; encoded=value as Field; consumed=8; }
                else {
                    encoded=checked_code(ll,slot*288,288,value,t.width as u32) as Field;
                    consumed=t.width as u32;
                    if value<256 { len=1; }
                    else if value==256 { s.phase=if s.final_block {2} else {0}; }
                    else {
                        assert(value<=285); let code=value-257;
                        len=hints.lengths[e]; assert(len>=length_base[code]);
                        let extra=len-length_base[code]; let width=length_extra[code];
                        assert(extra<POWERS[width] as u32);
                        encoded+=(extra as Field)*(POWERS[consumed] as Field); consumed+=width;
                        let ds=t.distance_symbol as u32; assert(ds<30);
                        let code=checked_code(dd,slot*32,32,ds,t.distance_width as u32);
                        encoded+=(code as Field)*(POWERS[consumed] as Field); consumed+=t.distance_width as u32;
                        dist=hints.token_distances[e]; assert(dist>=distance_base[ds]);
                        let extra=dist-distance_base[ds]; let width=distance_extra[ds];
                        assert(extra<POWERS[width] as u32);
                        encoded+=(extra as Field)*(POWERS[consumed] as Field); consumed+=width;
                        assert(dist<=window & dist<=s.output+produced);
                    }
                }
                if len>0 { assert(produced<P); }
                let end=t.start+consumed;
                token_window(data,limit,t.start,end,encoded,t.prefix,t.suffix);
                s.pos=end; decoded+=1; s.tokens+=1;
                if s.kind==0 {
                    assert(s.pos<=s.stored_end);
                    if s.pos==s.stored_end { s.phase=if s.final_block {2} else {0}; }
                }
                produced+=len;
                if len>0 { last_dist=dist; }
            }
        } else { assert_eq(event.action,0); }
        assert_eq(hints.starts[e+1],before); assert_eq(hints.ends[e+1],produced);
        assert_eq(hints.distances[e+1],dist); assert_eq(hints.symbols[e+1],sym);
    }
    assert_eq(started,header_count);
    assert(s.tokens<=6144 & s.output+plain_len<=40960);
    assert_eq(plain_len,if produced<P {produced} else {P});
    if !last { assert_eq(plain_len,P); assert(s.phase<2); }
    else { assert_eq(s.phase,2); assert(produced<=P); assert_eq((s.pos+7)/8,data_len-4); }
    s.pending_len=if produced>P {produced-P} else {0};
    s.pending_dist=if s.pending_len>0 {last_dist} else {0};
    s.table_commitment=if (s.phase==1) & (s.kind>0) {commitments[slot]} else {0};
    let mut a=s.a as Field; let mut weighted:Field=0;
    for k in 0..P {
        let byte=if k<plain_len {
            let owner=owners[k]; assert(owner<T+B+1);
            assert(k>=hints.starts[owner] & k<hints.ends[owner]);
            let dist=hints.distances[owner];
            if dist==0 { hints.symbols[owner] as u8 }
            else { assert(dist<=s.output+k & dist<=W*P+k); source[W*P+k-dist] }
        } else {0};
        assert_eq(plain[k],byte);
        a+=plain[k] as Field; weighted+=(k as Field)*(plain[k] as Field);
    }
    let b=(s.b as Field)+(plain_len as Field)*a-weighted;
    s.a=((a as u64)%65521) as u32; s.b=((b as u64)%65521) as u32;
    s.output+=plain_len;
    if last {
        let p=data_len-4;
        let checksum=(data[p] as u32)*16777216+(data[p+1] as u32)*65536+(data[p+2] as u32)*256+data[p+3] as u32;
        assert_eq(s.b*65536+s.a,checksum);
    }
    assert_eq(state_commit(salt,s),sout);
    assert_eq(commit_plain(salt,index,plain_len,plain),cp);
}

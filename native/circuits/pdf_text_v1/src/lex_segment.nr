use crate::commitment::{commit,commit_plain};
use crate::text_plan::{Anchor,Slot,Plan,plan_commit,challenge,check_plan,fingerprint,results_commit};

// Modes: general, comment, literal, hex, name, number, word, less, greater.
pub struct LexState<let A:u32,let C:u32> {
    pub pos:u32, pub mode:u8, pub depth:u32, pub escaped:bool, pub dict:u32,
    pub array:bool, pub closed:bool, pub bt:bool,
    pub font:Field, pub font_len:u32, pub name:Field, pub name_len:u32,
    pub font_fp:Field, pub font_power:Field, pub name_fp:Field, pub name_power:Field,
    pub word:u32, pub word_len:u32, pub long_word:bool,
    pub pending:bool, pub kind:u8, pub raw_fp:Field, pub raw_power:Field, pub raw_len:u32,
    pub strings_fp:Field, pub strings_power:Field, pub strings_len:u32, pub strings:u32,
    pub ops:u32, pub counts:[u32;A], pub ordinals:[u32;A],
    pub values:[Field;C], pub lengths:[u32;C], pub slot:u32, pub field_fp:Field, pub field_len:u32, pub pi:Field, pub r:Field,
}
pub fn initial<let A:u32,let C:u32>(pi:Field,r:Field)->LexState<A,C> {
    LexState {pos:0,mode:0,depth:0,escaped:false,dict:0,array:false,closed:false,bt:false,
        font:0,font_len:0,name:0,name_len:0,font_fp:0,font_power:1,name_fp:0,name_power:1,word:0,word_len:0,long_word:false,
        pending:false,kind:0,raw_fp:0,raw_power:1,raw_len:0,strings_fp:0,strings_power:1,strings_len:0,strings:0,ops:0,counts:[0;A],ordinals:[0;A],
        values:[0;C],lengths:[0;C],slot:0,field_fp:0,field_len:0,pi,r}
}
pub fn state_commit<let A:u32,let C:u32>(salt:Field,s:LexState<A,C>)->Field {
    let base=[s.pos as Field,s.mode as Field,s.depth as Field,s.escaped as Field,s.dict as Field,
        s.array as Field,s.closed as Field,s.bt as Field,s.font_len as Field,s.name_len as Field,
        s.word as Field,s.word_len as Field,s.long_word as Field,s.pending as Field,s.kind as Field,
        s.raw_fp,s.raw_power,s.raw_len as Field,s.ops as Field,s.pi,s.r];
    let mut fields=[0;34+2*A+2*C];
    for i in 0..21 { fields[i]=base[i]; }
    fields[21]=s.font;fields[22]=s.name;fields[23]=s.font_fp;fields[24]=s.font_power;fields[25]=s.name_fp;fields[26]=s.name_power;
    for a in 0..A { fields[27+2*a]=s.counts[a] as Field; fields[28+2*a]=s.ordinals[a] as Field; }
    for c in 0..C { fields[27+2*A+2*c]=s.values[c];fields[28+2*A+2*c]=s.lengths[c] as Field; }
    fields[27+2*A+2*C]=s.slot as Field;fields[28+2*A+2*C]=s.field_fp;fields[29+2*A+2*C]=s.field_len as Field;
    fields[30+2*A+2*C]=s.strings_fp;fields[31+2*A+2*C]=s.strings_power;
    fields[32+2*A+2*C]=s.strings_len as Field;fields[33+2*A+2*C]=s.strings as Field;
    commit(5,salt,fields)
}
struct ScanState {
    mode:u8,
    depth:Field,
    escaped:bool,
    dict:Field,
    array:bool,
    closed:bool,
    bt:bool,
    font:Field,
    font_len:Field,
    name:Field,
    name_len:Field,
    font_fp:Field,
    font_power:Field,
    name_fp:Field,
    name_power:Field,
    word:Field,
    word_len:Field,
    long_word:bool,
    pending:bool,
    kind:u8,
    raw_fp:Field,
    raw_power:Field,
    raw_len:u16,
    strings_fp:Field,
    strings_power:Field,
    strings_len:Field,
    strings:Field,
    r:Field,
}
fn scan_state<let A:u32,let C:u32>(s:LexState<A,C>)->ScanState { ScanState {
    mode:s.mode,
    depth:s.depth as Field,
    escaped:s.escaped,
    dict:s.dict as Field,
    array:s.array,
    closed:s.closed,
    bt:s.bt,
    font:s.font,
    font_len:s.font_len as Field,
    name:s.name,
    name_len:s.name_len as Field,
    font_fp:s.font_fp,
    font_power:s.font_power,
    name_fp:s.name_fp,
    name_power:s.name_power,
    word:s.word as Field,
    word_len:s.word_len as Field,
    long_word:s.long_word,
    pending:s.pending,
    kind:s.kind,
    raw_fp:s.raw_fp,
    raw_power:s.raw_power,
    raw_len:s.raw_len as u16,
    strings_fp:s.strings_fp,
    strings_power:s.strings_power,
    strings_len:s.strings_len as Field,
    strings:s.strings as Field,
    r:s.r,
} }
fn save_scan<let A:u32,let C:u32>(mut s:LexState<A,C>,v:ScanState)->LexState<A,C> {
    s.mode=v.mode;
    s.depth=v.depth as u32;assert_eq(v.depth,s.depth as Field);
    s.escaped=v.escaped;
    s.dict=v.dict as u32;assert_eq(v.dict,s.dict as Field);
    s.array=v.array;
    s.closed=v.closed;
    s.bt=v.bt;
    s.font=v.font;
    s.font_len=v.font_len as u32;assert_eq(v.font_len,s.font_len as Field);
    s.name=v.name;
    s.name_len=v.name_len as u32;assert_eq(v.name_len,s.name_len as Field);
    s.font_fp=v.font_fp;
    s.font_power=v.font_power;
    s.name_fp=v.name_fp;
    s.name_power=v.name_power;
    s.word=v.word as u32;assert_eq(v.word,s.word as Field);
    s.word_len=v.word_len as u32;assert_eq(v.word_len,s.word_len as Field);
    s.long_word=v.long_word;
    s.pending=v.pending;
    s.kind=v.kind;
    s.raw_fp=v.raw_fp;
    s.raw_power=v.raw_power;
    s.raw_len=v.raw_len as u32;
    s.strings_fp=v.strings_fp;
    s.strings_power=v.strings_power;
    s.strings_len=v.strings_len as u32;assert_eq(v.strings_len,s.strings_len as Field);
    s.strings=v.strings as u32;assert_eq(v.strings,s.strings as Field);
    s.r=v.r;
s }
global CLASSES:[[bool;4];256]=[[true,true,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[true,true,false,false],[true,true,false,false],[false,false,false,false],[true,true,false,false],[true,true,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[true,true,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,true,false,false],[false,false,false,false],[false,false,false,false],[false,true,false,false],[false,true,false,false],[false,false,false,false],[false,false,true,false],[false,false,false,false],[false,false,true,false],[false,false,true,false],[false,true,false,false],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,true,true],[false,false,false,false],[false,false,false,false],[false,true,false,false],[false,false,false,false],[false,true,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,true,false,false],[false,false,false,false],[false,true,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,true],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false],[false,false,false,false]];
struct Record { emitted:bool, fp:Field, power:Field, len:Field, index:u32 }
// Each next-state field is selected independently. Aggregate state never enters
// this function, and no branch reassigns a complete state structure.
#[no_predicates]
fn step(mut s:ScanState,b:u8,active:bool)->(ScanState,Record) {
    let cls=CLASSES[b as u32];
    let white=cls[0];let delim=cls[1];let numeric=cls[2];let hex=cls[3];
    let word_end=active & (s.mode==6) & delim;
    let token_end=active & ((s.mode==4)|(s.mode==5)|(s.mode==6)) & delim;
    let w=if s.long_word {0} else {s.word};
    let show=word_end & ((w==0x546a)|(w==0x544a)|(w==39)|(w==34));
    let bt=word_end & (w==0x4254);let et=word_end & (w==0x4554);let tf=word_end & (w==0x5466);
    assert(!word_end | (w!=0x4249));
    assert(!word_end | !s.pending | show);
    assert(!word_end | show | (!s.array & !s.closed));
    assert(!show | (s.bt & (s.font_len!=0) & s.pending & !s.array & (s.dict==0)));
    assert(!show | ((w==0x544a)==s.closed));
    assert(!bt | (!s.bt & (s.dict==0)));
    assert(!et | (s.bt & (s.dict==0)));
    assert(!tf | (s.bt & (s.dict==0) & (s.name_len!=0)));
    let prefix=s.font_len as Field*s.font_power+s.font_fp;
    let header=(prefix*s.r+s.kind as Field)*s.r+s.strings as Field;
    let record=Record {emitted:show,fp:if show {header*s.strings_power+s.strings_fp} else {0},
        power:if show {s.font_power*s.r*s.r*s.r*s.strings_power} else {0},
        len:if show {s.font_len+3+s.strings_len} else {0},index:0};
    let m=if token_end {0} else {s.mode};
    let g=active & (m==0);let literal=active & (m==2);let hx=active & (m==3);
    let less=active & (m==7);let greater=active & (m==8);
    let close_literal=literal & !s.escaped & (b==41) & (s.depth==1);
    let open_dict=less & (b==60);let start_hex=less & (b!=60);
    let close_hex=(hx|start_hex) & (b==62);
    let close=close_literal|close_hex;
    let start_literal=g & (b==40);let begin=start_literal|start_hex;
    let kind=if start_hex {1u8} else {0u8};
    let pending=s.pending & !show;
    let closed=s.closed & !show;
    let array_open=g & (b==91);let array_close=g & (b==93);let name_start=g & (b==47);
    assert(!active | (m<=8));
    assert(!begin | ((s.bt|bt) & !et & (s.dict==0) & !closed));
    assert(!begin | !pending | (s.kind==kind));
    assert(!open_dict | (!pending & !s.array));
    assert(!greater | ((b==62) & (s.dict!=0)));
    assert(!array_open | (!s.array & !closed & !pending & (s.dict==0)));
    assert(!array_close | (s.array & (s.dict==0)));
    assert(!name_start | (!pending & !closed));
    assert(!g | (b!=41));
    assert(!(hx|start_hex) | (b==62) | hex | white);
    assert(!(active & (m==5)) | numeric);
    let take=(literal & !close_literal)|((hx|start_hex) & (b!=62));
    let name_byte=active & (m==4);
    let word_byte=active & (m==6);
    let word_start=g & !white & !delim & !numeric;
    let grow_word=word_byte & (s.word_len!=3);
    assert(!name_byte | (s.name_len!=16));
    let depth_add=literal & !s.escaped & (b==40);
    let depth_sub=literal & !s.escaped & (b==41);
    assert(!depth_sub | (s.depth!=0));
    s.depth=if start_literal {1} else {s.depth+(depth_add as Field)-(depth_sub as Field)};
    s.dict=s.dict+(open_dict as Field)-(greater as Field);

    s.escaped=if literal { !s.escaped & (b==92) } else {s.escaped};
    s.array=if array_open {true} else if array_close {false} else {s.array};
    s.closed=if array_close {true} else {closed};
    s.bt=if bt {true} else if et {false} else {s.bt};
    s.font=if bt {0} else if tf {s.name} else {s.font};
    s.font_len=if bt {0} else if tf {s.name_len} else {s.font_len};
    s.font_fp=if bt {0} else if tf {s.name_fp} else {s.font_fp};
    s.font_power=if bt {1} else if tf {s.name_power} else {s.font_power};
    s.name=if name_start {0} else if name_byte {s.name*256+b as Field} else {s.name};
    s.name_fp=if name_start {0} else if name_byte {s.name_fp*s.r+b as Field} else {s.name_fp};
    s.name_power=if name_start {1} else if name_byte {s.name_power*s.r} else {s.name_power};
    s.name_len=if name_start {0} else {s.name_len+(name_byte as Field)};
    s.word=if word_start {b as Field} else if word_end {0} else if grow_word {s.word*256+b as Field} else {s.word};
    s.word_len=if word_start {1} else if word_end {0} else {s.word_len+(grow_word as Field)};
    s.long_word=if word_start|word_end {false} else {s.long_word|(word_byte & !grow_word)};
    s.pending=pending|begin;s.kind=if begin {kind} else if show {0} else {s.kind};
    let string_fp=((s.raw_len/256) as Field*s.r+(s.raw_len%256) as Field)*s.raw_power+s.raw_fp;
    let string_power=s.raw_power*s.r*s.r;
    s.strings_fp=if show {0} else if close {s.strings_fp*string_power+string_fp} else {s.strings_fp};
    s.strings_power=if show {1} else if close {s.strings_power*string_power} else {s.strings_power};
    s.strings_len=if show {0} else {s.strings_len+if close {s.raw_len as Field+2} else {0}};
    assert(!close | (s.strings!=255));
    s.strings=if show {0} else {s.strings+(close as Field)};

    s.raw_fp=if close {0} else if take {s.raw_fp*s.r+b as Field} else {s.raw_fp};
    s.raw_power=if close {1} else if take {s.raw_power*s.r} else {s.raw_power};
    s.raw_len=if close {0} else {s.raw_len+(take as u16)};
    let general_mode=if white|array_open|array_close {0u8} else if b==37 {1} else if start_literal {2}
        else if b==60 {7} else if b==62 {8} else if name_start {4} else if numeric {5} else {6};
    s.mode=if g {general_mode} else if close|open_dict|greater|(active & (m==1) & ((b==10)|(b==13))) {0}
        else if start_hex {3} else {m};
    (s,record)
}
#[no_predicates]
pub fn lex_segment<let K:u32,let P:u32,let M:u32,let A:u32,let C:u32,let Q:u32,let R:u32,let O:u32>(
    index:u32,first:bool,last:bool,cz:Field,lin:Field,lout:Field,cp:[Field;K],
    anchors:[Anchor<R>;A],slots:[Slot;C],cg:Field,salt:Field,
    plain:[[u8;P];K],lengths:[u32;K],incoming:LexState<A,C>,plan:Plan<A,C,Q>,positions:[u32;O],used:u32) {
    assert(K>0 & P>0 & P<=8192 & M>0 & M<=512 & A>0 & C>0 & Q<=65535 & R<=65535);
    assert_eq(first,index==0); assert(index*K*P<=40960);
    check_plan(plan,anchors,slots,M);
    let pi=plan_commit(salt,plan); let r=challenge(cz,pi,anchors,slots);
    let mut s=if first {initial(pi,r)} else {incoming};
    if first { assert_eq(lin,0); } else { assert_eq(state_commit(salt,s),lin); }
    assert_eq(s.pi,pi); assert_eq(s.r,r); assert_eq(s.pos,index*K*P);
    let mut anchor_fp=[0;A];
    for a in 0..A {
        if anchors[a].enabled {
            let (fp,_)=fingerprint(anchors[a].raw,anchors[a].len,r);anchor_fp[a]=fp;
        }
    }
    // Project all private plan-index lookups once, before the byte loop.
    // These arrays are never written after construction.
    let mut begins=[0u32;C+1];let mut ends=[0u32;C+1];let mut next_slot=[C;C+1];
    let mut next=C;
    for i in 0..C {
        let c=C-1-i;
        begins[c]=plan.anchor_ops[slots[c].before];ends[c]=plan.anchor_ops[slots[c].after];
        if slots[c].enabled {next=c;} next_slot[c]=next;
    }
    if first {s.slot=next_slot[0];}
    assert(s.slot<=C & s.field_len<=Q);
    // These invariants are established at the initial state and preserved by
    // every byte transition. Checking them at phase boundaries avoids repeated
    // range comparisons without allowing a larger accepted stream.
    assert(s.depth<=s.pos & s.dict<=s.pos & s.raw_len<=s.pos);
    assert(s.strings<=255 & s.strings_len+s.raw_len<=s.pos+2*s.strings);
    let mut scan=scan_state(s);
    let mut emitted=[false;K*P];let mut fps=[0;K*P];let mut powers=[0;K*P];let mut sizes=[0;K*P];
    let mut total=0u32;let mut ended=false;
    for k in 0..K {
        let n=lengths[k];assert(n<=P);
        if cp[k]==0 {
            assert(last);assert_eq(n,0);for i in 0..P {assert_eq(plain[k][i],0);}ended=true;
        } else {
            assert(!ended);assert_eq(commit_plain(salt,index*K+k,n,plain[k]),cp[k]);
            if n<P {assert(last);ended=true;}
        }
        for i in 0..P {
            let (next,record)=step(scan,plain[k][i],i<n);scan=next;
            emitted[k*P+i]=record.emitted;fps[k*P+i]=record.fp;powers[k*P+i]=record.power;sizes[k*P+i]=record.len;
            total+=record.emitted as u32;
        }
        s.pos+=n;
    }
    assert(s.pos<=40960);
    // These four scan arrays are frozen before the first private-position read.
    assert(used<=O);assert_eq(used,total);assert(s.ops+used<=M);
    let base=s.ops;let mut previous=0u32;
    for o in 0..O {
        let active=o<used;let p=positions[o];assert(p<K*P);
        assert(!active | emitted[p]);assert(!active | (o==0) | (p>previous));
        if !active {assert_eq(p,0);}
        let record=Record {emitted:active,fp:if active {fps[p]} else {0},power:if active {powers[p]} else {0},
            len:if active {sizes[p]} else {0},index:base+o};
        s=accumulate(s,record,anchors,slots,plan,anchor_fp,begins,ends,next_slot);
        previous=p;
    }
    s.ops=base+used;
    // Always call the constrained scanner; its explicit active input guards EOF.
    let flush=last & ((scan.mode==4)|(scan.mode==5)|(scan.mode==6)|(scan.mode==1));
    let (next,record)=step(scan,10,flush);scan=next;assert(!record.emitted);
    s=save_scan(s,scan);
    assert(s.depth<=s.pos & s.dict<=s.pos & s.raw_len<=s.pos);
    assert(s.strings_len+s.raw_len<=s.pos+2*s.strings);
    if last {
        assert_eq(s.mode,0); assert(!s.pending & !s.bt & !s.array & !s.closed & (s.dict==0));
        for a in 0..A {
            if anchors[a].enabled { assert(s.ordinals[a]>0); }
            assert_eq(s.ordinals[a],anchors[a].ordinal); assert_eq(s.counts[a],anchors[a].total);
        }
        assert_eq(s.slot,C);assert_eq(s.field_fp,0);assert_eq(s.field_len,0);
        for c in 0..C {assert_eq(s.lengths[c],plan.lengths[c]);}
        assert_eq(results_commit(salt,s.values,s.lengths),cg);
    } else { assert_eq(cg,0); }
    assert_eq(state_commit(salt,s),lout);
}

// Aggregation runs only once per operator slot, after the scan arrays freeze.
#[no_predicates]
fn accumulate<let A:u32,let C:u32,let Q:u32,let R:u32>(mut s:LexState<A,C>,record:Record,
    anchors:[Anchor<R>;A],_slots:[Slot;C],plan:Plan<A,C,Q>,anchor_fp:[Field;A],begins:[u32;C+1],ends:[u32;C+1],next_slot:[u32;C+1])->LexState<A,C> {
    for a in 0..A {
        let equal=(record.fp==anchor_fp[a]) & (record.len==anchors[a].len as Field);
        let matching=record.emitted & anchors[a].enabled & equal;
        s.counts[a]+=matching as u32;
        if record.emitted & anchors[a].enabled & (record.index==plan.anchor_ops[a]) {
            assert(equal);s.ordinals[a]=s.counts[a];
        }
    }
    assert(s.slot<=C);
    let current=s.slot;
    let inside=record.emitted & (current<C) & (record.index>begins[current]) & (record.index<ends[current]);
    if inside {s.field_fp=s.field_fp*record.power+record.fp;}
    assert_eq(record.len,(record.len as u32) as Field);
    s.field_len+=if inside {record.len as u32} else {0};assert(s.field_len<=Q);
    let closing=record.emitted & (current<C) & (record.index==ends[current]);
    for c in 0..C {
        if closing & (current==c) {s.values[c]=s.field_fp;s.lengths[c]=s.field_len;}
    }
    if closing {s.slot=next_slot[current+1];s.field_fp=0;s.field_len=0;}

    s
}

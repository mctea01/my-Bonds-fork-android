use crate::commitment::{commit,commit_plain};
use crate::text_plan::{Anchor,Slot,Plan,plan_commit,challenge,check_plan,fingerprint,record_header,results_commit};

// Modes: general, comment, literal, hex, name, number, word, less, greater.
pub struct LexState<let A:u32,let C:u32> {
    pub pos:u32, pub mode:u8, pub depth:u32, pub escaped:bool, pub dict:u32,
    pub array:bool, pub closed:bool, pub bt:bool,
    pub font:Field, pub font_len:u32, pub name:Field, pub name_len:u32,
    pub font_fp:Field, pub font_power:Field, pub name_fp:Field, pub name_power:Field,
    pub word:u32, pub word_len:u32, pub long_word:bool,
    pub pending:bool, pub kind:u8, pub raw_fp:Field, pub raw_power:Field, pub raw_len:u32,
    pub ops:u32, pub counts:[u32;A], pub ordinals:[u32;A],
    pub values:[Field;C], pub lengths:[u32;C], pub slot:u32, pub field_fp:Field, pub field_len:u32, pub pi:Field, pub r:Field,
}
pub fn initial<let A:u32,let C:u32>(pi:Field,r:Field)->LexState<A,C> {
    LexState {pos:0,mode:0,depth:0,escaped:false,dict:0,array:false,closed:false,bt:false,
        font:0,font_len:0,name:0,name_len:0,font_fp:0,font_power:1,name_fp:0,name_power:1,word:0,word_len:0,long_word:false,
        pending:false,kind:0,raw_fp:0,raw_power:1,raw_len:0,ops:0,counts:[0;A],ordinals:[0;A],
        values:[0;C],lengths:[0;C],slot:0,field_fp:0,field_len:0,pi,r}
}
pub fn state_commit<let A:u32,let C:u32>(salt:Field,s:LexState<A,C>)->Field {
    let base=[s.pos as Field,s.mode as Field,s.depth as Field,s.escaped as Field,s.dict as Field,
        s.array as Field,s.closed as Field,s.bt as Field,s.font_len as Field,s.name_len as Field,
        s.word as Field,s.word_len as Field,s.long_word as Field,s.pending as Field,s.kind as Field,
        s.raw_fp,s.raw_power,s.raw_len as Field,s.ops as Field,s.pi,s.r];
    let mut fields=[0;30+2*A+2*C];
    for i in 0..21 { fields[i]=base[i]; }
    fields[21]=s.font;fields[22]=s.name;fields[23]=s.font_fp;fields[24]=s.font_power;fields[25]=s.name_fp;fields[26]=s.name_power;
    for a in 0..A { fields[27+2*a]=s.counts[a] as Field; fields[28+2*a]=s.ordinals[a] as Field; }
    for c in 0..C { fields[27+2*A+2*c]=s.values[c];fields[28+2*A+2*c]=s.lengths[c] as Field; }
    fields[27+2*A+2*C]=s.slot as Field;fields[28+2*A+2*C]=s.field_fp;fields[29+2*A+2*C]=s.field_len as Field;
    commit(5,salt,fields)
}
fn whitespace(b:u8)->bool { (b==0)|(b==9)|(b==10)|(b==12)|(b==13)|(b==32) }
fn delimiter(b:u8)->bool { whitespace(b)|(b==37)|(b==40)|(b==41)|(b==60)|(b==62)|(b==91)|(b==93)|(b==47) }
fn digit(b:u8)->bool { (b>=48)&(b<=57) }
fn numeric(b:u8)->bool { digit(b)|(b==43)|(b==45)|(b==46) }
fn hex(b:u8)->bool { digit(b)|((b>=65)&(b<=70))|((b>=97)&(b<=102)) }
fn raw<let A:u32,let C:u32>(mut s:LexState<A,C>,b:u8)->LexState<A,C> {
    assert(s.raw_len<65535); s.raw_fp=s.raw_fp*s.r+b as Field; s.raw_power*=s.r; s.raw_len+=1; s
}
fn begin_string<let A:u32,let C:u32>(mut s:LexState<A,C>,kind:u8)->LexState<A,C> {
    assert(s.bt & (s.dict==0) & !s.closed);
    if s.pending { assert_eq(s.kind,kind); } else { s.kind=kind; s.pending=true; }
    s
}
struct Record { emitted:bool, fp:Field, power:Field, len:u32, index:u32 }
fn no_record()->Record {Record {emitted:false,fp:0,power:1,len:0,index:0}}
fn finish_word<let A:u32,let C:u32>(mut s:LexState<A,C>,max_ops:u32)->(LexState<A,C>,Record) {
    let mut record=no_record();
    let w=if s.long_word {0} else {s.word};
    let show=(w==0x546a)|(w==0x544a)|(w==39)|(w==34);
    assert(w!=0x4249); // BI is forbidden outside strings/comments/names.
    if s.pending { assert(show); }
    if show {
        assert(s.bt & (s.font_len>0) & s.pending & !s.array & (s.dict==0));
        assert_eq(w==0x544a,s.closed);
        assert(s.ops<max_ops);
        assert(s.font_len<=16 & s.kind<=1 & s.raw_len<=65535);
        let prefix=(s.font_len as Field)*s.font_power+s.font_fp;
        let header=((prefix*s.r+s.kind as Field)*s.r+(s.raw_len/256) as Field)*s.r+(s.raw_len%256) as Field;
        let hp=s.font_power*s.r*s.r*s.r*s.r;
        let fp=header*s.raw_power+s.raw_fp; let power=hp*s.raw_power;
        let len=s.font_len+4+s.raw_len;
        record=Record {emitted:true,fp,power,len,index:s.ops};
        s.ops+=1; s.pending=false; s.closed=false; s.raw_fp=0; s.raw_power=1; s.raw_len=0; s.kind=0;
    } else {
        assert(!s.array & !s.closed);
        if w==0x4254 { assert(!s.bt & (s.dict==0)); s.bt=true; s.font=0;s.font_len=0;s.font_fp=0;s.font_power=1; }
        if w==0x4554 { assert(s.bt & (s.dict==0)); s.bt=false; }
        if w==0x5466 { assert(s.bt & (s.dict==0) & (s.name_len>0)); s.font=s.name;s.font_len=s.name_len;s.font_fp=s.name_fp;s.font_power=s.name_power; }
    }
    s.word=0; s.word_len=0; s.long_word=false; s.mode=0; (s,record)
}
// One deterministic byte transition, including delimiter reprocessing after
// a name/number/operator ends. No operator-position advice exists.
fn step<let A:u32,let C:u32>(mut s:LexState<A,C>,b:u8,max_ops:u32)->(LexState<A,C>,Record) {
    let mut record=no_record();
    let end=delimiter(b);
    if ((s.mode==4)|(s.mode==5)|(s.mode==6)) & end {
        if s.mode==6 { let (next,emitted)=finish_word(s,max_ops);s=next;record=emitted; }
        else { s.mode=0; }
    }
    let m=s.mode;assert(m<=8);
    let mut take=false; let mut begin=false; let mut new_kind=0u8;
    if m==1 { if (b==10)|(b==13) {s.mode=0;} }
    if m==2 {
        take=true;
        if s.escaped {s.escaped=false;}
        else if b==92 {s.escaped=true;}
        else if b==40 {s.depth+=1;assert(s.depth<=40960);}
        else if b==41 {assert(s.depth>0);s.depth-=1;if s.depth==0 {s.mode=0;take=false;}}
    }
    if m==3 {
        if b==62 {s.mode=0;} else {assert(hex(b)|whitespace(b));take=true;}
    }
    if m==7 {
        if b==60 {assert(!s.pending & !s.array);s.dict+=1;assert(s.dict<=40960);s.mode=0;}
        else {
            begin=true;new_kind=1;s.mode=3;
            if b==62 {s.mode=0;} else {assert(hex(b)|whitespace(b));take=true;}
        }
    }
    if m==8 {assert_eq(b,62);assert(s.dict>0);s.dict-=1;s.mode=0;}
    if m==4 {
        assert(s.name_len<16);
        s.name=s.name*256+b as Field;s.name_fp=s.name_fp*s.r+b as Field;s.name_power*=s.r;
        s.name_len+=1;
    }
    if m==5 {assert(numeric(b));}
    if m==6 {if s.word_len<3 {s.word=s.word*256+b as u32;s.word_len+=1;} else {s.long_word=true;}}
    if m==0 {
        if whitespace(b) {}
        else if b==37 {s.mode=1;}
        else if b==40 {begin=true;s.mode=2;s.depth=1;}
        else if b==60 {s.mode=7;}
        else if b==62 {s.mode=8;}
        else if b==91 {assert(!s.array & !s.closed & !s.pending & (s.dict==0));s.array=true;}
        else if b==93 {assert(s.array & (s.dict==0));s.array=false;s.closed=true;}
        else if b==47 {assert(!s.pending & !s.closed);s.mode=4;s.name=0;s.name_len=0;s.name_fp=0;s.name_power=1;}
        else if b==41 {assert(false);}
        else if numeric(b) {s.mode=5;}
        else {s.mode=6;s.word=b as u32;s.word_len=1;s.long_word=false;}
    }
    if begin {s=begin_string(s,new_kind);}
    // Exactly one raw-byte update, regardless of lexical mode. This avoids
    // duplicating the fingerprint/state multiplexer in every string branch.
    if take {s=raw(s,b);}

    (s,record)
}
pub fn lex_segment<let K:u32,let P:u32,let M:u32,let A:u32,let C:u32,let Q:u32,let R:u32>(
    index:u32,first:bool,last:bool,cz:Field,lin:Field,lout:Field,cp:[Field;K],
    anchors:[Anchor<R>;A],slots:[Slot;C],cg:Field,salt:Field,
    plain:[[u8;P];K],lengths:[u32;K],incoming:LexState<A,C>,plan:Plan<A,C,Q>) {
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
            let x=anchors[a]; let (header,_)=record_header(x.font,x.font_len,x.kind,x.len,r);
            let (fp,power)=fingerprint(x.raw,x.len,r); anchor_fp[a]=header*power+fp;
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
    // Completed anchor fingerprints are immutable before any scan step.
    let mut ended=false;
    for k in 0..K {
        let n=lengths[k]; assert(n<=P);
        if cp[k]==0 {
            assert(last); assert_eq(n,0); for i in 0..P { assert_eq(plain[k][i],0); } ended=true;
        } else {
            assert(!ended); assert_eq(commit_plain(salt,index*K+k,n,plain[k]),cp[k]);
            if n<P { assert(last); ended=true; }
            for i in 0..P {
                if i<n { let (next,record)=step(s,plain[k][i],M);s=accumulate(next,record,anchors,slots,plan,anchor_fp,begins,ends,next_slot); s.pos+=1; assert(s.pos<=40960); }
            }
        }
    }
    if last {
        // EOF delimits a final word/name/number/comment, never a string/dict.
        if (s.mode==4)|(s.mode==5)|(s.mode==6)|(s.mode==1) { let (next,record)=step(s,10,M);s=accumulate(next,record,anchors,slots,plan,anchor_fp,begins,ends,next_slot); }
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

// Aggregation is outside lexical mode dispatch: each integer counter gets one
// checked update per byte. Record events are computed by the scanner, never hints.
fn accumulate<let A:u32,let C:u32,let Q:u32,let R:u32>(mut s:LexState<A,C>,record:Record,
    anchors:[Anchor<R>;A],_slots:[Slot;C],plan:Plan<A,C,Q>,anchor_fp:[Field;A],begins:[u32;C+1],ends:[u32;C+1],next_slot:[u32;C+1])->LexState<A,C> {
    for a in 0..A {
        let equal=record.fp==anchor_fp[a];
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
    s.field_len+=if inside {record.len} else {0};assert(s.field_len<=Q);
    let closing=record.emitted & (current<C) & (record.index==ends[current]);
    for c in 0..C {
        if closing & (current==c) {s.values[c]=s.field_fp;s.lengths[c]=s.field_len;}
    }
    if closing {s.slot=next_slot[current+1];s.field_fp=0;s.field_len=0;}

    s
}

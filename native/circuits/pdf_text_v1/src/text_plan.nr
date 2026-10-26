use crate::commitment::{commit,hash_fields,pack31};

pub struct Anchor<let R:u32> {
    pub enabled:bool, pub font_len:u32, pub font:[u8;16], pub kind:u8,
    pub len:u32, pub raw:[u8;R], pub ordinal:u32, pub total:u32,
}
pub struct Slot { pub enabled:bool, pub before:u32, pub after:u32 }
pub struct Plan<let A:u32,let C:u32,let Q:u32> {
    pub anchor_ops:[u32;A], pub lengths:[u32;C], pub records:[[u8;Q];C],
}
pub fn fingerprint<let N:u32>(bytes:[u8;N],len:u32,r:Field)->(Field,Field) {
    assert(len<=N);
    let mut fp=0; let mut power=1;
    for i in 0..N { if i<len { fp=fp*r+bytes[i] as Field; power*=r; } }
    (fp,power)
}
pub fn record_header(font:[u8;16],font_len:u32,kind:u8,len:u32,r:Field)->(Field,Field) {
    assert(font_len>0 & font_len<=16 & kind<=1 & len<=65535);
    let mut fp=font_len as Field; let mut power=r;
    for i in 0..16 { if i<font_len { fp=fp*r+font[i] as Field; power*=r; } }
    fp=((fp*r+kind as Field)*r+(len/256) as Field)*r+(len%256) as Field;
    (fp,power*r*r*r)
}
pub fn plan_commit<let A:u32,let C:u32,let Q:u32>(salt:Field,p:Plan<A,C,Q>)->Field {
    let mut fields=[0;A+C*(1+(Q+30)/31)];
    for a in 0..A { fields[a]=p.anchor_ops[a] as Field; }
    for c in 0..C {
        assert(p.lengths[c]<=Q);
        for i in 0..Q { if i>=p.lengths[c] { assert_eq(p.records[c][i],0); } }
        let packed=pack31(p.records[c]); let offset=A+c*(1+(Q+30)/31);
        fields[offset]=p.lengths[c] as Field;
        for i in 0..((Q+30)/31) { fields[offset+1+i]=packed[i]; }
    }
    commit(6,salt,fields)
}
// A is a hash of a fixed-width byte serialization. Ordinal/total are outputs,
// excluded from this transcript; all input anchor content and slot ranges bind.
pub fn challenge<let A:u32,let C:u32,let R:u32>(cz:Field,pi:Field,anchors:[Anchor<R>;A],slots:[Slot;C])->Field {
    let mut bytes=[0u8;A*(21+R)+C*9];
    for a in 0..A {
        let x=anchors[a]; let o=a*(21+R);
        assert(x.font_len<=16 & x.kind<=1 & x.len<=R & x.len<=65535);
        if x.enabled { assert(x.font_len>0); }
        else { assert_eq(x.font_len,0); assert_eq(x.kind,0); assert_eq(x.len,0); }
        bytes[o]=x.enabled as u8; bytes[o+1]=x.font_len as u8;
        for i in 0..16 { if i>=x.font_len { assert_eq(x.font[i],0); } bytes[o+2+i]=x.font[i]; }
        bytes[o+18]=x.kind; bytes[o+19]=(x.len/256) as u8; bytes[o+20]=(x.len%256) as u8;
        for i in 0..R { if i>=x.len { assert_eq(x.raw[i],0); } bytes[o+21+i]=x.raw[i]; }
    }
    for c in 0..C {
        let x=slots[c]; let o=A*(21+R)+c*9;
        bytes[o]=x.enabled as u8;
        for j in 0..4 { bytes[o+1+j]=(x.before>>(8*(3-j))) as u8; bytes[o+5+j]=(x.after>>(8*(3-j))) as u8; }
        if !x.enabled { assert_eq(x.before,0); assert_eq(x.after,0); }
    }
    hash_fields([7,cz,pi,hash_fields(pack31(bytes))])
}
pub fn check_plan<let A:u32,let C:u32,let Q:u32,let R:u32>(p:Plan<A,C,Q>,anchors:[Anchor<R>;A],slots:[Slot;C],max_ops:u32) {
    let enabled=anchors.map(|a| a.enabled);
    for a in 0..A { if enabled[a] { assert(p.anchor_ops[a]<max_ops); } else { assert_eq(p.anchor_ops[a],0); } }
    let mut previous_end=0u32; let mut seen=false;
    for c in 0..C {
        let s=slots[c];
        if s.enabled {
            assert(s.before<A & s.after<A); assert(enabled[s.before] & enabled[s.after]);
            let begin=p.anchor_ops[s.before]; let end=p.anchor_ops[s.after]; assert(begin<end);
            if seen { assert(begin>=previous_end); } previous_end=end; seen=true;
        } else { assert_eq(p.lengths[c],0); }
    }
}
pub fn results_commit<let C:u32>(salt:Field,values:[Field;C],lengths:[u32;C])->Field {
    let mut fields=[0;C*2];
    for c in 0..C { fields[c*2]=values[c]; fields[c*2+1]=lengths[c] as Field; }
    commit(8,salt,fields)
}

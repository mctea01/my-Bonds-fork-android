use crate::text_plan::{Anchor,Slot,Plan,plan_commit,challenge,check_plan,fingerprint,results_commit};

pub struct DigitFont { pub enabled:bool, pub len:u32, pub name:[u8;16], pub width:u8, pub digits:[u16;10] }
pub struct Predicate { pub enabled:bool, pub kind:u8, pub slot:u32, pub format:u8, pub cutoff:u32 }
struct DateState { group:u32, count:u32, year:u32, month:u32, day:u32, gap:bool }
fn date_code(mut s:DateState,code:u16,digits:[u16;10],active:bool)->DateState {
    let mut found=false;let mut value=0u32;
    for d in 0..10 {let equal=code==digits[d];found=found|equal;value+=if equal {d} else {0};}
    let take=active & found;
    let advance=take & s.gap & (s.count>0);
    let group=s.group+(advance as u32);
    let count=(if advance {0} else {s.count})+(take as u32);
    assert(!take | ((group<3) & (count<=if group==0 {4} else {2})));
    let separator=active & !found & (s.count>0);
    assert(!separator | (s.group!=0) | (s.count==4));
    s.year=if take & (group==0) {s.year*10+value} else {s.year};
    s.month=if take & (group==1) {s.month*10+value} else {s.month};
    s.day=if take & (group==2) {s.day*10+value} else {s.day};
    s.group=group;s.count=count;s.gap=if advance {false} else {s.gap|separator};s
}
fn is_hex(b:u8)->bool { ((b>=48)&(b<=57))|((b>=65)&(b<=70))|((b>=97)&(b<=102)) }
fn nibble(b:u8)->u8 { assert(is_hex(b)); if b<=57 {b-48} else if b<=70 {b-55} else {b-87} }
fn white(b:u8)->bool { (b==0)|(b==9)|(b==10)|(b==12)|(b==13)|(b==32) }

pub fn date<let Q:u32,let D:u32>(bytes:[u8;Q],len:u32,fonts:[DigitFont;D])->u32 {
    assert(len<=Q & D>0);
    let mut font_names=[0;D];
    for d in 0..D {
        let mut value=0;
        for j in 0..16 {if j<fonts[d].len {value=value*256+fonts[d].name[j] as Field;}}
        font_names[d]=value;
    }
    let digit_tables=fonts.map(|f| f.digits);
    let mut stage=0u8;let mut font_len=0u32;let mut name=0;let mut name_pos=0u32;
    let mut kind=0u8;let mut remaining=0u32;let mut strings=0u32;
    let mut width=0u8;let mut font_index=0u32;
    let mut high=0u16;let mut half=false;let mut hex_high=0u8;let mut hex_half=false;
    let mut escape=0u8;let mut octal=0u32;let mut octal_count=0u32;
    let mut flags1=[false;Q];let mut flags2=[false;Q];
    let mut codes1=[0u16;Q];let mut codes2=[0u16;Q];let mut indices=[0u32;Q];
    for i in 0..Q {
        let active=i<len;let b=bytes[i];
        let start=active & (stage==0);let naming=active & (stage==1);let type_byte=active & (stage==2);
        let count_byte=active & (stage==3);let length_hi=active & (stage==6);let length_lo=active & (stage==4);
        let raw=active & (stage==5);let literal=raw & (kind==0);let hexadecimal=raw & (kind==1);
        let ending=raw & (remaining==1);
        assert(!start | ((b>0)&(b<=16)));assert(!type_byte | (b<=1));assert(!count_byte | (b>0));
        let full_len=remaining+b as u32;
        assert(!length_lo | ((strings>0)&(full_len+i+1<=len)));
        let empty=length_lo & (full_len==0);
        let finished=ending|empty;
        let next_strings=strings-(length_lo as u32);
        let new_name=name*256+b as Field;
        let new_name_pos=name_pos+(naming as u32);
        let mut matched=false;
        for d in 0..D {
            let select=type_byte & fonts[d].enabled & (fonts[d].len==font_len) & (font_names[d]==name);
            matched=matched|select;
            width=if select {fonts[d].width} else {width};font_index=if select {d} else {font_index};
        }
        assert(!type_byte | matched);
        let oct=(b>=48)&(b<=55);
        let flush_previous=literal & (escape==2) & !oct;
        let e=if flush_previous {0u8} else {escape};
        let oct_digit=literal & (e==2) & oct;
        let escaped=literal & (e==1);
        let oct_start=escaped & oct;
        let ordinary=literal & ((e==0)|(e==3)|(e==4));
        let skip=ordinary & ((e==3)|(e==4)) & (b==10);
        let slash=ordinary & !skip & (b==92);
        let plain=ordinary & !skip & (b!=92);
        let mapped=escaped & !oct & (b!=10) & (b!=13);
        let digit=if oct {b as u32-48} else {0};
        let oct_next=if oct_start {digit} else if oct_digit {octal*8+digit} else {octal};
        let oct_count=if oct_start {1} else {octal_count+(oct_digit as u32)};
        let oct_complete=oct_digit & (oct_count==3);
        let hex_digit=hexadecimal & !white(b);
        assert(!hex_digit | is_hex(b));
        let n=if hex_digit {nibble(b)} else {0};
        let pair=hex_digit & hex_half;
        let hh=if hex_digit {!hex_half} else {hex_half};
        let hv=if hex_digit & !hex_half {n} else {hex_high};
        let escaped_value=if b==110 {10u8} else if b==114 {13} else if b==116 {9} else if b==98 {8} else if b==102 {12} else {b};
        let out=plain|mapped|oct_complete|pair;
        let value=if pair {hex_high*16+n} else if oct_complete {(oct_next%256) as u8}
            else if mapped {escaped_value} else if b==13 {10} else {b};
        let next_escape=if oct_start|(oct_digit & !oct_complete) {2u8} else if escaped & (b==13) {3}
            else if slash {1} else if plain & (b==13) {4} else if literal {0} else {escape};
        let flush_hex=ending & (kind==1) & hh;
        let flush_octal=ending & (kind==0) & (next_escape==2);
        let flush=flush_hex|flush_octal;
        let flush_byte=if flush_hex {hv*16} else {(oct_next%256) as u8};
        let first=flush_previous|out|flush;
        let second=(flush_previous & out)|((flush_previous|out)&flush);
        assert(!(flush_previous & out & flush));
        let byte1=if flush_previous {(octal%256) as u8} else if out {value} else {flush_byte};
        let byte2=if flush {flush_byte} else {value};
        let code1=if width==1 {byte1 as u16} else {high*256+byte1 as u16};
        let has1=first & ((width==1)|half);
        let half1=if first {(width==2)&!half} else {half};
        let high1=if first & (width==2) & !half {byte1 as u16} else {high};
        let code2=if width==1 {byte2 as u16} else {high1*256+byte2 as u16};
        let has2=second & ((width==1)|half1);
        let half2=if second {(width==2)&!half1} else {half1};
        let high2=if second & (width==2) & !half1 {byte2 as u16} else {high1};
        assert(!finished | !half2);assert(!ending | (next_escape!=1));
        flags1[i]=has1;flags2[i]=has2;codes1[i]=code1;codes2[i]=code2;indices[i]=font_index;
        high=if finished {0} else {high2};half=if finished {false} else {half2};
        hex_high=if finished {0} else {hv};hex_half=if finished {false} else {hh};
        escape=if finished {0} else {next_escape};octal=if finished {0} else {oct_next};octal_count=if finished {0} else {oct_count};
        name=if start {0} else if naming {new_name} else {name};name_pos=if start {0} else {new_name_pos};
        font_len=if start {b as u32} else {font_len};kind=if type_byte {b} else {kind};
        strings=if count_byte {b as u32} else {next_strings};
        remaining=if length_hi {b as u32*256} else if length_lo {full_len} else {remaining-(raw as u32)};
        stage=if start {1} else if naming & (new_name_pos==font_len) {2} else if type_byte {3}
            else if count_byte {6} else if length_hi {4} else if finished {if next_strings==0 {0} else {6}}
            else if length_lo {5} else {stage};
    }
    let mut s=DateState {group:0,count:0,year:0,month:0,day:0,gap:false};
    // Source decoding is complete before date accumulation. Input font tables
    // and emitted arrays are immutable throughout these private reads.
    for i in 0..Q {
        let digits=digit_tables[indices[i]];
        s=date_code(s,codes1[i],digits,flags1[i]);
        s=date_code(s,codes2[i],digits,flags2[i]);
    }
    assert_eq(stage,0); assert_eq(s.group,2); assert(s.count>0 & s.year>0 & s.year<=9999 & s.month>0 & s.month<=12 & s.day>0);
    let leap=(s.year%4==0)&((s.year%100!=0)|(s.year%400==0));
    let days=if s.month==2 {if leap {29} else {28}} else if (s.month==4)|(s.month==6)|(s.month==9)|(s.month==11) {30} else {31};
    assert(s.day<=days); s.year*10000+s.month*100+s.day
}
pub fn sha_claim<let Q:u32>(slot:u8,salt:[u8;16],bytes:[u8;Q],len:u32)->[u8;32] {
    assert(len<=Q & len<=65535);
    let mut message=[0u8;((Q+37+9+63)/64)*64];
    let domain:[u8;18]=[100,105,119,45,122,107,112,100,102,45,99,108,97,105,109,45,118,49];
    for i in 0..18 { message[i]=domain[i]; } message[18]=slot;
    for i in 0..16 { message[19+i]=salt[i]; }
    message[35]=(len/256) as u8; message[36]=(len%256) as u8;
    for i in 0..Q { if i>=len {assert_eq(bytes[i],0);} message[37+i]=bytes[i]; }
    message[37+Q]=128;
    for j in 0..8 { message[((Q+37+9+63)/64)*64-8+j]=(((Q+37) as u64*8)>>((8*(7-j)) as u64)) as u8; }
    let mut state=[0x6a09e667u32,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for b in 0..((Q+37+9+63)/64) {
        let mut words=[0u32;16];
        for w in 0..16 { let o=b*64+w*4; words[w]=(message[o] as u32)*16777216+(message[o+1] as u32)*65536+(message[o+2] as u32)*256+message[o+3] as u32; }
        state=std::hash::sha256_compression(words,state);
    }
    let mut digest=[0u8;32];
    for i in 0..8 { for j in 0..4 { digest[i*4+j]=(state[i]>>(8*(3-j))) as u8; } } digest
}
pub fn bind_plan<let A:u32,let C:u32,let Q:u32,let R:u32>(
    cz:Field,anchors:[Anchor<R>;A],slots:[Slot;C],cg:Field,salt:Field,plan:Plan<A,C,Q>) {
    check_plan(plan,anchors,slots,512);
    let pi=plan_commit(salt,plan); let r=challenge(cz,pi,anchors,slots);
    let mut values=[0;C];
    for c in 0..C { let (fp,_)=fingerprint(plan.records[c],plan.lengths[c],r); values[c]=fp; }
    assert_eq(results_commit(salt,values,plan.lengths),cg);
}
pub fn claim<let A:u32,let C:u32,let Q:u32,let R:u32,let START:u32,let COUNT:u32>(
    cz:Field,anchors:[Anchor<R>;A],slots:[Slot;C],cg:Field,digests:[[u8;32];COUNT],
    salt:Field,plan:Plan<A,C,Q>,claim_salts:[[u8;16];COUNT]) {
    assert(START+COUNT<=C & COUNT>0 & C<=256);
    bind_plan(cz,anchors,slots,cg,salt,plan);
    for j in 0..COUNT {
        let c=START+j;
        if slots[c].enabled { assert_eq(sha_claim(c as u8,claim_salts[j],plan.records[c],plan.lengths[c]),digests[j]); }
        else { assert_eq(digests[j],[0;32]); }
    }
}
pub fn pred<let A:u32,let C:u32,let Q:u32,let R:u32,let D:u32,let V:u32>(
    cz:Field,anchors:[Anchor<R>;A],slots:[Slot;C],cg:Field,fonts:[DigitFont;D],predicates:[Predicate;V],
    salt:Field,plan:Plan<A,C,Q>) {
    assert(V<=2);
    bind_plan(cz,anchors,slots,cg,salt,plan);
    for d in 0..D {
        let f=fonts[d]; assert(f.len<=16);
        if f.enabled {assert(f.len>0 & ((f.width==1)|(f.width==2)));}
        else {assert_eq(f.len,0);assert_eq(f.width,0);}
        for i in 0..16 {if i>=f.len {assert_eq(f.name[i],0);}}
        for i in 0..10 {
            if !f.enabled {assert_eq(f.digits[i],0);} else {
                if f.width==1 {assert(f.digits[i]<=255);}
                for j in 0..10 {if i<j {assert(f.digits[i]!=f.digits[j]);}}
            }
        }
        for e in 0..D { if (d<e)&f.enabled&fonts[e].enabled { assert((f.len!=fonts[e].len)|(f.name!=fonts[e].name)); } }
    }
    for v in 0..V { if predicates[v].enabled { assert(predicates[v].slot<C & predicates[v].kind<=1); assert_eq(predicates[v].format,0); } }
    let enabled=slots.map(|s| s.enabled);
    // Select immutable input records once per predicate, rather than duplicating
    // the complete decoder for every possible claim slot.
    for v in 0..V {
        let p=predicates[v];
        if p.enabled {
            assert(enabled[p.slot]);
            let value=date(plan.records[p.slot],plan.lengths[p.slot],fonts);
            if p.kind==0 {assert(value<=p.cutoff);} else {assert(value>=p.cutoff);}
        }
    }
}

#[test]
fn sha_claim_known_answer() {
    let bytes=[65u8,66,0,0];
    assert_eq(sha_claim(3,[9;16],bytes,2),[56, 42, 223, 191, 119, 28, 197, 97, 164, 149, 12, 179, 218, 144, 208, 9, 83, 157, 228, 147, 243, 188, 55, 201, 160, 90, 126, 167, 193, 50, 145, 245]);
}

fn test_fonts(width:u8)->[DigitFont;1] {
    [DigitFont {enabled:true,len:1,name:[70,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],width,
        digits:[48,49,50,51,52,53,54,55,56,57]}]
}

#[test]
fn date_ascii() {
    let bytes:[u8;14]=[1, 70, 0, 1, 0, 8, 50, 48, 50, 48, 45, 49, 45, 50];
    assert_eq(date(bytes,14,test_fonts(1)),20200102);
}

#[test]
fn date_octal() {
    let bytes:[u8;22]=[1, 70, 0, 1, 0, 16, 50, 48, 50, 48, 92, 48, 53, 53, 48, 49, 92, 48, 53, 53, 48, 50];
    assert_eq(date(bytes,22,test_fonts(1)),20200102);
}

#[test]
fn date_short_octal() {
    let bytes:[u8;20]=[1, 70, 0, 1, 0, 14, 50, 48, 50, 48, 92, 53, 53, 48, 49, 92, 53, 53, 48, 50];
    assert_eq(date(bytes,20,test_fonts(1)),20200102);
}

#[test]
fn date_identity_hex() {
    let bytes:[u8;46]=[1, 70, 1, 1, 0, 40, 48, 48, 51, 50, 48, 48, 51, 48, 48, 48, 51, 50, 48, 48, 51, 48, 48, 48, 50, 100, 48, 48, 51, 48, 48, 48, 51, 49, 48, 48, 50, 100, 48, 48, 51, 48, 48, 48, 51, 50];
    assert_eq(date(bytes,46,test_fonts(2)),20200102);
}

#[test(should_fail)]
fn rejects_invalid_calendar_date() {
    let bytes:[u8;16]=[1, 70, 0, 1, 0, 10, 50, 48, 50, 49, 45, 48, 50, 45, 50, 57];
    assert_eq(date(bytes,16,test_fonts(1)),20210229);
}

#[test(should_fail)]
fn rejects_extra_date_digits() {
    let bytes:[u8;16]=[1, 70, 0, 1, 0, 10, 50, 48, 50, 48, 45, 49, 45, 50, 32, 51];
    assert_eq(date(bytes,16,test_fonts(1)),20200102);
}

#[test]
fn date_v2_octal_boundary() {
    let bytes:[u8;21]=[1,70,0,3,0,8,50,48,50,48,45,48,49,45,0,2,92,55,0,1,49];
    assert_eq(date(bytes,21,test_fonts(1)),20200101);
}

#[test(should_fail)]
fn rejects_v2_identity_odd_string() {
    let bytes:[u8;48]=[1,70,1,2,0,2,48,48,0,38,51,50,48,48,51,48,48,48,51,50,48,48,51,48,48,48,50,68,48,48,51,48,48,48,51,49,48,48,50,68,48,48,51,48,48,48,51,49];
    assert_eq(date(bytes,48,test_fonts(2)),20200101);
}

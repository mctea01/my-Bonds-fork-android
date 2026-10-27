use crate::text_plan::{Anchor,Slot,Plan,plan_commit,challenge,check_plan,fingerprint,results_commit};

pub struct DigitFont { pub enabled:bool, pub len:u32, pub name:[u8;16], pub width:u8, pub digits:[u16;10] }
pub struct Predicate { pub enabled:bool, pub kind:u8, pub slot:u32, pub format:u8, pub cutoff:u32 }
struct DateState { group:u32, count:u32, year:u32, month:u32, day:u32, gap:bool }
fn date_code(mut s:DateState,code:u16,digits:[u16;10])->DateState {
    let mut found=false; let mut value=0u32;
    for d in 0..10 { if code==digits[d] { assert(!found); found=true; value=d; } }
    if found {
        if s.gap & (s.count>0) { s.group+=1; s.count=0; s.gap=false; }
        assert(s.group<3); s.count+=1;
        if s.group==0 { assert(s.count<=4); s.year=s.year*10+value; }
        else if s.group==1 { assert(s.count<=2); s.month=s.month*10+value; }
        else { assert(s.count<=2); s.day=s.day*10+value; }
    } else if s.count>0 {
        if s.group==0 { assert_eq(s.count,4); }
        s.gap=true;
    }
    s
}
fn emit(s:DateState,byte:u8,width:u8,high:u16,half:bool,digits:[u16;10])->(DateState,u16,bool) {
    if width==1 { (date_code(s,byte as u16,digits),0,false) }
    else if half { (date_code(s,high*256+byte as u16,digits),0,false) }
    else { (s,byte as u16,true) }
}
fn is_hex(b:u8)->bool { ((b>=48)&(b<=57))|((b>=65)&(b<=70))|((b>=97)&(b<=102)) }
fn nibble(b:u8)->u8 { assert(is_hex(b)); if b<=57 {b-48} else if b<=70 {b-55} else {b-87} }
fn white(b:u8)->bool { (b==0)|(b==9)|(b==10)|(b==12)|(b==13)|(b==32) }

pub fn date<let Q:u32,let D:u32>(bytes:[u8;Q],len:u32,fonts:[DigitFont;D])->u32 {
    assert(len<=Q);
    let mut cursor=0u32; let mut stage=0u8; let mut font_len=0u32; let mut name=[0u8;16];
    let mut name_pos=0u32; let mut kind=0u8; let mut remaining=0u32;
    let mut strings=0u32;
    let mut width=0u8; let mut digits=[0u16;10];
    let mut high=0u16; let mut half=false; let mut hex_high=0u8; let mut hex_half=false;
    let mut escape=0u8; let mut octal=0u32; let mut octal_count=0u32;
    let mut s=DateState {group:0,count:0,year:0,month:0,day:0,gap:false};
    for i in 0..Q {
        if i<len {
            let b=bytes[i]; cursor+=1;
            if stage==0 { font_len=b as u32; assert(font_len>0 & font_len<=16); name=[0;16]; name_pos=0; stage=1; }
            else if stage==1 {
                for j in 0..16 { if j==name_pos { name[j]=b; } } name_pos+=1;
                if name_pos==font_len { stage=2; }
            } else if stage==2 { assert(b<=1); kind=b; stage=3; }
            else if stage==3 { strings=b as u32;assert(strings>0);stage=6; }
            else if stage==6 { remaining=(b as u32)*256; stage=4; }
            else if stage==4 {
                remaining+=b as u32; assert(remaining<=len-cursor);
                let mut matched=false;
                for d in 0..D {
                    if fonts[d].enabled & (fonts[d].len==font_len) & (fonts[d].name==name) {
                        assert(!matched); matched=true; width=fonts[d].width; digits=fonts[d].digits;
                    }
                }
                assert(matched);assert(strings>0);strings-=1;
                stage=if remaining==0 {if strings==0 {0} else {6}} else {5};
            } else {
                assert_eq(stage,5); assert(remaining>0); remaining-=1;
                let mut out=false; let mut value=0u8;
                let mut first_out=false; let mut first_byte=0u8;
                let mut second_out=false; let mut second_byte=0u8;
                if kind==1 {
                    if !white(b) {
                        let n=nibble(b);
                        if hex_half { out=true; value=hex_high*16+n; hex_half=false; } else {hex_high=n; hex_half=true;}
                    }
                } else {
                    // A short octal escape emits before reprocessing this byte.
                    let oct=(b>=48)&(b<=55);
                    if (escape==2) & !oct {
                        first_out=true;first_byte=(octal%256) as u8;escape=0;
                    }
                    if escape==2 {
                        octal=octal*8+(b-48) as u32; octal_count+=1;
                        if octal_count==3 { out=true; value=(octal%256) as u8; escape=0; }
                    } else if escape==1 {
                        if oct { escape=2; octal=(b-48) as u32; octal_count=1; }
                        else {
                            escape=0;
                            if b==13 { escape=3; }
                            else if b!=10 {
                                out=true;
                                value=if b==110 {10} else if b==114 {13} else if b==116 {9} else if b==98 {8} else if b==102 {12} else {b};
                            }
                        }
                    } else {
                        let skip=(escape==3)&(b==10); escape=0;
                        if !skip { if b==92 {escape=1;} else {out=true;value=b;} }
                    }
                }
                if out {
                    if first_out {second_out=true;second_byte=value;} else {first_out=true;first_byte=value;}
                }
                if remaining==0 {
                    let flush_hex=(kind==1)&hex_half;let flush_octal=escape==2;
                    if flush_hex|flush_octal {
                        let byte=if flush_hex {hex_high*16} else {(octal%256) as u8};
                        if first_out {assert(!second_out);second_out=true;second_byte=byte;} else {first_out=true;first_byte=byte;}
                    }
                    assert(escape!=1);escape=0;hex_half=false;stage=if strings==0 {0} else {6};
                }
                // At most two decoded bytes per source byte: a short octal
                // escape followed by an ordinary byte. Decode each only once.
                if first_out {let (next,h,f)=emit(s,first_byte,width,high,half,digits);s=next;high=h;half=f;}
                if second_out {let (next,h,f)=emit(s,second_byte,width,high,half,digits);s=next;high=h;half=f;}
                if remaining==0 {assert(!half);}

            }
        }
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

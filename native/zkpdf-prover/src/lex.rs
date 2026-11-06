//! Streaming Word-profile scanner preserving v2 per-string record boundaries.
use crate::{
    field::{self, F},
    Error, Result,
};
use acvm::AcirField;
use serde_json::{json, Value};

pub const BASE: [&str; 21] = [
    "pos",
    "mode",
    "depth",
    "escaped",
    "dict",
    "array",
    "closed",
    "bt",
    "font_len",
    "name_len",
    "word",
    "word_len",
    "long_word",
    "pending",
    "kind",
    "raw_fp",
    "raw_power",
    "raw_len",
    "ops",
    "pi",
    "r",
];
const EXTRA: [&str; 6] = [
    "font",
    "name",
    "font_fp",
    "font_power",
    "name_fp",
    "name_power",
];
pub fn integer(s: &Value, key: &str) -> usize {
    s[key].as_u64().expect("state_schema") as usize
}
pub fn scalar(v: &Value) -> F {
    if let Some(s) = v.as_str() {
        F::from_hex(s).expect("field_schema")
    } else if let Some(b) = v.as_bool() {
        field::number(b as usize)
    } else {
        field::number(v.as_u64().expect("field_schema") as usize)
    }
}
fn ensure(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error("word_profile"))
    }
}
pub fn record(font: &[u8], kind: u8, strings: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure(
        !font.is_empty()
            && font.len() <= 16
            && kind <= 1
            && !strings.is_empty()
            && strings.len() <= 255,
    )?;
    let mut bytes = vec![font.len() as u8];
    bytes.extend(font);
    bytes.extend([kind, strings.len() as u8]);
    for s in strings {
        ensure(s.len() <= 65535)?;
        bytes.extend((s.len() as u16).to_be_bytes());
        bytes.extend(s);
    }
    Ok(bytes)
}
pub fn initial(pi: F, r: F, a: usize, c: usize) -> Value {
    let mut s = json!({});
    for key in BASE.iter().chain(EXTRA.iter()).chain(
        [
            "strings_fp",
            "strings_power",
            "strings_len",
            "strings",
            "slot",
            "field_fp",
            "field_len",
        ]
        .iter(),
    ) {
        s[*key] = json!(0);
    }
    for key in ["escaped", "array", "closed", "bt", "long_word", "pending"] {
        s[key] = json!(false);
    }
    for key in [
        "font",
        "name",
        "raw_fp",
        "font_fp",
        "name_fp",
        "strings_fp",
        "field_fp",
    ] {
        s[key] = field::json(field::number(0));
    }
    for key in ["raw_power", "font_power", "name_power", "strings_power"] {
        s[key] = field::json(field::number(1));
    }
    s["pi"] = field::json(pi);
    s["r"] = field::json(r);
    s["counts"] = json!(vec![0; a]);
    s["ordinals"] = json!(vec![0; a]);
    s["values"] = json!(vec![field::json(field::number(0)); c]);
    s["lengths"] = json!(vec![0; c]);
    s
}
pub fn state_commit(salt: F, s: &Value) -> Result<F> {
    let mut fields: Vec<F> = BASE
        .iter()
        .chain(EXTRA.iter())
        .map(|k| scalar(&s[*k]))
        .collect();
    for i in 0..16 {
        fields.extend([scalar(&s["counts"][i]), scalar(&s["ordinals"][i])]);
    }
    for i in 0..12 {
        fields.extend([scalar(&s["values"][i]), scalar(&s["lengths"][i])]);
    }
    fields.extend(
        [
            "slot",
            "field_fp",
            "field_len",
            "strings_fp",
            "strings_power",
            "strings_len",
            "strings",
        ]
        .map(|k| scalar(&s[k])),
    );
    field::commit(5, salt, &fields)
}
pub fn result_commit(salt: F, s: &Value) -> Result<F> {
    let fields: Vec<F> = (0..12)
        .flat_map(|i| [scalar(&s["values"][i]), scalar(&s["lengths"][i])])
        .collect();
    field::commit(8, salt, &fields)
}
pub fn plan_commit(salt: F, plan: &Value) -> Result<F> {
    let mut fields: Vec<F> = plan["anchor_ops"]
        .as_array()
        .expect("plan_schema")
        .iter()
        .map(scalar)
        .collect();
    for i in 0..12 {
        fields.push(scalar(&plan["lengths"][i]));
        let bytes: Vec<u8> = plan["records"][i]
            .as_array()
            .expect("plan_schema")
            .iter()
            .map(|v| v.as_u64().expect("plan_schema") as u8)
            .collect();
        fields.extend(field::pack(&bytes));
    }
    field::commit(6, salt, &fields)
}
pub fn challenge(cz: F, pi: F, anchors: &[Value], slots: &[Value]) -> Result<F> {
    let mut bytes = Vec::new();
    for a in anchors {
        bytes.push(a["enabled"].as_bool().expect("anchor_schema") as u8);
        bytes.extend((integer(a, "len") as u16).to_be_bytes());
        bytes.extend(
            a["raw"]
                .as_array()
                .expect("anchor_schema")
                .iter()
                .map(|x| x.as_u64().expect("anchor_schema") as u8),
        );
    }
    for s in slots {
        bytes.push(s["enabled"].as_bool().expect("slot_schema") as u8);
        bytes.extend((integer(s, "before") as u32).to_be_bytes());
        bytes.extend((integer(s, "after") as u32).to_be_bytes());
    }
    field::hash(&[field::number(7), cz, pi, field::hash(&field::pack(&bytes))?])
}
pub struct Scanner {
    pub s: Value,
    pub records: Vec<Vec<u8>>,
    raw: Vec<u8>,
    strings: Vec<Vec<u8>>,
    anchors: Vec<Value>,
    slots: Vec<Value>,
    plan: Value,
    anchor_fp: Vec<F>,
    r: F,
}
impl Scanner {
    pub fn new(pi: F, r: F, anchors: Vec<Value>, slots: Vec<Value>, plan: Value) -> Self {
        let mut s = initial(pi, r, anchors.len(), slots.len());
        s["slot"] = json!(slots
            .iter()
            .position(|x| x["enabled"] == true)
            .unwrap_or(slots.len()));
        let anchor_fp = anchors
            .iter()
            .map(|a| {
                let bytes: Vec<u8> = a["raw"].as_array().expect("anchor_schema")
                    [..integer(a, "len")]
                    .iter()
                    .map(|x| x.as_u64().expect("anchor_schema") as u8)
                    .collect();
                field::fingerprint(&bytes, r)
            })
            .collect();
        Self {
            s,
            records: Vec::new(),
            raw: Vec::new(),
            strings: Vec::new(),
            anchors,
            slots,
            plan,
            anchor_fp,
            r,
        }
    }
    pub fn collect(content: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut scan = Self::new(
            field::number(0),
            field::number(3),
            vec![],
            vec![],
            json!({"anchor_ops":[]}),
        );
        for b in content {
            scan.step(*b)?;
        }
        scan.eof()?;
        Ok(scan.records)
    }
    fn n(&self, key: &str) -> usize {
        integer(&self.s, key)
    }
    fn b(&self, key: &str) -> bool {
        self.s[key].as_bool().expect("state_schema")
    }
    fn f(&self, key: &str) -> F {
        scalar(&self.s[key])
    }
    fn set(&mut self, key: &str, n: usize) {
        self.s[key] = json!(n);
    }
    fn flag(&mut self, key: &str, b: bool) {
        self.s[key] = json!(b);
    }
    fn sf(&mut self, key: &str, f: F) {
        self.s[key] = field::json(f);
    }
    fn raw_byte(&mut self, b: u8) -> Result<()> {
        ensure(self.raw.len() < 65535)?;
        self.raw.push(b);
        self.sf(
            "raw_fp",
            self.f("raw_fp") * self.r + field::number(b as usize),
        );
        self.sf("raw_power", self.f("raw_power") * self.r);
        self.set("raw_len", self.n("raw_len") + 1);
        Ok(())
    }
    fn begin(&mut self, kind: usize) -> Result<()> {
        ensure(self.b("bt") && self.n("dict") == 0 && !self.b("closed"))?;
        ensure(!self.b("pending") || self.n("kind") == kind)?;
        self.set("kind", kind);
        self.flag("pending", true);
        Ok(())
    }
    fn word(&mut self) -> Result<()> {
        let w = if self.b("long_word") {
            0
        } else {
            self.n("word")
        };
        let show = [0x546a, 0x544a, 39, 34].contains(&w);
        ensure(w != 0x4249 && (!self.b("pending") || show))?;
        if show {
            ensure(
                self.b("bt")
                    && self.n("font_len") != 0
                    && self.b("pending")
                    && !self.b("array")
                    && self.n("dict") == 0
                    && ((w == 0x544a) == self.b("closed")),
            )?;
            if self.records.len() >= 512 {
                return Err(Error("max_ops"));
            }
            let font = self.f("font").to_be_bytes();
            let len = self.n("font_len");
            self.records.push(record(
                &font[32 - len..],
                self.n("kind") as u8,
                &self.strings,
            )?);
            self.flag("pending", false);
            self.flag("closed", false);
            self.sf("strings_fp", field::number(0));
            self.sf("strings_power", field::number(1));
            self.set("strings_len", 0);
            self.set("strings", 0);
            self.set("kind", 0);
            self.strings.clear();
        } else {
            ensure(!self.b("array") && !self.b("closed"))?;
            if w == 0x4254 {
                ensure(!self.b("bt") && self.n("dict") == 0)?;
                self.flag("bt", true);
                self.sf("font", field::number(0));
                self.set("font_len", 0);
                self.sf("font_fp", field::number(0));
                self.sf("font_power", field::number(1));
            }
            if w == 0x4554 {
                ensure(self.b("bt") && self.n("dict") == 0)?;
                self.flag("bt", false);
            }
            if w == 0x5466 {
                ensure(self.b("bt") && self.n("dict") == 0 && self.n("name_len") != 0)?;
                self.sf("font", self.f("name"));
                self.set("font_len", self.n("name_len"));
                self.sf("font_fp", self.f("name_fp"));
                self.sf("font_power", self.f("name_power"));
            }
        }
        self.set("word", 0);
        self.set("word_len", 0);
        self.flag("long_word", false);
        self.set("mode", 0);
        Ok(())
    }
    fn end_string(&mut self) -> Result<()> {
        ensure(self.strings.len() < 255)?;
        let mut data = (self.raw.len() as u16).to_be_bytes().to_vec();
        data.extend(&self.raw);
        self.strings.push(std::mem::take(&mut self.raw));
        self.sf(
            "strings_fp",
            self.f("strings_fp") * field::power(self.r, data.len())
                + field::fingerprint(&data, self.r),
        );
        self.sf(
            "strings_power",
            self.f("strings_power") * field::power(self.r, data.len()),
        );
        self.set("strings_len", self.n("strings_len") + data.len());
        self.set("strings", self.n("strings") + 1);
        self.sf("raw_fp", field::number(0));
        self.sf("raw_power", field::number(1));
        self.set("raw_len", 0);
        Ok(())
    }
    pub fn aggregate(&mut self, start: usize) -> Result<()> {
        for index in start..self.records.len() {
            let data = &self.records[index];
            let value = field::fingerprint(data, self.r);
            let power = field::power(self.r, data.len());
            let len = data.len();
            let op = self.n("ops");
            for a in 0..self.anchors.len() {
                if self.anchors[a]["enabled"] == true {
                    let equal =
                        value == self.anchor_fp[a] && len == integer(&self.anchors[a], "len");
                    let count = self.s["counts"][a].as_u64().expect("state_schema") + equal as u64;
                    self.s["counts"][a] = json!(count);
                    if op == self.plan["anchor_ops"][a].as_u64().expect("plan_schema") as usize {
                        ensure(equal)?;
                        self.s["ordinals"][a] = json!(count);
                    }
                }
            }
            let c = self.n("slot");
            if c < self.slots.len() {
                let slot = &self.slots[c];
                let begin = self.plan["anchor_ops"][integer(slot, "before")]
                    .as_u64()
                    .expect("plan_schema") as usize;
                let end = self.plan["anchor_ops"][integer(slot, "after")]
                    .as_u64()
                    .expect("plan_schema") as usize;
                if begin < op && op < end {
                    self.sf("field_fp", self.f("field_fp") * power + value);
                    self.set("field_len", self.n("field_len") + len);
                }
                if op == end {
                    self.s["values"][c] = self.s["field_fp"].clone();
                    self.s["lengths"][c] = self.s["field_len"].clone();
                    self.sf("field_fp", field::number(0));
                    self.set("field_len", 0);
                    self.set(
                        "slot",
                        (c + 1..self.slots.len())
                            .find(|i| self.slots[*i]["enabled"] == true)
                            .unwrap_or(self.slots.len()),
                    );
                }
            }
            self.set("ops", op + 1);
        }
        Ok(())
    }
    pub fn step(&mut self, b: u8) -> Result<()> {
        let white = [0, 9, 10, 12, 13, 32].contains(&b);
        let delimiter = white || b"%()<>[]/".contains(&b);
        let hex = b.is_ascii_hexdigit();
        if [4, 5, 6].contains(&self.n("mode")) && delimiter {
            if self.n("mode") == 6 {
                self.word()?;
            } else {
                self.set("mode", 0);
            }
        }
        match self.n("mode") {
            1 => {
                if b == 10 || b == 13 {
                    self.set("mode", 0);
                }
            }
            2 => {
                if self.b("escaped") {
                    self.raw_byte(b)?;
                    self.flag("escaped", false);
                } else if b == 92 {
                    self.raw_byte(b)?;
                    self.flag("escaped", true);
                } else if b == 40 {
                    self.set("depth", self.n("depth") + 1);
                    self.raw_byte(b)?;
                } else if b == 41 {
                    ensure(self.n("depth") > 0)?;
                    self.set("depth", self.n("depth") - 1);
                    if self.n("depth") == 0 {
                        self.set("mode", 0);
                        self.end_string()?;
                    } else {
                        self.raw_byte(b)?;
                    }
                } else {
                    self.raw_byte(b)?;
                }
            }
            3 => {
                if b == 62 {
                    self.set("mode", 0);
                    self.end_string()?;
                } else {
                    ensure(white || hex)?;
                    self.raw_byte(b)?;
                }
            }
            7 => {
                if b == 60 {
                    ensure(!self.b("pending") && !self.b("array"))?;
                    self.set("dict", self.n("dict") + 1);
                    self.set("mode", 0);
                } else {
                    self.begin(1)?;
                    self.set("mode", 3);
                    if b == 62 {
                        self.set("mode", 0);
                        self.end_string()?;
                    } else {
                        ensure(white || hex)?;
                        self.raw_byte(b)?;
                    }
                }
            }
            8 => {
                ensure(b == 62 && self.n("dict") > 0)?;
                self.set("dict", self.n("dict") - 1);
                self.set("mode", 0);
            }
            4 => {
                ensure(self.n("name_len") < 16)?;
                self.sf(
                    "name",
                    self.f("name") * field::number(256) + field::number(b as usize),
                );
                self.sf(
                    "name_fp",
                    self.f("name_fp") * self.r + field::number(b as usize),
                );
                self.sf("name_power", self.f("name_power") * self.r);
                self.set("name_len", self.n("name_len") + 1);
            }
            5 => {
                ensure(b"+-.0123456789".contains(&b))?;
            }
            6 => {
                if self.n("word_len") < 3 {
                    self.set("word", self.n("word") * 256 + b as usize);
                    self.set("word_len", self.n("word_len") + 1);
                } else {
                    self.flag("long_word", true);
                }
            }
            0 => match b {
                _ if white => {}
                37 => self.set("mode", 1),
                40 => {
                    self.begin(0)?;
                    self.set("mode", 2);
                    self.set("depth", 1);
                }
                60 => self.set("mode", 7),
                62 => self.set("mode", 8),
                91 => {
                    ensure(
                        !self.b("array")
                            && !self.b("closed")
                            && !self.b("pending")
                            && self.n("dict") == 0,
                    )?;
                    self.flag("array", true);
                }
                93 => {
                    ensure(self.b("array") && self.n("dict") == 0)?;
                    self.flag("array", false);
                    self.flag("closed", true);
                }
                47 => {
                    ensure(!self.b("pending") && !self.b("closed"))?;
                    self.set("mode", 4);
                    self.sf("name", field::number(0));
                    self.set("name_len", 0);
                    self.sf("name_fp", field::number(0));
                    self.sf("name_power", field::number(1));
                }
                41 => return Err(Error("word_profile")),
                _ if b"+-.0123456789".contains(&b) => self.set("mode", 5),
                _ => {
                    self.set("mode", 6);
                    self.set("word", b as usize);
                    self.set("word_len", 1);
                    self.flag("long_word", false);
                }
            },
            _ => return Err(Error("lex_state")),
        }
        Ok(())
    }
    pub fn eof(&mut self) -> Result<()> {
        if [1, 4, 5, 6].contains(&self.n("mode")) {
            self.step(10)?;
        }
        ensure(
            self.n("mode") == 0
                && !["pending", "bt", "array", "closed"]
                    .iter()
                    .any(|k| self.b(k))
                && self.n("dict") == 0,
        )
    }
}

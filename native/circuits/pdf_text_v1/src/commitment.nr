// Fixed-length Poseidon2 sponge matching Noir beta.15's internal Poseidon2::hash.
// The standard library exposes the permutation, but not its sponge type.
pub fn commit<let N: u32>(tag: Field, salt: Field, fields: [Field; N]) -> Field {
    let mut input = [0; N+3];
    input[0] = tag; input[1] = salt; input[2] = N as Field;
    for i in 0..N { input[i+3] = fields[i]; }
    let mut state = [0,0,0,((N+3) as Field)*18446744073709551616];
    for chunk in 0..((N+5)/3) {
        for j in 0..3 {
            if chunk*3+j < N+3 { state[j] += input[chunk*3+j]; }
        }
        state = std::hash::poseidon2_permutation(state,4);
    }
    state[0]
}

// The last group is left-zero-padded, hence its integer is the big-endian
// interpretation of the remaining bytes (no multiplication for missing bytes).
pub fn pack31<let N: u32>(bytes: [u8; N]) -> [Field; (N+30)/31] {
    let mut packed = [0; (N+30)/31];
    for group in 0..((N+30)/31) {
        let mut word: Field = 0;
        for j in 0..31 {
            if group*31+j < N { word = word*256 + bytes[group*31+j] as Field; }
        }
        packed[group] = word;
    }
    packed
}

// Commit to a capacity-padded byte array AND its actual byte length. Without
// the byte length, distinct inputs ending in zero bytes could share a preimage.
pub fn commit_bytes<let N: u32>(tag: Field, salt: Field, bytes: [u8;N], len: u32) -> Field {
    assert(len <= N);
    for i in 0..N { if i >= len { assert_eq(bytes[i],0); } }
    let packed = pack31(bytes);
    let mut fields = [0; 1+(N+30)/31];
    fields[0] = len as Field;
    for i in 0..((N+30)/31) { fields[i+1] = packed[i]; }
    commit(tag,salt,fields)
}

pub fn commit_plain<let P: u32>(salt: Field, index: u32, len: u32, bytes: [u8;P]) -> Field {
    assert(len <= P);
    for i in 0..P { if i >= len { assert_eq(bytes[i],0); } }
    let packed = pack31(bytes);
    let mut fields = [0; 2+(P+30)/31];
    fields[0] = index as Field; fields[1] = len as Field;
    for i in 0..((P+30)/31) { fields[i+2] = packed[i]; }
    commit(2,salt,fields)
}

#[test]
fn packing_boundaries() {
    assert_eq(pack31([1u8,2,3]),[66051]);
    let mut bytes = [0u8;33]; bytes[30]=7; bytes[31]=1; bytes[32]=2;
    assert_eq(pack31(bytes),[7,258]);
}

// Expected values generated independently with bb.js 2.1.9 poseidon2Hash,
// using [tag,salt,N,...fields], via tools/poseidon_reference.mjs.
#[test]
fn known_answers() {
    assert_eq(commit(1,42,[0,1,2]),0x0e38abf00bd0aeb288ed74a01e99cec931b4904f6ba8aec4b9aa762107256dea);
    assert_eq(commit(2,42,[]),0x2bea62b95fd366e7903877a49f491dcbb320cd4c7d1b26bb9ed8baa75a564cdf);
}

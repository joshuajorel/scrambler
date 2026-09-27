//! Generates FF1 differential test vectors with the `fpe` crate
//! (https://github.com/str4d/fpe, version pinned in Cargo.toml) and prints
//! them as JSON for ff1/testdata/differential_fpe-rs.json.
//!
//! The inputs are a fixed list of edge cases followed by pseudorandom
//! parameters (key size, radix in 2..=65536, length, tweak, numerals) drawn
//! from a SplitMix64 generator with a fixed seed, so the output is
//! reproducible byte for byte. Run it through ../generate.sh.

use aes::{Aes128, Aes192, Aes256};
use fpe::ff1::{FlexibleNumeralString, FF1};
use num_bigint::BigUint;
use std::fmt::Write as _;

const SEED: u64 = 0x5343_524D_424C_4552; // "SCRMBLER"
const RANDOM_CASES: usize = 700;

/// Radixes that sit on an edge: tiny, powers of two and their neighbours,
/// the 10^6 domain boundary (999/1000), the int16 sign bit, and the maximum.
const EDGE_RADIXES: &[u32] = &[
    2, 3, 10, 16, 36, 62, 64, 255, 256, 257, 999, 1000, 1023, 1024, 1025, 32767, 32768, 32769,
    65535, 65536,
];

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }

    fn numerals(&mut self, n: usize, radix: u32) -> Vec<u16> {
        (0..n)
            .map(|_| self.below(u64::from(radix)) as u16)
            .collect()
    }
}

struct Case {
    note: &'static str,
    key: Vec<u8>,
    radix: u32,
    tweak: Vec<u8>,
    pt: Vec<u16>,
}

/// Smallest n >= 2 with radix^n >= 1,000,000.
fn min_len(radix: u32) -> usize {
    let (mut n, mut d) = (0usize, 1u64);
    while d < 1_000_000 {
        d *= u64::from(radix);
        n += 1;
    }
    n.max(2)
}

/// Exact b = ceil(BITLEN(radix^v - 1) / 8).
fn exact_b(radix: u32, v: usize) -> usize {
    let m = BigUint::from(radix).pow(v as u32) - 1u32;
    (m.bits() as usize).div_ceil(8)
}

/// The b the fpe crate computes (Radix::calculate_b in fpe 0.6.1): exact for
/// powers of two, floating point otherwise.
fn fpe_b(radix: u32, v: usize) -> usize {
    if radix.is_power_of_two() {
        (v * radix.trailing_zeros() as usize).div_ceil(8)
    } else {
        libm::ceil(v as f64 * libm::log2(f64::from(radix)) / 8f64) as usize
    }
}

fn encrypt(key: &[u8], radix: u32, tweak: &[u8], pt: &[u16]) -> Vec<u16> {
    macro_rules! run {
        ($aes:ty) => {{
            let ff = FF1::<$aes>::new(key, radix).expect("radix");
            let ct: Vec<u16> = ff
                .encrypt(tweak, &FlexibleNumeralString::from(pt.to_vec()))
                .expect("encrypt")
                .into();
            let back: Vec<u16> = ff
                .decrypt(tweak, &FlexibleNumeralString::from(ct.clone()))
                .expect("decrypt")
                .into();
            assert_eq!(back, pt, "fpe decrypt(encrypt(pt)) != pt");
            ct
        }};
    }
    match key.len() {
        16 => run!(Aes128),
        24 => run!(Aes192),
        32 => run!(Aes256),
        n => panic!("bad key length {n}"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn list(x: &[u16]) -> String {
    let items: Vec<String> = x.iter().map(|v| v.to_string()).collect();
    format!("[{}]", items.join(", "))
}

fn key_for(rng: &mut SplitMix64, i: usize) -> Vec<u8> {
    rng.bytes([16, 24, 32][i % 3])
}

/// Collects cases, rotating through the three AES key sizes.
struct Cases {
    list: Vec<Case>,
    rng: SplitMix64,
}

impl Cases {
    fn push(&mut self, note: &'static str, radix: u32, pt: Vec<u16>, tweak_len: usize) {
        let key = key_for(&mut self.rng, self.list.len());
        let tweak = self.rng.bytes(tweak_len);
        self.list.push(Case {
            note,
            key,
            radix,
            tweak,
            pt,
        });
    }

    fn random(&mut self, note: &'static str, radix: u32, n: usize, tweak_len: usize) {
        let pt = self.rng.numerals(n, radix);
        self.push(note, radix, pt, tweak_len);
    }
}

fn edge_cases(rng: SplitMix64) -> Cases {
    let mut c = Cases {
        list: Vec::new(),
        rng,
    };
    // Bouncy Castle encodes radix 65536 in P as 00 00 00 and gets
    // [6653, 42184] here; the correct output is [18476, 48157].
    c.list.push(Case {
        note: "radix 65536 P-encoding regression (zero key, zero 8-byte tweak)",
        key: vec![0; 16],
        radix: 65536,
        tweak: vec![0; 8],
        pt: vec![0, 1],
    });
    c.list.push(Case {
        note: "Wycheproof aes_ff1_radix65536 tcId 7",
        key: unhex("ad65778960d778c614e2673dee073acb"),
        radix: 65536,
        tweak: unhex("4505f45a8fa30b90"),
        pt: vec![35521, 37776],
    });
    for &radix in EDGE_RADIXES {
        let lo = min_len(radix);
        let max = (radix - 1) as u16;
        c.push(
            "edge radix, minimum length, all zero",
            radix,
            vec![0; lo],
            0,
        );
        c.push(
            "edge radix, minimum length, all radix-1",
            radix,
            vec![max; lo],
            8,
        );
        c.random("edge radix, minimum length + 1", radix, lo + 1, 13);
        let n = lo + 2 + c.rng.below(40) as usize;
        let t = c.rng.below(40) as usize;
        c.random("edge radix, random length", radix, n, t);
    }
    // radix 65536: n = 2, 3, and the step from one S block (n = 12: b = 12,
    // d = 16) to two (n = 13: b = 14, d = 20); then int16 sign-bit digits.
    for n in [2, 3, 12, 13, 29, 30, 64, 256] {
        c.random("radix 65536 length boundary", 65536, n, 8);
    }
    for pt in [
        vec![32767, 32768],
        vec![65535, 32767, 32768],
        vec![65535, 65535, 65535],
    ] {
        c.push("radix 65536 digits 32767/32768/65535", 65536, pt, 8);
    }
    // radix 2 with v = 232: b = 29 exactly (floating point is prone to 30).
    for n in [463, 464] {
        c.random("radix 2, v = 232 (b = 29)", 2, n, 0);
        c.random("radix 2, v = 232 (b = 29)", 2, n, 17);
    }
    c.random("radix 2, long input", 2, 1000, 5);
    // d > 16 for radix 10 (v = 29 -> b = 13 -> d = 20), and a long input.
    c.random("radix 10, d = 20", 10, 58, 3);
    c.random("radix 10, long input", 10, 1000, 3);
    // Bouncy Castle's testFF1Rounding parameters (radix 256, n = 57).
    c.random("radix 256, n = 57", 256, 57, 8);
    c.random("radix 256, n = 58", 256, 58, 8);
    // Every tweak length 0..=40 (every padding length), then long tweaks.
    for t in (0..=40).chain([255, 256, 1000]) {
        c.random("tweak length sweep", 36, 19, t);
    }
    c
}

fn random_case(rng: &mut SplitMix64, i: usize) -> Case {
    let radix = match rng.below(4) {
        0 => EDGE_RADIXES[rng.below(EDGE_RADIXES.len() as u64) as usize],
        1 => 1u32 << (1 + rng.below(16)),
        _ => 2 + rng.below(65535) as u32,
    };
    let lo = min_len(radix);
    let n = match rng.below(20) {
        0 => lo + rng.below(600) as usize,
        1..=3 => lo + rng.below(200) as usize,
        _ => lo + rng.below(40) as usize,
    };
    let t = match rng.below(20) {
        0 => rng.below(600) as usize,
        1..=5 => rng.below(128) as usize,
        _ => rng.below(33) as usize,
    };
    let key = key_for(rng, i);
    let tweak = rng.bytes(t);
    let pt = match rng.below(20) {
        0 => vec![0; n],
        1 => vec![(radix - 1) as u16; n],
        _ => rng.numerals(n, radix),
    };
    Case {
        note: "random",
        key,
        radix,
        tweak,
        pt,
    }
}

fn main() {
    // Oracle self-checks: published answers the crate must reproduce.
    assert_eq!(
        encrypt(&[0; 16], 65536, &[0; 8], &[0, 1]),
        vec![18476, 48157]
    );
    assert_eq!(
        encrypt(
            &unhex("2b7e151628aed2a6abf7158809cf4f3c"),
            10,
            &[],
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        ),
        vec![2, 4, 3, 3, 4, 7, 7, 4, 8, 4],
        "NIST FF1 sample 1"
    );

    let mut c = edge_cases(SplitMix64(SEED));
    for i in 0..RANDOM_CASES {
        let case = random_case(&mut c.rng, i);
        c.list.push(case);
    }
    let cases = c.list;

    let mut out = String::new();
    let mut skipped = 0;
    let mut id = 0;
    for c in &cases {
        let v = c.pt.len() - c.pt.len() / 2;
        if exact_b(c.radix, v) != fpe_b(c.radix, v) {
            // The crate would use a wrong b here; such a vector would test
            // its rounding, not FF1. None occur with this seed.
            skipped += 1;
            continue;
        }
        let ct = encrypt(&c.key, c.radix, &c.tweak, &c.pt);
        if id > 0 {
            out.push_str(",\n");
        }
        let _ = write!(
            out,
            "  {{\"id\": {id}, \"note\": \"{}\", \"key\": \"{}\", \"radix\": {}, \"tweak\": \"{}\",\n   \"pt\": {},\n   \"ct\": {}}}",
            c.note,
            hex(&c.key),
            c.radix,
            hex(&c.tweak),
            list(&c.pt),
            list(&ct)
        );
        id += 1;
    }

    println!("{{");
    println!(" \"description\": \"FF1 vectors computed by the Rust fpe crate for differential testing: fixed edge cases, then SplitMix64 pseudorandom parameters over radix 2..=65536, all AES key sizes, and tweaks of 0..1000 bytes. Every input satisfies radix^n >= 1000000. Regenerate with tools/differential/generate.sh.\",");
    println!(" \"generator\": \"tools/differential/fpe-rs\",");
    println!(" \"library\": \"fpe (https://github.com/str4d/fpe)\",");
    println!(" \"library_version\": \"0.6.1\",");
    println!(" \"seed\": \"{SEED:#018x}\",");
    println!(
        " \"pinned\": {{\"fpe\": \"0.6.1\", \"aes\": \"0.8.4\", \"cipher\": \"0.4.4\", \"cbc\": \"0.1.2\", \"num-bigint\": \"0.4.8\", \"libm\": \"0.2.16\", \"rustc\": \"{}\"}},",
        env!("GEN_RUSTC_VERSION")
    );
    println!(" \"skipped_float_b_mismatch\": {skipped},");
    println!(" \"vectors\": [\n{out}\n ]");
    println!("}}");
    eprintln!("{id} vectors ({skipped} skipped)");
}

// Evaluates versions and requirements with the semver crate (1.0), the one
// Cargo resolves with. Input: two files of one JSON-quoted string per line
// (versions, constraints); output: the two corpora.
// Usage: cargo run -- versions.lines constraints.lines outdir
use semver::{Version, VersionReq};
use std::fs;

fn quote(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn unquote(s: &str) -> String {
    // The inputs are JSON strings without exotic escapes.
    let inner = &s[1..s.len() - 1];
    let mut o = String::new();
    let mut it = inner.chars();
    while let Some(c) = it.next() {
        if c != '\\' { o.push(c); continue; }
        match it.next() {
            Some('n') => o.push('\n'), Some('t') => o.push('\t'), Some('r') => o.push('\r'),
            Some('u') => { let h: String = it.by_ref().take(4).collect(); o.push(char::from_u32(u32::from_str_radix(&h, 16).unwrap()).unwrap()); }
            Some(x) => o.push(x), None => {}
        }
    }
    o
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let versions: Vec<String> = fs::read_to_string(&args[1]).unwrap().lines().filter(|l| !l.is_empty()).map(unquote).collect();
    let reqs: Vec<String> = fs::read_to_string(&args[2]).unwrap().lines().filter(|l| !l.is_empty()).map(unquote).collect();
    let mut valid: Vec<Version> = versions.iter().filter_map(|v| Version::parse(v).ok()).collect();
    valid.sort();
    let mut out = String::new();
    for v in &versions {
        let rank = match Version::parse(v) {
            Ok(p) => { let mut r: i64 = -1; let mut prev: Option<&Version> = None; for x in &valid { if prev.map_or(true, |p| p != x) { r += 1; } if *x == p { break; } prev = Some(x); } r }
            Err(_) => -1,
        };
        out.push_str(&format!("{}\t{}\n", quote(v), rank));
    }
    fs::write(format!("{}/cargo-versions.tsv", args[3]), out).unwrap();
    let universe: Vec<&String> = versions.iter().filter(|v| Version::parse(v).is_ok()).take(220).collect();
    let mut out = format!("# [{}]\n", universe.iter().map(|v| quote(v)).collect::<Vec<_>>().join(","));
    for r in &reqs {
        match VersionReq::parse(r) {
            Ok(req) => {
                let bits: String = universe.iter().map(|v| if req.matches(&Version::parse(v).unwrap()) { '1' } else { '0' }).collect();
                out.push_str(&format!("{}\tok\t{}\t{}\n", quote(r), quote(&req.to_string()), bits));
            }
            Err(_) => out.push_str(&format!("{}\tinvalid\t\t\n", quote(r))),
        }
    }
    fs::write(format!("{}/cargo-constraints.tsv", args[3]), out).unwrap();
}

use serde_json::{json, Value};
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const F: [&str; 20] = ["vpn","proxy","tor","malware","c2","scanner","brute_force","spammer","compromised","datacenter","cdn","anycast","crawler","bot","cloud","private_relay","anonymizer","mobile","isp","government"];
const S: [f64; 20] = [30.0,25.0,45.0,95.0,95.0,55.0,70.0,65.0,75.0,15.0,5.0,0.0,10.0,40.0,10.0,15.0,35.0,0.0,0.0,0.0];
const L: [(f64, &str); 4] = [(80.0,"critical"),(60.0,"high"),(35.0,"medium"),(15.0,"low")];

fn u16(d: &[u8], o: usize) -> u16 { u16::from_le_bytes(d[o..o+2].try_into().unwrap()) }
fn u32(d: &[u8], o: usize) -> u32 { u32::from_le_bytes(d[o..o+4].try_into().unwrap()) }
fn u64(d: &[u8], o: usize) -> u64 { u64::from_le_bytes(d[o..o+8].try_into().unwrap()) }

struct DB {
    v4s: Vec<u32>, v4e: Vec<u32>, v4m: Vec<u32>, v4v: Vec<u16>,
    v6s: Vec<u128>, v6e: Vec<u128>, v6m: Vec<u128>, v6v: Vec<u16>,
    vt: Vec<[u32; 4]>, st: Vec<String>, w: [f64; 20],
}

fn load(path: &str) -> DB {
    let d = fs::read(path).unwrap();
    assert_eq!(u32(&d, 0), 6);
    let o: Vec<usize> = (0..19).map(|i| u64(&d, 8 + i*8) as usize).collect();
    let (cn, ln, v6n, valn, strn) = (o[0], o[1], o[2], o[3], o[4]);
    let off = &o[5..];
    let bi: Vec<u32> = (0..65537).map(|i| u32(&d, off[0] + i*4)).collect();
    let n = cn + ln;
    let mut s = vec![0u32; n];
    let mut e = vec![0u32; n];
    let mut v = vec![0u16; n];
    for b in 0..65536 {
        for j in bi[b]..bi[b+1] {
            let lo = u16(&d, off[1] + j as usize * 2) as u32;
            s[j as usize] = (b as u32) << 16 | lo;
            e[j as usize] = s[j as usize] + u16(&d, off[2] + j as usize * 2) as u32;
            v[j as usize] = u16(&d, off[3] + j as usize * 2);
        }
    }
    for i in 0..ln {
        s[cn+i] = u32(&d, off[4] + i*4);
        e[cn+i] = u32(&d, off[5] + i*4);
        v[cn+i] = u16(&d, off[6] + i*2);
    }
    let mut idx: Vec<usize> = (0..n).collect();
    idx.sort_by_key(|&i| s[i]);
    let v4s: Vec<u32> = idx.iter().map(|&i| s[i]).collect();
    let v4e: Vec<u32> = idx.iter().map(|&i| e[i]).collect();
    let v4v: Vec<u16> = idx.iter().map(|&i| v[i]).collect();
    let mut v4m = vec![0u32; n];
    let mut mx = 0u32;
    for i in 0..n { if v4e[i] > mx { mx = v4e[i]; } v4m[i] = mx; }

    let v6s: Vec<u128> = (0..v6n).map(|i| (u64(&d, off[7]+i*16+8) as u128) << 64 | u64(&d, off[7]+i*16) as u128).collect();
    let v6e: Vec<u128> = (0..v6n).map(|i| (u64(&d, off[8]+i*16+8) as u128) << 64 | u64(&d, off[8]+i*16) as u128).collect();
    let v6v: Vec<u16> = (0..v6n).map(|i| u16(&d, off[9] + i*2)).collect();
    let mut v6m = vec![0u128; v6n];
    let mut m: u128 = 0;
    for i in 0..v6n { if v6e[i] > m { m = v6e[i]; } v6m[i] = m; }

    let vt: Vec<[u32; 4]> = (0..valn).map(|i| [
        u32(&d, off[10] + i*16), u32(&d, off[10] + i*16+4),
        u32(&d, off[10] + i*16+8), u32(&d, off[10] + i*16+12),
    ]).collect();
    let sd = off[12];
    let st: Vec<String> = (0..strn).map(|i| {
        let so = u32(&d, off[11] + i*8) as usize;
        let sl = u32(&d, off[11] + i*8 + 4) as usize;
        String::from_utf8_lossy(&d[sd+so..sd+so+sl]).into_owned()
    }).collect();
    let mut w = [0f64; 20];
    if n > 0 {
        let mut c = [0usize; 20];
        for &vid in &v4v {
            let b = vt[vid as usize][0];
            for i in 0..20 { if b & (1 << i) != 0 { c[i] += 1; } }
        }
        for i in 0..20 { w[i] = S[i] * (1.0 + (n as f64 / c[i].max(1) as f64).log2() / 24.0); }
    } else { w = S; }
    DB { v4s, v4e, v4m, v4v, v6s, v6e, v6m, v6v, vt, st, w }
}

fn upper<T: Ord + Copy>(a: &[T], ip: T) -> usize {
    let (mut lo, mut hi) = (0, a.len());
    while lo < hi { let m = (lo + hi) / 2; if a[m] > ip { hi = m; } else { lo = m + 1; } }
    lo
}

fn r1(x: f64) -> f64 { (x * 10.0).round() / 10.0 }

fn lookup(db: &DB, ip_str: &str) -> Value {
    let addr: IpAddr = ip_str.parse().unwrap();
    let mut matches: Vec<(String, String, String, Vec<&str>, f64)> = Vec::new();
    let mut push = |vid: u16, rng: String| {
        let vt = db.vt[vid as usize];
        let b = vt[0];
        let mut fl = Vec::new();
        let mut mxw = 0.0f64;
        for i in 0..20 {
            if b & (1 << i) != 0 { fl.push(F[i]); if db.w[i] > mxw { mxw = db.w[i]; } }
        }
        matches.push((db.st[vt[2] as usize].clone(), db.st[vt[1] as usize].clone(), rng, fl, r1(mxw)));
    };
    match addr {
        IpAddr::V4(a) => {
            let ip = u32::from(a);
            let mut i = upper(&db.v4s, ip);
            while i > 0 {
                i -= 1;
                if db.v4m[i] < ip { break; }
                if db.v4e[i] >= ip {
                    push(db.v4v[i], format!("{}-{}", Ipv4Addr::from(db.v4s[i]), Ipv4Addr::from(db.v4e[i])));
                }
            }
        }
        IpAddr::V6(a) => {
            let ip = u128::from(a);
            let mut i = upper(&db.v6s, ip);
            while i > 0 {
                i -= 1;
                if db.v6m[i] < ip { break; }
                if db.v6e[i] >= ip {
                    push(db.v6v[i], format!("{}-{}", Ipv6Addr::from(db.v6s[i]), Ipv6Addr::from(db.v6e[i])));
                }
            }
        }
    }
    matches.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap());

    let mut all_flags: Vec<&str> = Vec::new();
    for m in &matches { for f in &m.3 { if !all_flags.contains(f) { all_flags.push(f); } } }
    let fi = |f: &str| F.iter().position(|x| *x == f).unwrap();
    let mut ranked = all_flags.clone();
    ranked.sort_by(|a, b| db.w[fi(b)].partial_cmp(&db.w[fi(a)]).unwrap());

    let mut src: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for m in &matches { src.insert((m.1.clone(), m.0.clone())); }
    let score = if ranked.is_empty() { 0.0 } else {
        let top = db.w[fi(ranked[0])];
        let ex: f64 = ranked[1..].iter().map(|f| db.w[fi(f)]).sum();
        r1((100f64).min((top + ex * 0.15) * (1.0 + 0.08 * ((src.len() + 1) as f64).log2())))
    };
    let verdict = if matches.is_empty() { "clean" }
        else { L.iter().find(|(t, _)| score >= *t).map(|(_, n)| *n).unwrap_or("minimal") };

    let mut providers: Vec<String> = Vec::new();
    for m in &matches { if !m.1.is_empty() && !providers.contains(&m.1) { providers.push(m.1.clone()); } }
    if let Some(i) = providers.iter().position(|p| p.eq_ignore_ascii_case("tor")) {
        providers.remove(i);
        providers.insert(0, "Tor".into());
    }
    let reasons: Vec<&str> = ranked.iter().take(5).copied().collect();
    let top = providers.first().cloned().unwrap_or_default();
    json!({
        "ip": ip_str, "found": !matches.is_empty(), "verdict": verdict, "score": score,
        "detections": matches.len(), "sources": src.len(), "top_provider": top,
        "providers": providers, "flags": all_flags, "reasons": reasons,
        "matches": matches.iter().map(|m| json!({
            "source": m.0, "provider": m.1, "range": m.2, "flags": m.3, "weight": m.4
        })).collect::<Vec<_>>(),
    })
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let ip = if args.len() > 1 { args[1].clone() } else { "8.8.8.8".into() };
    let db = load("../intel.bin");
    println!("{}", serde_json::to_string_pretty(&lookup(&db, &ip)).unwrap());
}

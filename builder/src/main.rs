mod build;
mod db;

use db::Result;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

const FLAG_NAMES: &[&str] = &[
    "vpn", "proxy", "tor", "malware", "c2", "scanner", "brute_force",
    "spammer", "compromised", "datacenter", "cdn", "anycast", "crawler",
    "bot", "cloud", "private_relay", "anonymizer", "mobile", "isp",
    "government",
];

fn flags_to_strings(flags: u32) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (i, name) in FLAG_NAMES.iter().enumerate() {
        if flags & (1 << i) != 0 {
            out.push(*name);
        }
    }
    out
}

fn db_path() -> PathBuf {
    if let Ok(p) = std::env::var("OUT_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from("intel.bin")
}

fn feeds_path() -> PathBuf {
    if let Ok(p) = std::env::var("FEEDS_FILE") {
        return PathBuf::from(p);
    }
    for c in ["feeds-intel.json", "../feeds-intel.json"] {
        let p = PathBuf::from(c);
        if p.exists() { return p; }
    }
    PathBuf::from("feeds-intel.json")
}

fn cmd_update() -> Result<()> {
    let out = db_path();
    let feeds = feeds_path();
    println!("feeds: {}", feeds.display());
    println!("out:   {}", out.display());
    let t = Instant::now();
    build::build_db(&feeds, &out, true)?;
    let size = std::fs::metadata(&out)?.len();
    println!("built in {:.2}s, {:.2} MB", t.elapsed().as_secs_f64(), size as f64 / 1e6);
    Ok(())
}

fn cmd_check(ip: &str) -> Result<()> {
    let addr: IpAddr = ip.parse().map_err(|_| format!("invalid IP: {ip}"))?;
    let t = Instant::now();
    let db = db::Db::open(&db_path())?;
    let load_us = t.elapsed().as_micros();
    let t2 = Instant::now();
    let hits = db.lookup(addr);
    let lookup_ns = t2.elapsed().as_nanos();

    let mut combined: u32 = 0;
    let mut providers: Vec<&str> = Vec::new();
    let mut sources: Vec<&str> = Vec::new();
    for h in &hits {
        combined |= h.flags;
        if !h.provider.is_empty() && !providers.contains(&h.provider) {
            providers.push(h.provider);
        }
        if !sources.contains(&h.source) { sources.push(h.source); }
    }
    let primary = providers.first().copied().unwrap_or("");

    let out = serde_json::json!({
        "ip": ip,
        "found": !hits.is_empty(),
        "primary_provider": primary,
        "providers": providers,
        "flags": flags_to_strings(combined),
        "flag_bits": combined,
        "matches": hits.iter().map(|h| serde_json::json!({
            "range": format!("{}-{}", h.start, h.end),
            "provider": h.provider,
            "source": h.source,
            "flags": flags_to_strings(h.flags),
        })).collect::<Vec<_>>(),
        "_perf": {"load_us": load_us, "lookup_ns": lookup_ns},
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn cmd_bench(n: usize) -> Result<()> {
    let t = Instant::now();
    let db = db::Db::open(&db_path())?;
    let load_us = t.elapsed().as_micros();
    println!("load: {load_us} us | v4={} v6={}", db.v4_count(), db.v6_count());

    let starts = db.v4_starts();
    let tails = db.v4_tail();
    let v4n = starts.len();
    let mut sample_v4: Vec<u32> = Vec::with_capacity(n);
    let mut seed: u32 = 0x9E3779B1;
    for _ in 0..n {
        seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
        let idx = (seed as usize) % v4n.max(1);
        let s = starts[idx];
        let e = tails[idx].end;
        let span = e.wrapping_sub(s).saturating_add(1).max(1);
        let off = seed % span;
        sample_v4.push(s.wrapping_add(off));
    }

    let mut total_hits = 0usize;
    let t = Instant::now();
    for ip in &sample_v4 {
        let hits = db.lookup_v4(*ip);
        total_hits += hits.len();
    }
    let el = t.elapsed();
    let per = el.as_nanos() as f64 / n as f64;
    println!("v4 hit-path: {n} lookups in {:.3} ms | {:.1} ns/op | {:.2}M ops/s | total_hits={}",
        el.as_secs_f64() * 1000.0, per, 1e9 / per / 1e6, total_hits);

    let mut miss: Vec<u32> = Vec::with_capacity(n);
    let mut s: u32 = 0xDEADBEEF;
    for _ in 0..n {
        s = s.wrapping_mul(1103515245).wrapping_add(12345);
        miss.push(s);
    }
    let t = Instant::now();
    let mut h = 0usize;
    for ip in &miss { h += db.lookup_v4(*ip).len(); }
    let el = t.elapsed();
    let per = el.as_nanos() as f64 / n as f64;
    println!("v4 random:   {n} lookups in {:.3} ms | {:.1} ns/op | {:.2}M ops/s | total_hits={}",
        el.as_secs_f64() * 1000.0, per, 1e9 / per / 1e6, h);

    let t = Instant::now();
    let mut acc = 0u32;
    for ip in &sample_v4 { acc |= db.lookup_v4_flags(*ip); }
    let el = t.elapsed();
    let per = el.as_nanos() as f64 / n as f64;
    println!("v4 flags hit:{n} lookups in {:.3} ms | {:.1} ns/op | {:.2}M ops/s | acc=0x{:x}",
        el.as_secs_f64() * 1000.0, per, 1e9 / per / 1e6, acc);

    let t = Instant::now();
    let mut acc = 0u32;
    for ip in &miss { acc |= db.lookup_v4_flags(*ip); }
    let el = t.elapsed();
    let per = el.as_nanos() as f64 / n as f64;
    println!("v4 flags rnd:{n} lookups in {:.3} ms | {:.1} ns/op | {:.2}M ops/s | acc=0x{:x}",
        el.as_secs_f64() * 1000.0, per, 1e9 / per / 1e6, acc);

    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: threat-intel <update|check IP|bench [N]>");
        std::process::exit(1);
    }
    match args[1].as_str() {
        "update" => cmd_update(),
        "check" => {
            if args.len() < 3 { Err("check requires IP".into()) }
            else { cmd_check(&args[2]) }
        }
        "bench" => {
            let n = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(100_000);
            cmd_bench(n)
        }
        c => Err(format!("unknown command: {c}").into()),
    }
}

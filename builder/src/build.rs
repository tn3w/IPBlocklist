use crate::db::{Builder, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::OnceLock;
use sha2::{Digest, Sha256};

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) \
    Chrome/131.0.0.0 Safari/537.36";
const WORKERS: usize = 8;
const ASN_WORKERS: usize = 16;

#[derive(Deserialize)]
pub struct FeedsFile {
    pub flags: Vec<String>,
    pub feeds: Vec<FeedSpec>,
}

#[derive(Deserialize, Clone)]
pub struct FeedSpec {
    pub name: String,
    #[serde(default)]
    pub provider: Option<String>,
    pub url: String,
    pub regex: String,
    pub flags: Vec<String>,
    #[serde(default)]
    pub is_asn: bool,
    #[serde(default)]
    pub asns: Vec<String>,
}

const REQUEST_CACHE_DIR: &str = "request_cache";

static ASN_CACHE: OnceLock<Mutex<HashMap<u32, Vec<String>>>> = OnceLock::new();

fn asn_cache_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ASN_CACHE_FILE") {
        return PathBuf::from(p);
    }
    PathBuf::from("asn_prefixes.json")
}

fn load_asn_cache() {
    let map = fs::read(asn_cache_path()).ok()
        .and_then(|b| serde_json::from_slice::<HashMap<String, Vec<String>>>(&b).ok())
        .map(|m| m.into_iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|n| (n, v))).collect())
        .unwrap_or_default();
    let _ = ASN_CACHE.set(Mutex::new(map));
}

fn save_asn_cache() -> Result<()> {
    let guard = ASN_CACHE.get().ok_or("asn cache uninit")?.lock().unwrap();
    let m: HashMap<String, &Vec<String>> = guard.iter()
        .map(|(k, v)| (k.to_string(), v)).collect();
    fs::write(asn_cache_path(), serde_json::to_vec(&m)?)?;
    Ok(())
}

fn request_cache_path(url: &str) -> PathBuf {
    let hex: String = Sha256::digest(url.as_bytes())
        .iter().map(|b| format!("{b:02x}")).collect();
    PathBuf::from(REQUEST_CACHE_DIR).join(hex)
}

pub fn flag_mask(flags: &[String], all_flags: &[String]) -> u32 {
    let mut m = 0u32;
    for f in flags {
        if let Some(i) = all_flags.iter().position(|x| x == f) {
            m |= 1 << i;
        }
    }
    m
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(UA)
        .build()
}

static PEERINGDB_LOCK: Mutex<()> = Mutex::new(());

fn http_get(url: &str) -> Result<Vec<u8>> {
    let raw = http_get_raw(url)?;
    if url.ends_with(".gz") {
        let mut d = flate2::read::GzDecoder::new(&raw[..]);
        let mut out = Vec::new();
        d.read_to_end(&mut out)?;
        Ok(out)
    } else {
        Ok(raw)
    }
}

fn http_get_raw(url: &str) -> Result<Vec<u8>> {
    let cache_path = request_cache_path(url);
    if let Ok(b) = fs::read(&cache_path) {
        return Ok(b);
    }
    let is_pdb = url.contains("peeringdb.com");
    let _guard;
    if is_pdb {
        _guard = PEERINGDB_LOCK.lock().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(800));
    }
    let key = if is_pdb { std::env::var("PEERINGDB_API_KEY").ok() } else { None };
    let mut attempt = 0;
    let res = loop {
        attempt += 1;
        let mut req = agent().get(url);
        if let Some(k) = &key { req = req.set("Authorization", &format!("Api-Key {k}")); }
        match req.call() {
            Ok(r) => break r,
            Err(ureq::Error::Status(429, _)) if is_pdb && attempt < 4 => {
                eprintln!("  pdb 429, sleep 15s (attempt {attempt})");
                std::thread::sleep(std::time::Duration::from_secs(15));
            }
            Err(e) => return Err(format!("GET {url}: {e}").into()),
        }
    };
    let mut buf = Vec::new();
    res.into_reader().take(500 * 1024 * 1024).read_to_end(&mut buf)?;
    let _ = fs::create_dir_all(REQUEST_CACHE_DIR);
    let _ = fs::write(&cache_path, &buf);
    Ok(buf)
}

fn parse_token(token: &str) -> Option<(u128, u128, bool)> {
    let t = token.trim().trim_matches('"');
    if t.is_empty() || t == "0.0.0.0" || t == "::" {
        return None;
    }
    let (ip_part, prefix_part) = match t.find('/') {
        Some(i) => (&t[..i], Some(&t[i + 1..])),
        None => (t, None),
    };
    let ip: IpAddr = ip_part.parse().ok()?;
    match ip {
        IpAddr::V4(a) => {
            let v = u32::from(a);
            let p = prefix_part.and_then(|p| p.parse::<u32>().ok()).unwrap_or(32);
            if p > 32 { return None; }
            let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            let net = v & mask;
            let bcast = net | !mask;
            Some((net as u128, bcast as u128, false))
        }
        IpAddr::V6(a) => {
            let v = u128::from(a);
            let p = prefix_part.and_then(|p| p.parse::<u32>().ok()).unwrap_or(128);
            if p > 128 { return None; }
            let mask: u128 = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            let net = v & mask;
            let bcast = net | !mask;
            Some((net, bcast, true))
        }
    }
}

fn normalize_asn(s: &str) -> Option<u32> {
    let t = s.trim().trim_start_matches("AS").trim_start_matches("as");
    t.parse::<u32>().ok()
}

fn ripestat_cached(asn: u32) -> Result<Vec<String>> {
    if let Some(cache) = ASN_CACHE.get() {
        if let Some(v) = cache.lock().unwrap().get(&asn) {
            return Ok(v.clone());
        }
    }
    let v = ripestat_prefixes(asn)?;
    if let Some(cache) = ASN_CACHE.get() {
        cache.lock().unwrap().insert(asn, v.clone());
    }
    Ok(v)
}

fn ripestat_prefixes(asn: u32) -> Result<Vec<String>> {
    let url = format!(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    );
    let mut last_err: Option<String> = None;
    for attempt in 1..=4 {
        match http_get(&url).and_then(|body| {
            let v: serde_json::Value = serde_json::from_slice(&body)?;
            if v.get("status").and_then(|s| s.as_str()) != Some("ok") {
                return Err(format!("RIPEstat AS{asn}: bad status").into());
            }
            let arr = v.pointer("/data/prefixes").and_then(|x| x.as_array())
                .ok_or("RIPEstat: no prefixes array")?;
            Ok(arr.iter()
                .filter_map(|p| p.get("prefix").and_then(|x| x.as_str()).map(String::from))
                .collect::<Vec<_>>())
        }) {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e.to_string());
                std::thread::sleep(std::time::Duration::from_millis(500 * attempt));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "ripestat: unknown error".into()).into())
}

fn extract_tokens(body: &[u8], regex: &str) -> Result<Vec<String>> {
    let text = String::from_utf8_lossy(body);
    let re = regex::Regex::new(&format!("(?m){regex}"))
        .map_err(|e| format!("regex: {e}"))?;
    Ok(re.captures_iter(&text)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect())
}

pub struct FeedResult {
    pub name: String,
    pub provider: Option<String>,
    pub flags: u32,
    pub v4: Vec<(u32, u32)>,
    pub v6: Vec<(u128, u128)>,
}

fn collect_ranges(tokens: &[String]) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for tok in tokens {
        if let Some((s, e, is6)) = parse_token(tok) {
            if is6 { v6.push((s, e)); }
            else { v4.push((s as u32, e as u32)); }
        }
    }
    (v4, v6)
}

fn resolve_asns(asns: Vec<u32>) -> Vec<String> {
    let asns = Mutex::new(asns);
    let prefixes: Mutex<Vec<String>> = Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..ASN_WORKERS {
            s.spawn(|| loop {
                let asn = match asns.lock().unwrap().pop() {
                    Some(a) => a,
                    None => break,
                };
                match ripestat_cached(asn) {
                    Ok(ps) => prefixes.lock().unwrap().extend(ps),
                    Err(e) => eprintln!("  AS{asn}: {e}"),
                }
            });
        }
    });
    prefixes.into_inner().unwrap()
}

pub fn run_feed(spec: &FeedSpec, flag_names: &[String]) -> Result<FeedResult> {
    let flags = flag_mask(&spec.flags, flag_names);

    let tokens = if spec.is_asn && !spec.asns.is_empty() {
        spec.asns.clone()
    } else if spec.url.is_empty() {
        return Err(format!("{}: empty url and no static asns", spec.name).into());
    } else {
        let body = http_get(&spec.url)?;
        extract_tokens(&body, &spec.regex)?
    };

    if tokens.is_empty() {
        return Err(format!("{}: 0 tokens extracted", spec.name).into());
    }

    let (v4, v6) = if spec.is_asn {
        let asn_set: HashSet<u32> = tokens.iter()
            .filter_map(|t| normalize_asn(t)).collect();
        if asn_set.is_empty() {
            return Err(format!("{}: 0 valid ASNs", spec.name).into());
        }
        let prefixes = resolve_asns(asn_set.into_iter().collect());
        if prefixes.is_empty() {
            return Err(format!("{}: 0 prefixes resolved", spec.name).into());
        }
        collect_ranges(&prefixes)
    } else {
        collect_ranges(&tokens)
    };

    if v4.is_empty() && v6.is_empty() {
        return Err(format!("{}: 0 IPs after parsing", spec.name).into());
    }

    Ok(FeedResult {
        name: spec.name.clone(),
        provider: spec.provider.clone(),
        flags,
        v4,
        v6,
    })
}

pub fn build_db(feeds_file: &Path, out: &Path, verbose: bool) -> Result<()> {
    let ff: FeedsFile = serde_json::from_slice(&fs::read(feeds_file)?)?;
    let flag_names = ff.flags.clone();
    load_asn_cache();

    let queue: Mutex<Vec<(usize, FeedSpec)>> =
        Mutex::new(ff.feeds.iter().cloned().enumerate().rev().collect());
    let results: Mutex<Vec<Option<std::result::Result<FeedResult, String>>>> =
        Mutex::new((0..ff.feeds.len()).map(|_| None).collect());

    std::thread::scope(|s| {
        for _ in 0..WORKERS {
            s.spawn(|| loop {
                let item = queue.lock().unwrap().pop();
                match item {
                    Some((i, spec)) => {
                        let r = run_feed(&spec, &flag_names)
                            .map_err(|e| e.to_string());
                        results.lock().unwrap()[i] = Some(r);
                    }
                    None => break,
                }
            });
        }
    });

    let results = results.into_inner().unwrap();
    let mut failures: Vec<String> = Vec::new();

    let mut b = Builder::new();
    for r in results.iter().flatten() {
        match r {
            Err(e) => {
                eprintln!("  FAIL {}", e);
                failures.push(e.clone());
            }
            Ok(r) => {
                let prov_id = b.intern(r.provider.as_deref().unwrap_or(""));
                let src_id = b.intern(&r.name);
                let val_id = b.value_id(r.flags, prov_id, src_id);
                for &(s, e) in &r.v4 { b.push_v4(s, e, val_id); }
                for &(s, e) in &r.v6 { b.push_v6(s, e, val_id); }
                if verbose {
                    println!("  {:<24} v4={:7} v6={:7}", r.name, r.v4.len(), r.v6.len());
                }
            }
        }
    }

    if !failures.is_empty() {
        let _ = save_asn_cache();
        return Err(format!("{} feed(s) failed:\n  {}",
            failures.len(), failures.join("\n  ")).into());
    }

    let v4n = b.v4.len();
    let v6n = b.v6.len();
    b.finalize();
    if verbose {
        println!("merge: v4 {} -> {} | v6 {} -> {}", v4n, b.v4.len(), v6n, b.v6.len());
        println!("values: {} | strings: {}", b.values.len(), b.strings.len());
    }
    b.write(out)?;
    save_asn_cache()?;
    Ok(())
}

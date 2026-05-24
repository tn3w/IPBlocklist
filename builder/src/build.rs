use crate::db::{Builder, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) \
    Chrome/131.0.0.0 Safari/537.36";
const WORKERS: usize = 8;

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
    #[serde(default)]
    pub only_unique: bool,
    #[serde(default)]
    pub provider_map_url: Option<String>,
}

const REQUEST_CACHE_DIR: &str = "request_cache";

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

pub struct Coverage {
    pub v4: Vec<(u32, u32)>,
    pub v6: Vec<(u128, u128)>,
}

pub fn merge_v4(mut r: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    r.sort_unstable_by_key(|x| x.0);
    let mut out: Vec<(u32, u32)> = Vec::with_capacity(r.len());
    for (s, e) in r {
        if let Some(last) = out.last_mut() {
            if s <= last.1.saturating_add(1) {
                if e > last.1 { last.1 = e; }
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

pub fn merge_v6(mut r: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    r.sort_unstable_by_key(|x| x.0);
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(r.len());
    for (s, e) in r {
        if let Some(last) = out.last_mut() {
            if s <= last.1.saturating_add(1) {
                if e > last.1 { last.1 = e; }
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

pub fn subtract_v4(target: &[(u32, u32)], cover: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for &(a, b) in target {
        let mut cur = a;
        let mut i = cover.partition_point(|c| c.1 < cur);
        while i < cover.len() && cover[i].0 <= b {
            if cover[i].0 > cur {
                out.push((cur, cover[i].0 - 1));
            }
            if cover[i].1 == u32::MAX { cur = u32::MAX; break; }
            cur = cover[i].1 + 1;
            if cur > b { break; }
            i += 1;
        }
        if cur <= b && !(cur == u32::MAX && i < cover.len() && cover[i].1 == u32::MAX) {
            out.push((cur, b));
        }
    }
    out
}

pub fn subtract_v6(target: &[(u128, u128)], cover: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut out = Vec::new();
    for &(a, b) in target {
        let mut cur = a;
        let mut i = cover.partition_point(|c| c.1 < cur);
        while i < cover.len() && cover[i].0 <= b {
            if cover[i].0 > cur {
                out.push((cur, cover[i].0 - 1));
            }
            if cover[i].1 == u128::MAX { cur = u128::MAX; break; }
            cur = cover[i].1 + 1;
            if cur > b { break; }
            i += 1;
        }
        if cur <= b && !(cur == u128::MAX && i < cover.len() && cover[i].1 == u128::MAX) {
            out.push((cur, b));
        }
    }
    out
}

pub fn parse_provider_map(body: &[u8]) -> (Vec<(u32, u32, String)>, Vec<(u128, u128, String)>) {
    let text = String::from_utf8_lossy(body);
    let mut dict: HashMap<u32, String> = HashMap::new();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut section: u8 = 0;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() { continue; }
        if l == "#dict" { section = 1; continue; }
        if l == "#data" { section = 2; continue; }
        if l.starts_with('#') { continue; }
        let mut parts = l.splitn(2, '\t');
        let a = match parts.next() { Some(x) => x, None => continue };
        let b = match parts.next() { Some(x) => x, None => continue };
        if section == 1 {
            if let Ok(idx) = a.parse::<u32>() {
                dict.insert(idx, b.to_string());
            }
        } else if section == 2 {
            let idx: u32 = match b.trim().parse() { Ok(x) => x, Err(_) => continue };
            let name = match dict.get(&idx) { Some(s) => s.clone(), None => continue };
            let (ip_str, span) = match a.split_once('+') {
                Some((ip, sp)) => (ip, sp.parse::<u128>().unwrap_or(0)),
                None => (a, 0u128),
            };
            let ip: IpAddr = match ip_str.parse() { Ok(x) => x, Err(_) => continue };
            match ip {
                IpAddr::V4(x) => {
                    let s = u32::from(x);
                    let e = s.saturating_add(span as u32);
                    v4.push((s, e, name));
                }
                IpAddr::V6(x) => {
                    let s = u128::from(x);
                    let e = s.saturating_add(span);
                    v6.push((s, e, name));
                }
            }
        }
    }
    v4.sort_by_key(|r| r.0);
    v6.sort_by_key(|r| r.0);
    (v4, v6)
}

fn split_v4(ranges: &[(u32, u32)], map: &[(u32, u32, String)])
    -> HashMap<String, Vec<(u32, u32)>>
{
    let mut g: HashMap<String, Vec<(u32, u32)>> = HashMap::new();
    for &(a, b) in ranges {
        let mut cur = a;
        let mut i = map.partition_point(|m| m.1 < cur);
        while i < map.len() && map[i].0 <= b {
            if map[i].0 > cur {
                g.entry(String::new()).or_default().push((cur, map[i].0 - 1));
                cur = map[i].0;
            }
            let end = map[i].1.min(b);
            g.entry(map[i].2.clone()).or_default().push((cur, end));
            if end == u32::MAX || end >= b { cur = u32::MAX; break; }
            cur = end + 1;
            i += 1;
        }
        if cur <= b { g.entry(String::new()).or_default().push((cur, b)); }
    }
    g
}

fn split_v6(ranges: &[(u128, u128)], map: &[(u128, u128, String)])
    -> HashMap<String, Vec<(u128, u128)>>
{
    let mut g: HashMap<String, Vec<(u128, u128)>> = HashMap::new();
    for &(a, b) in ranges {
        let mut cur = a;
        let mut i = map.partition_point(|m| m.1 < cur);
        while i < map.len() && map[i].0 <= b {
            if map[i].0 > cur {
                g.entry(String::new()).or_default().push((cur, map[i].0 - 1));
                cur = map[i].0;
            }
            let end = map[i].1.min(b);
            g.entry(map[i].2.clone()).or_default().push((cur, end));
            if end == u128::MAX || end >= b { cur = u128::MAX; break; }
            cur = end + 1;
            i += 1;
        }
        if cur <= b { g.entry(String::new()).or_default().push((cur, b)); }
    }
    g
}

fn group_by_provider(
    spec: &FeedSpec, flags: u32,
    v4: &[(u32, u32)], v6: &[(u128, u128)],
    map4: &[(u32, u32, String)], map6: &[(u128, u128, String)],
) -> Vec<FeedResult> {
    let g4 = split_v4(v4, map4);
    let g6 = split_v6(v6, map6);
    let mut groups: HashMap<String, (Vec<(u32, u32)>, Vec<(u128, u128)>)> = HashMap::new();
    for (p, r) in g4 { groups.entry(p).or_default().0 = r; }
    for (p, r) in g6 { groups.entry(p).or_default().1 = r; }
    let mut out = Vec::new();
    for (p, (v4, v6)) in groups {
        if v4.is_empty() && v6.is_empty() { continue; }
        out.push(FeedResult {
            name: spec.name.clone(),
            provider: if p.is_empty() { None } else { Some(p) },
            flags, v4, v6,
        });
    }
    out
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

fn provider_for(spec: &FeedSpec, asn: u32) -> String {
    if let Some(p) = &spec.provider {
        return p.clone();
    }
    crate::asn_db::lookup_org(asn).unwrap_or_default()
}

pub fn run_feed(
    spec: &FeedSpec,
    flag_names: &[String],
    coverage: Option<&Coverage>,
) -> Result<Vec<FeedResult>> {
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

    if !spec.is_asn {
        let (mut v4, mut v6) = collect_ranges(&tokens);
        if v4.is_empty() && v6.is_empty() {
            return Err(format!("{}: 0 IPs after parsing", spec.name).into());
        }
        if let Some(map_url) = &spec.provider_map_url {
            let body = http_get(map_url)?;
            let (map4, map6) = parse_provider_map(&body);
            let mut groups = group_by_provider(spec, flags, &v4, &v6, &map4, &map6);
            if spec.only_unique {
                let cov = coverage.ok_or_else(||
                    format!("{}: only_unique requires coverage", spec.name))?;
                groups.retain_mut(|g| {
                    if g.provider.is_some() { return true; }
                    g.v4 = subtract_v4(&merge_v4(std::mem::take(&mut g.v4)), &cov.v4);
                    g.v6 = subtract_v6(&merge_v6(std::mem::take(&mut g.v6)), &cov.v6);
                    !g.v4.is_empty() || !g.v6.is_empty()
                });
            }
            if groups.is_empty() {
                return Err(format!("{}: 0 IPs after uniqueness filter", spec.name).into());
            }
            return Ok(groups);
        }
        if spec.only_unique {
            let cov = coverage.ok_or_else(||
                format!("{}: only_unique requires coverage", spec.name))?;
            v4 = subtract_v4(&merge_v4(v4), &cov.v4);
            v6 = subtract_v6(&merge_v6(v6), &cov.v6);
            if v4.is_empty() && v6.is_empty() {
                return Err(format!("{}: 0 IPs after uniqueness filter", spec.name).into());
            }
        }
        return Ok(vec![FeedResult {
            name: spec.name.clone(),
            provider: spec.provider.clone(),
            flags, v4, v6,
        }]);
    }

    let asn_set: HashSet<u32> = tokens.iter()
        .filter_map(|t| normalize_asn(t)).collect();
    if asn_set.is_empty() {
        return Err(format!("{}: 0 valid ASNs", spec.name).into());
    }

    let mut groups: HashMap<String, (Vec<(u32, u32)>, Vec<(u128, u128)>)> = HashMap::new();
    for asn in asn_set {
        let provider = provider_for(spec, asn);
        let (v4, v6) = crate::asn_db::prefixes_for(asn);
        let entry = groups.entry(provider).or_default();
        entry.0.extend(v4);
        entry.1.extend(v6);
    }

    let mut out = Vec::new();
    for (provider, (v4, v6)) in groups {
        if v4.is_empty() && v6.is_empty() { continue; }
        out.push(FeedResult {
            name: spec.name.clone(),
            provider: if provider.is_empty() { None } else { Some(provider) },
            flags, v4, v6,
        });
    }
    if out.is_empty() {
        return Err(format!("{}: 0 IPs after parsing", spec.name).into());
    }
    Ok(out)
}

pub fn build_db(feeds_file: &Path, out: &Path, verbose: bool) -> Result<()> {
    let ff: FeedsFile = serde_json::from_slice(&fs::read(feeds_file)?)?;
    let flag_names = ff.flags.clone();

    if ff.feeds.iter().any(|f| f.is_asn) {
        crate::asn_db::init()?;
    }

    let normal: Vec<(usize, FeedSpec)> = ff.feeds.iter().cloned().enumerate()
        .filter(|(_, f)| !f.only_unique).collect();
    let unique: Vec<(usize, FeedSpec)> = ff.feeds.iter().cloned().enumerate()
        .filter(|(_, f)| f.only_unique).collect();

    let run_batch = |batch: Vec<(usize, FeedSpec)>, cov: Option<&Coverage>|
        -> Vec<(usize, std::result::Result<Vec<FeedResult>, String>)>
    {
        let queue: Mutex<Vec<(usize, FeedSpec)>> = Mutex::new(batch.into_iter().rev().collect());
        let out: Mutex<Vec<(usize, std::result::Result<Vec<FeedResult>, String>)>> =
            Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..WORKERS {
                s.spawn(|| loop {
                    let item = queue.lock().unwrap().pop();
                    match item {
                        Some((i, spec)) => {
                            let r = run_feed(&spec, &flag_names, cov)
                                .map_err(|e| e.to_string());
                            out.lock().unwrap().push((i, r));
                        }
                        None => break,
                    }
                });
            }
        });
        out.into_inner().unwrap()
    };

    let normal_results = run_batch(normal, None);

    let mut cov_v4: Vec<(u32, u32)> = Vec::new();
    let mut cov_v6: Vec<(u128, u128)> = Vec::new();
    for (_, r) in &normal_results {
        if let Ok(parts) = r {
            for p in parts {
                cov_v4.extend(&p.v4);
                cov_v6.extend(&p.v6);
            }
        }
    }
    let coverage = Coverage { v4: merge_v4(cov_v4), v6: merge_v6(cov_v6) };

    let unique_results = run_batch(unique, Some(&coverage));

    let mut results: Vec<Option<std::result::Result<Vec<FeedResult>, String>>> =
        (0..ff.feeds.len()).map(|_| None).collect();
    for (i, r) in normal_results.into_iter().chain(unique_results.into_iter()) {
        results[i] = Some(r);
    }
    let mut failures = 0usize;

    let mut b = Builder::new();
    for r in results.iter().flatten() {
        match r {
            Err(e) => {
                eprintln!("  FAIL {}", e);
                failures += 1;
            }
            Ok(parts) => {
                for r in parts {
                    let prov_id = b.intern(r.provider.as_deref().unwrap_or(""));
                    let src_id = b.intern(&r.name);
                    let val_id = b.value_id(r.flags, prov_id, src_id);
                    for &(s, e) in &r.v4 { b.push_v4(s, e, val_id); }
                    for &(s, e) in &r.v6 { b.push_v6(s, e, val_id); }
                    if verbose {
                        println!("  {:<24} provider={:<28} v4={:6} v6={:6}",
                            r.name, r.provider.as_deref().unwrap_or(""),
                            r.v4.len(), r.v6.len());
                    }
                }
            }
        }
    }

    if failures > 0 {
        eprintln!("warning: {failures} feed(s) failed, continuing");
    }

    let v4n = b.v4.len();
    let v6n = b.v6.len();
    b.finalize()?;
    if verbose {
        println!("merge: v4 {} -> {} | v6 {} -> {}",
            v4n, b.v4.len(), v6n, b.v6.len());
        println!("values: {} | strings: {}",
            b.values.len(), b.strings.len());
    }
    b.write(out)?;
    Ok(())
}

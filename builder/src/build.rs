use crate::db::{Builder, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

struct AsnDb {
    names: HashMap<u32, String>,
    v4: HashMap<u32, Vec<(u32, u32)>>,
    v6: HashMap<u32, Vec<(u128, u128)>>,
}

static ASN_DB: OnceLock<AsnDb> = OnceLock::new();

fn asn_env_path(key: &str, fallbacks: &[&str]) -> PathBuf {
    if let Some(p) = std::env::var_os(key) {
        return PathBuf::from(p);
    }
    for c in fallbacks {
        let p = PathBuf::from(c);
        if p.exists() { return p; }
    }
    PathBuf::from(fallbacks[0])
}

fn parse_provider_tsv(text: &str) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let Some((a, n)) = line.split_once('\t') else { continue };
        let Ok(asn) = a.trim().parse::<u32>() else { continue };
        let name = n.trim();
        if !name.is_empty() {
            m.insert(asn, name.to_string());
        }
    }
    m
}

fn cidr_to_range(cidr: &str) -> Option<(IpAddr, IpAddr)> {
    let (ip, p) = cidr.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let prefix: u32 = p.parse().ok()?;
    match ip {
        IpAddr::V4(a) => {
            if prefix > 32 { return None; }
            let v = u32::from(a);
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let net = v & mask;
            let bcast = net | !mask;
            Some((IpAddr::from(net.to_be_bytes()), IpAddr::from(bcast.to_be_bytes())))
        }
        IpAddr::V6(a) => {
            if prefix > 128 { return None; }
            let v = u128::from(a);
            let mask: u128 = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            let net = v & mask;
            let bcast = net | !mask;
            Some((IpAddr::from(net.to_be_bytes()), IpAddr::from(bcast.to_be_bytes())))
        }
    }
}

fn parse_prefixes_csv(
    text: &str,
) -> (HashMap<u32, Vec<(u32, u32)>>, HashMap<u32, Vec<(u128, u128)>>) {
    let mut v4: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
    let mut v6: HashMap<u32, Vec<(u128, u128)>> = HashMap::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 && line.starts_with("asn,") { continue; }
        let mut it = line.splitn(3, ',');
        let Some(a) = it.next() else { continue };
        let Some(cidr) = it.next() else { continue };
        let Ok(asn) = a.trim().parse::<u32>() else { continue };
        let Some((s, e)) = cidr_to_range(cidr.trim()) else { continue };
        match (s, e) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                v4.entry(asn).or_default().push((u32::from(s), u32::from(e)));
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                v6.entry(asn).or_default().push((u128::from(s), u128::from(e)));
            }
            _ => {}
        }
    }
    (v4, v6)
}

fn asn_db_init() -> Result<()> {
    let provider = asn_env_path(
        "ASN_PROVIDER_FILE",
        &["asn-provider.tsv", "../asn-provider.tsv"],
    );
    let prefixes = asn_env_path(
        "ASN_PREFIXES_FILE",
        &["asn-prefixes.csv", "../asn-prefixes.csv"],
    );
    eprintln!("loading asn provider: {}", provider.display());
    eprintln!("loading asn prefixes: {}", prefixes.display());
    let names = parse_provider_tsv(
        &fs::read_to_string(&provider)
            .map_err(|e| format!("{}: {e}", provider.display()))?,
    );
    let (v4, v6) = parse_prefixes_csv(
        &fs::read_to_string(&prefixes)
            .map_err(|e| format!("{}: {e}", prefixes.display()))?,
    );
    let _ = ASN_DB.set(AsnDb { names, v4, v6 });
    Ok(())
}

fn asn_lookup_org(asn: u32) -> Option<String> {
    ASN_DB.get()?.names.get(&asn).cloned()
}

fn asn_prefixes_for(asn: u32) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let Some(db) = ASN_DB.get() else { return (Vec::new(), Vec::new()); };
    let v4 = db.v4.get(&asn).cloned().unwrap_or_default();
    let v6 = db.v6.get(&asn).cloned().unwrap_or_default();
    (v4, v6)
}

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
    asn_lookup_org(asn).unwrap_or_default()
}

pub fn run_feed(spec: &FeedSpec, flag_names: &[String]) -> Result<Vec<FeedResult>> {
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
        let (v4, v6) = collect_ranges(&tokens);
        if v4.is_empty() && v6.is_empty() {
            return Err(format!("{}: 0 IPs after parsing", spec.name).into());
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
        let (v4, v6) = asn_prefixes_for(asn);
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
        asn_db_init()?;
    }

    let queue: Mutex<Vec<(usize, FeedSpec)>> =
        Mutex::new(ff.feeds.iter().cloned().enumerate().rev().collect());
    let results: Mutex<Vec<Option<std::result::Result<Vec<FeedResult>, String>>>> =
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

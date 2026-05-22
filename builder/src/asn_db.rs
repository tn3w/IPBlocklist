use crate::db::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

const MAGIC: u64 = 0x000442444E534144;

struct Asndb {
    v4: HashMap<u32, Vec<(u32, u32)>>,
    v6: HashMap<u32, Vec<(u128, u128)>>,
    names: HashMap<u32, String>,
}

static DB: OnceLock<Asndb> = OnceLock::new();

fn db_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ASNDB_FILE") {
        return PathBuf::from(p);
    }
    for c in ["asndb-mini.bin", "../asndb-mini.bin"] {
        let p = PathBuf::from(c);
        if p.exists() { return p; }
    }
    PathBuf::from("asndb-mini.bin")
}

fn provider_path() -> PathBuf {
    if let Some(p) = std::env::var_os("ASN_PROVIDER_FILE") {
        return PathBuf::from(p);
    }
    for c in ["asn-provider.tsv", "../asn-provider.tsv"] {
        let p = PathBuf::from(c);
        if p.exists() { return p; }
    }
    PathBuf::from("asn-provider.tsv")
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn build_v4(bytes: &[u8], off: usize, count: usize) -> HashMap<u32, Vec<(u32, u32)>> {
    let mut map: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
    for i in 0..count {
        let o = off + i * 8;
        let start = u32_at(bytes, o);
        let aidx = u32_at(bytes, o + 4);
        if aidx == u32::MAX { continue; }
        let end = if i + 1 < count {
            u32_at(bytes, off + (i + 1) * 8).saturating_sub(1)
        } else {
            u32::MAX
        };
        map.entry(aidx).or_default().push((start, end));
    }
    map
}

fn build_v6(bytes: &[u8], off: usize, count: usize) -> HashMap<u32, Vec<(u128, u128)>> {
    let mut map: HashMap<u32, Vec<(u128, u128)>> = HashMap::new();
    for i in 0..count {
        let o = off + i * 20;
        let start = u128::from_be_bytes(bytes[o..o + 16].try_into().unwrap());
        let aidx = u32_at(bytes, o + 16);
        if aidx == u32::MAX { continue; }
        let end = if i + 1 < count {
            let no = off + (i + 1) * 20;
            u128::from_be_bytes(bytes[no..no + 16].try_into().unwrap()).saturating_sub(1)
        } else {
            u128::MAX
        };
        map.entry(aidx).or_default().push((start, end));
    }
    map
}

fn asn_index_map(bytes: &[u8], off: usize, count: usize) -> HashMap<u32, u32> {
    let mut m = HashMap::with_capacity(count);
    for i in 0..count {
        let asn = u32_at(bytes, off + i * 8);
        m.insert(asn, i as u32);
    }
    m
}

fn load_names() -> Result<HashMap<u32, String>> {
    let path = provider_path();
    eprintln!("loading asn-provider: {}", path.display());
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("asn-provider {}: {e}", path.display()))?;
    let mut m = HashMap::new();
    for line in text.lines() {
        let Some((a, n)) = line.split_once('\t') else { continue; };
        let Ok(asn) = a.trim().parse::<u32>() else { continue; };
        let name = n.trim();
        if !name.is_empty() {
            m.insert(asn, name.to_string());
        }
    }
    Ok(m)
}

pub fn init() -> Result<()> {
    let path = db_path();
    eprintln!("loading asndb: {}", path.display());
    let bytes = fs::read(&path)
        .map_err(|e| format!("asndb {}: {e}", path.display()))?;
    if bytes.len() < 104 {
        return Err("asndb: file too small".into());
    }
    if u64_at(&bytes, 0) != MAGIC {
        return Err("asndb: bad magic".into());
    }
    let flavor = bytes[8];
    if flavor != 1 {
        return Err(format!("asndb: expected mini flavor (1), got {flavor}").into());
    }

    let asn_count = u32_at(&bytes, 16) as usize;
    let seg4_count = u32_at(&bytes, 20) as usize;
    let seg6_count = u32_at(&bytes, 24) as usize;
    let asn_off = u64_at(&bytes, 40) as usize;
    let seg4_off = u64_at(&bytes, 48) as usize;
    let seg6_off = u64_at(&bytes, 56) as usize;

    let asn_to_idx = asn_index_map(&bytes, asn_off, asn_count);
    let v4_by_idx = build_v4(&bytes, seg4_off, seg4_count);
    let v6_by_idx = build_v6(&bytes, seg6_off, seg6_count);

    let mut v4: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
    let mut v6: HashMap<u32, Vec<(u128, u128)>> = HashMap::new();
    for (asn, idx) in &asn_to_idx {
        if let Some(p) = v4_by_idx.get(idx) { v4.insert(*asn, p.clone()); }
        if let Some(p) = v6_by_idx.get(idx) { v6.insert(*asn, p.clone()); }
    }

    let names = load_names()?;
    let _ = DB.set(Asndb { v4, v6, names });
    Ok(())
}

pub fn lookup_org(asn: u32) -> Option<String> {
    DB.get()?.names.get(&asn).cloned()
}

pub fn prefixes_for(asn: u32) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let db = DB.get().expect("asndb not initialized");
    let v4 = db.v4.get(&asn).cloned().unwrap_or_default();
    let v6 = db.v6.get(&asn).cloned().unwrap_or_default();
    (v4, v6)
}

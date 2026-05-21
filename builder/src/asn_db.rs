use crate::db::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

const MAGIC: u64 = 0x000442444E534144;
const MINI_REC: usize = 8;

struct Asndb {
    bytes: Vec<u8>,
    asn_off: usize,
    asn_count: usize,
    str_off: usize,
    v4_by_idx: HashMap<u32, Vec<(u32, u32)>>,
    v6_by_idx: HashMap<u32, Vec<(u128, u128)>>,
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

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn build_v4_index(bytes: &[u8], off: usize, count: usize) -> HashMap<u32, Vec<(u32, u32)>> {
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

fn build_v6_index(bytes: &[u8], off: usize, count: usize) -> HashMap<u32, Vec<(u128, u128)>> {
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
    let str_off = u64_at(&bytes, 88) as usize;

    let v4_by_idx = build_v4_index(&bytes, seg4_off, seg4_count);
    let v6_by_idx = build_v6_index(&bytes, seg6_off, seg6_count);

    let db = Asndb {
        bytes, asn_off, asn_count, str_off, v4_by_idx, v6_by_idx,
    };
    let _ = DB.set(db);
    Ok(())
}

fn db_ref() -> &'static Asndb {
    DB.get().expect("asndb not initialized")
}

fn asn_at(db: &Asndb, i: usize) -> u32 {
    u32_at(&db.bytes, db.asn_off + i * MINI_REC)
}

fn name_off_at(db: &Asndb, i: usize) -> u32 {
    u32_at(&db.bytes, db.asn_off + i * MINI_REC + 4)
}

fn read_str(db: &Asndb, off: u32) -> String {
    if off == 0 {
        return String::new();
    }
    let base = db.str_off + off as usize;
    let n = u32_at(&db.bytes, base) as usize;
    String::from_utf8_lossy(&db.bytes[base + 4..base + 4 + n]).into_owned()
}

fn asn_idx(db: &Asndb, asn: u32) -> Option<u32> {
    let mut lo = 0usize;
    let mut hi = db.asn_count;
    while lo < hi {
        let m = (lo + hi) >> 1;
        if asn_at(db, m) < asn { lo = m + 1; } else { hi = m; }
    }
    if lo < db.asn_count && asn_at(db, lo) == asn {
        Some(lo as u32)
    } else {
        None
    }
}

pub fn lookup_org(asn: u32) -> Option<String> {
    let db = DB.get()?;
    let idx = asn_idx(db, asn)?;
    let off = name_off_at(db, idx as usize);
    let s = read_str(db, off);
    if s.is_empty() { None } else { Some(s) }
}

pub fn prefixes_for(asn: u32) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let db = db_ref();
    let Some(idx) = asn_idx(db, asn) else {
        return (Vec::new(), Vec::new());
    };
    let v4 = db.v4_by_idx.get(&idx).cloned().unwrap_or_default();
    let v6 = db.v6_by_idx.get(&idx).cloned().unwrap_or_default();
    (v4, v6)
}


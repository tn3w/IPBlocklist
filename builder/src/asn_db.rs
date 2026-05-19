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

static SUFFIX: OnceLock<regex::Regex> = OnceLock::new();
static PREFIX: OnceLock<regex::Regex> = OnceLock::new();
static TAG: OnceLock<regex::Regex> = OnceLock::new();
static TAIL: OnceLock<regex::Regex> = OnceLock::new();
static DOMAIN: OnceLock<regex::Regex> = OnceLock::new();
static OF_TAIL: OnceLock<regex::Regex> = OnceLock::new();
static SEP: OnceLock<regex::Regex> = OnceLock::new();
static MULTI_WS: OnceLock<regex::Regex> = OnceLock::new();

const FILLER: &[&str] = &["de", "da", "do", "of", "the", "le", "la", "y", "e", "und"];

fn re(once: &'static OnceLock<regex::Regex>, pattern: &'static str)
    -> &'static regex::Regex
{
    once.get_or_init(|| regex::Regex::new(pattern).unwrap())
}

pub fn normalize(name: &str) -> String {
    let suffix = re(&SUFFIX,
        r"(?i)[, ]+(?:s\.?[apr]\.?[a-z]?\.?|sp\.? ?z\.? ?o\.?o\.?|a\.?s\.?|\
        gmbh|kg|ag|ab|oy|n\.?v\.?|b\.?v\.?|co\.?,? ?ltd\.?|\
        p?(?:vt|ty|te)\.? ?ltd\.?|sdn\.? bhd\.?|ltda?\.?|me|eireli|\
        llc|llp|l\.?p\.?|plc|limited|inc\.?|incorporated|corp(?:oration)?\.?|\
        holdings?|company|co\.?|group|enterprises?|jsc|ooo|uab|sarl|sas|srl|\
        k\.k\.|sociedad an[oó]nima|telecom(?:unica[cç][oõ]es|\
        municaciones|munications?)?|technologies|technology|tecnologia|\
        informatica|comunica[cç][aã]o|servi[cç]os|provedor|solu[cç][oõ]es|\
        networks?|solutions?|services?|systems?|international|\
        communications?|internet|digital|online|broadband|cable|fiber|\
        media|cloud|hosting|wireless)\b\.?");
    let prefix = re(&PREFIX,
        r"(?i)^(?:pt|ooo|zao|cjsc|ojsc|pjsc|jsc|the|\
        (?:closed |open |public |private )?joint[- ]stock company|\
        limited liability company)\s+");
    let tag = re(&TAG, r"(?i)[- ](?:AS|NET|ASN|CORP|HOSTING|GLOBAL|CDN|ISP)\d*\b");
    let tail = re(&TAIL, r"(?:NET|AS|ASN|CORP|HOSTING|GLOBAL|CDN|ISP)\d*$");
    let domain = re(&DOMAIN, r"(?i)\.(?:com|net|org|io|co|us)\b");
    let of_tail = re(&OF_TAIL, r"(?i)\s+of (?:the )?\w+$");
    let sep = re(&SEP, r"[\s\-_]+");
    let multi_ws = re(&MULTI_WS, r"\s{2,}");

    let mut text = name.trim().trim_matches(|c: char| ",.'\"".contains(c)).to_string();
    text = domain.replace_all(&text, "").to_string();
    text = prefix.replace(&text, "").to_string();
    loop {
        let next = suffix.replace_all(&text, "").trim_matches(|c: char| " ,.".contains(c)).to_string();
        if next == text { break; }
        text = next;
    }
    text = of_tail.replace(&text, "").to_string();
    text = tag.replace_all(&text, "").to_string();

    let no_sep = !text.contains(|c: char| c.is_whitespace() || c == '-' || c == '_');
    if no_sep && text.chars().all(|c| !c.is_alphabetic() || c.is_uppercase()) && !text.is_empty() {
        let stripped = tail.replace(&text, "").to_string();
        if !stripped.is_empty() && stripped != text {
            text = title(&stripped);
        }
    }
    let alpha: Vec<char> = text.chars().filter(|c| c.is_alphabetic()).collect();
    if !alpha.is_empty() {
        let upper = alpha.iter().filter(|c| c.is_uppercase()).count() as f32 / alpha.len() as f32;
        if upper > 0.85 || upper < 0.15 {
            let mut words: Vec<String> = sep.split(&text).filter(|s| !s.is_empty())
                .map(String::from).collect();
            while words.last().map(|w| FILLER.contains(&w.to_lowercase().as_str())).unwrap_or(false) {
                words.pop();
            }
            text = words.iter().map(|w| {
                let lo = w.to_lowercase();
                if FILLER.contains(&lo.as_str()) { lo }
                else if w.chars().all(|c| c.is_alphabetic()) && w.chars().count() >= 4 { title(w) }
                else { w.clone() }
            }).collect::<Vec<_>>().join(" ");
        }
    }
    let out = multi_ws.replace_all(&text, " ").trim_matches(|c: char| " ,-".contains(c)).to_string();
    if out.is_empty() { name.to_string() } else { out }
}

fn title(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars.flat_map(|c| c.to_lowercase())).collect(),
        None => String::new(),
    }
}

use crate::db::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

const MMDB_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb";
const MAX_AGE: Duration = Duration::from_secs(7 * 86400);

static ORG_MAP: OnceLock<HashMap<u32, String>> = OnceLock::new();

fn cache_path() -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".cache/ipblocklist-builder"))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    let _ = fs::create_dir_all(&base);
    base.join("GeoLite2-ASN.mmdb")
}

fn fresh(p: &PathBuf) -> bool {
    fs::metadata(p)
        .and_then(|m| m.modified())
        .map(|t| SystemTime::now().duration_since(t).unwrap_or(MAX_AGE) < MAX_AGE)
        .unwrap_or(false)
}

fn download(p: &PathBuf) -> Result<()> {
    eprintln!("downloading GeoLite2-ASN.mmdb...");
    let res = ureq::get(MMDB_URL).call().map_err(|e| format!("mmdb: {e}"))?;
    let mut buf = Vec::new();
    res.into_reader().read_to_end(&mut buf)?;
    fs::write(p, &buf)?;
    Ok(())
}

pub fn init() -> Result<()> {
    let path = cache_path();
    if !fresh(&path) {
        download(&path)?;
    }
    let reader = maxminddb::Reader::open_readfile(&path)
        .map_err(|e| format!("mmdb open: {e}"))?;
    let mut map: HashMap<u32, String> = HashMap::new();
    for net in [
        "0.0.0.0/0".parse().unwrap(),
        "::/0".parse().unwrap(),
    ] {
        for item in reader.within::<maxminddb::geoip2::Asn>(net)
            .map_err(|e| format!("mmdb iter: {e}"))?
        {
            let item = item.map_err(|e| format!("mmdb item: {e}"))?;
            if let (Some(asn), Some(org)) = (
                item.info.autonomous_system_number,
                item.info.autonomous_system_organization,
            ) {
                map.entry(asn).or_insert_with(|| org.to_string());
            }
        }
    }
    let _ = ORG_MAP.set(map);
    Ok(())
}

pub fn lookup_org(asn: u32) -> Option<&'static str> {
    ORG_MAP.get()?.get(&asn).map(|s| s.as_str())
}

use std::io::Read;

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

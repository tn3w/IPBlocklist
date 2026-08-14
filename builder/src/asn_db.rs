use crate::brand::brand;
use crate::db::Result;
use flate2::read::GzDecoder;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::OnceLock;

struct Asndb {
    v4: HashMap<u32, Vec<(u32, u32)>>,
    v6: HashMap<u32, Vec<(u128, u128)>>,
    names: HashMap<u32, String>,
}

static DB: OnceLock<Asndb> = OnceLock::new();

fn source_path(variable: &str, name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    let parent = PathBuf::from("..").join(name);
    if parent.exists() { parent } else { PathBuf::from(name) }
}

fn reader(path: &PathBuf) -> Result<Box<dyn BufRead>> {
    let file = File::open(path)
        .map_err(|error| format!("ip2asn {}: {error}", path.display()))?;
    let stream: Box<dyn Read> = match path.extension().is_some_and(|ext| ext == "gz") {
        true => Box::new(GzDecoder::new(file)),
        false => Box::new(file),
    };
    Ok(Box::new(BufReader::new(stream)))
}

fn addresses(first: &str, last: &str) -> Option<(IpAddr, IpAddr)> {
    Some((first.parse().ok()?, last.parse().ok()?))
}

/// RIPE `asn.txt` reads `<asn> <handle> - <company>, <CC>`, the dash often missing.
fn ripe_names(path: &PathBuf) -> Result<(HashMap<u32, String>, HashMap<u32, String>)> {
    let mut handles = HashMap::new();
    let mut companies = HashMap::new();

    for line in reader(path)?.lines() {
        let line = line.map_err(|error| format!("asnames {}: {error}", path.display()))?;
        let Some((asn, rest)) = line.split_once(' ') else { continue; };
        let Ok(asn) = asn.parse::<u32>() else { continue; };

        let name = match rest.rsplit_once(", ") {
            Some((head, country)) if country.len() == 2 => head,
            _ => rest,
        };
        let Some(handle) = name.split_whitespace().next() else { continue; };

        handles.insert(asn, handle.to_string());
        companies.insert(asn, name.split_once(" - ").map_or(name, |(_, tail)| tail)
            .to_string());
    }

    Ok((handles, companies))
}

/// CAIDA joins `aut|…|org_id|…` rows to `org_id|…|org_name|…` rows by org id.
fn caida_companies(path: &PathBuf) -> Result<HashMap<u32, String>> {
    let mut organizations: HashMap<String, String> = HashMap::new();
    let mut members: Vec<(u32, String)> = Vec::new();

    for line in reader(path)?.lines() {
        let line = line.map_err(|error| format!("as-org2info {error}"))?;
        if line.starts_with('#') {
            continue;
        }

        let fields: Vec<&str> = line.split('|').collect();
        match fields.len() {
            5 => { organizations.insert(fields[0].to_string(), fields[2].to_string()); }
            6 => if let Ok(asn) = fields[0].parse::<u32>() {
                members.push((asn, fields[3].to_string()));
            },
            _ => continue,
        }
    }

    Ok(members
        .into_iter()
        .filter_map(|(asn, org)| Some((asn, organizations.get(&org)?.clone())))
        .filter(|(_, name)| !name.is_empty())
        .collect())
}

fn load_names() -> Result<HashMap<u32, String>> {
    let asnames = source_path("RIPE_ASNAMES_FILE", "asn.txt");
    let asorg = source_path("CAIDA_ASORG_FILE", "as-org2info.txt.gz");
    eprintln!("loading names: {} + {}", asnames.display(), asorg.display());

    let (handles, mut companies) = ripe_names(&asnames)?;
    companies.extend(caida_companies(&asorg)?);

    let asns: Vec<u32> = handles.keys().chain(companies.keys()).copied().collect();
    Ok(asns
        .into_iter()
        .map(|asn| {
            let handle = handles.get(&asn).map_or("", String::as_str);
            let company = companies.get(&asn).map_or("", String::as_str);
            (asn, brand(handle, company))
        })
        .filter(|(_, name)| !name.is_empty())
        .collect())
}

pub fn init() -> Result<()> {
    let path = source_path("IP2ASN_FILE", "ip2asn-combined.tsv.gz");
    eprintln!("loading ip2asn: {}", path.display());

    let mut v4: HashMap<u32, Vec<(u32, u32)>> = HashMap::new();
    let mut v6: HashMap<u32, Vec<(u128, u128)>> = HashMap::new();

    for line in reader(&path)?.lines() {
        let line = line.map_err(|error| format!("ip2asn {}: {error}", path.display()))?;
        let mut fields = line.split('\t');
        let (Some(first), Some(last), Some(asn)) =
            (fields.next(), fields.next(), fields.next()) else { continue; };

        let Ok(asn) = asn.parse::<u32>() else { continue; };
        if asn == 0 { continue; }

        match addresses(first, last) {
            Some((IpAddr::V4(start), IpAddr::V4(end))) => {
                v4.entry(asn).or_default().push((start.into(), end.into()));
            }
            Some((IpAddr::V6(start), IpAddr::V6(end))) => {
                v6.entry(asn).or_default().push((start.into(), end.into()));
            }
            _ => continue,
        }
    }

    if v4.is_empty() && v6.is_empty() {
        return Err(format!("ip2asn {}: no ranges parsed", path.display()).into());
    }

    let _ = DB.set(Asndb { v4, v6, names: load_names()? });
    Ok(())
}

pub fn lookup_org(asn: u32) -> Option<String> {
    DB.get()?.names.get(&asn).cloned()
}

pub fn prefixes_for(asn: u32) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
    let db = DB.get().expect("ip2asn not initialized");
    let v4 = db.v4.get(&asn).cloned().unwrap_or_default();
    let v6 = db.v6.get(&asn).cloned().unwrap_or_default();
    (v4, v6)
}

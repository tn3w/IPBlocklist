use crate::db::{score_for_flags, Db, Result};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const FLAG_NAMES: [&str; 20] = [
    "vpn", "proxy", "tor", "malware", "c2", "scanner", "brute_force",
    "spammer", "compromised", "datacenter", "cdn", "anycast", "crawler",
    "bot", "cloud", "private_relay", "anonymizer", "mobile", "isp",
    "government",
];
const FLAG_SEV: [u8; 20] = [
    30, 25, 45, 95, 95, 55, 70, 65, 75, 15,
    5,  0,  10, 0,  10, 15, 35, 0,  0,  0,
];

pub struct Stats {
    pub v4_ranges: usize,
    pub v6_ranges: usize,
    pub v4_lines: usize,
    pub v6_lines: usize,
    pub v4_ips: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format { Range, Cidr }

pub fn build(db: &Db, out: &Path, threshold: u8, fmt: Format) -> Result<Stats> {
    let mut v4: Vec<(u32, u32)> = Vec::new();
    db.iter_v4(|s, e, flags| {
        if score_for_flags(flags) >= threshold {
            v4.push((s, e));
        }
    });
    v4.sort_unstable();
    let v4 = merge_u32(v4);

    let mut v6: Vec<(u128, u128)> = Vec::new();
    db.iter_v6(|s, e, flags| {
        if score_for_flags(flags) >= threshold {
            v6.push((s, e));
        }
    });
    v6.sort_unstable();
    let v6 = merge_u128(v6);

    let mut w = BufWriter::new(File::create(out)?);
    write_header(&mut w, out, threshold, fmt, v4.len(), v6.len())?;
    let mut ips = 0u64;
    let mut v4_lines = 0usize;
    let mut v6_lines = 0usize;
    for &(s, e) in &v4 {
        ips += (e - s) as u64 + 1;
        match fmt {
            Format::Range => {
                if s == e {
                    writeln!(w, "{}", Ipv4Addr::from(s))?;
                } else {
                    writeln!(w, "{}-{}", Ipv4Addr::from(s), Ipv4Addr::from(e))?;
                }
                v4_lines += 1;
            }
            Format::Cidr => {
                for (a, p) in range_to_cidrs_u32(s, e) {
                    if p == 32 {
                        writeln!(w, "{}", Ipv4Addr::from(a))?;
                    } else {
                        writeln!(w, "{}/{}", Ipv4Addr::from(a), p)?;
                    }
                    v4_lines += 1;
                }
            }
        }
    }
    for &(s, e) in &v6 {
        match fmt {
            Format::Range => {
                if s == e {
                    writeln!(w, "{}", Ipv6Addr::from(s))?;
                } else {
                    writeln!(w, "{}-{}", Ipv6Addr::from(s), Ipv6Addr::from(e))?;
                }
                v6_lines += 1;
            }
            Format::Cidr => {
                for (a, p) in range_to_cidrs_u128(s, e) {
                    if p == 128 {
                        writeln!(w, "{}", Ipv6Addr::from(a))?;
                    } else {
                        writeln!(w, "{}/{}", Ipv6Addr::from(a), p)?;
                    }
                    v6_lines += 1;
                }
            }
        }
    }
    w.flush()?;
    drop(w);
    let bytes = std::fs::metadata(out)?.len();
    Ok(Stats {
        v4_ranges: v4.len(),
        v6_ranges: v6.len(),
        v4_lines, v6_lines,
        v4_ips: ips,
        bytes,
    })
}

fn write_header<W: Write>(
    w: &mut W, path: &Path, threshold: u8, fmt: Format,
    v4_ranges: usize, v6_ranges: usize,
) -> std::io::Result<()> {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("blocklist");
    let kind = match fmt {
        Format::Cidr => "ipv4+ipv6 hash:net netset",
        Format::Range => "ipv4+ipv6 iprange list",
    };
    let flags: Vec<&str> = FLAG_NAMES.iter().enumerate()
        .filter(|(i, _)| FLAG_SEV[*i] >= threshold)
        .map(|(_, n)| *n).collect();
    let date = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| format_utc(d.as_secs())).unwrap_or_else(|_| "unknown".into());
    writeln!(w, "#")?;
    writeln!(w, "# {name}")?;
    writeln!(w, "#")?;
    writeln!(w, "# {kind}")?;
    writeln!(w, "#")?;
    writeln!(w, "# Aggregated IP intelligence: ranges where the max flag")?;
    writeln!(w, "# severity is >= {threshold}/100. Suitable for blocking or")?;
    writeln!(w, "# challenging clients exhibiting bot/abuse behavior.")?;
    writeln!(w, "#")?;
    writeln!(w, "# Maintainer      : IPBlocklist")?;
    writeln!(w, "# Maintainer URL  : https://github.com/tn3w/IPBlocklist")?;
    writeln!(w, "# List source URL : feeds-intel.json (see repo)")?;
    writeln!(w, "# Source File Date: {date}")?;
    writeln!(w, "# Category        : reputation")?;
    writeln!(w, "# Version         : 1")?;
    writeln!(w, "#")?;
    writeln!(w, "# Threshold       : {threshold}")?;
    writeln!(w, "# Flags included  : {}", flags.join(", "))?;
    writeln!(w, "# Entries (v4)    : {v4_ranges}")?;
    writeln!(w, "# Entries (v6)    : {v6_ranges}")?;
    writeln!(w, "#")?;
    Ok(())
}

fn format_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let mut rem = (secs % 86400) as u32;
    let h = rem / 3600; rem %= 3600;
    let m = rem / 60;
    let s = rem % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn range_to_cidrs_u32(mut s: u32, e: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    loop {
        let max_size = if s == 0 { 32 } else { s.trailing_zeros() as u8 };
        let span = (e - s).saturating_add(1);
        let span_bits = if span == 0 { 32 } else { 31 - span.leading_zeros() as u8 };
        let bits = max_size.min(span_bits);
        out.push((s, 32 - bits));
        let step = 1u64 << bits;
        let next = s as u64 + step;
        if next > e as u64 { break; }
        s = next as u32;
    }
    out
}

fn range_to_cidrs_u128(mut s: u128, e: u128) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    loop {
        let max_size = if s == 0 { 128 } else { s.trailing_zeros() as u8 };
        let span = e.saturating_sub(s).saturating_add(1);
        let span_bits = if span == 0 { 128 } else { 127 - span.leading_zeros() as u8 };
        let bits = max_size.min(span_bits);
        out.push((s, 128 - bits));
        if bits >= 128 { break; }
        let step = 1u128 << bits;
        let next = s.saturating_add(step);
        if next > e { break; }
        s = next;
    }
    out
}

pub fn analyze(db: &Db) -> Vec<(u8, u64, u64)> {
    let mut ranges = [0u64; 101];
    let mut ips = [0u64; 101];
    db.iter_v4(|s, e, flags| {
        let sc = score_for_flags(flags) as usize;
        ranges[sc] += 1;
        ips[sc] += (e - s) as u64 + 1;
    });
    db.iter_v6(|_, _, flags| {
        let sc = score_for_flags(flags) as usize;
        ranges[sc] += 1;
    });
    let mut out = Vec::new();
    let mut cr = 0u64;
    let mut ci = 0u64;
    for s in (0..=100).rev() {
        cr += ranges[s];
        ci += ips[s];
        if ranges[s] > 0 {
            out.push((s as u8, cr, ci));
        }
    }
    out
}

fn merge_u32(v: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if v.is_empty() {
        return v;
    }
    let mut out = Vec::with_capacity(v.len());
    out.push(v[0]);
    for &(s, e) in &v[1..] {
        let last = out.last_mut().unwrap();
        if s <= last.1.saturating_add(1) {
            if e > last.1 {
                last.1 = e;
            }
        } else {
            out.push((s, e));
        }
    }
    out
}

fn merge_u128(v: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    if v.is_empty() {
        return v;
    }
    let mut out = Vec::with_capacity(v.len());
    out.push(v[0]);
    for &(s, e) in &v[1..] {
        let last = out.last_mut().unwrap();
        if s <= last.1.saturating_add(1) {
            if e > last.1 {
                last.1 = e;
            }
        } else {
            out.push((s, e));
        }
    }
    out
}

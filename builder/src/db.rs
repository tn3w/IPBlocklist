use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub type Err = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Err>;

pub const HEADER_SIZE: usize = 256;
pub const VERSION: u32 = 6;
pub const V4_BUCKETS: usize = 65536;

const SEV: [u8; 20] = [
    30, 25, 45, 95, 95, 55, 70, 65, 75, 15,
    5,  0,  10, 40, 10, 15, 35, 0,  0,  0,
];

const BGPTOOLS_THREAT_MASK: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3)
    | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 13) | (1 << 16);

pub fn score_for_flags(flags: u32) -> u8 {
    score_for_flags_src(flags, false)
}

pub fn score_for_flags_src(flags: u32, bgptools: bool) -> u8 {
    let mut max = 0u8;
    for i in 0..20 {
        if flags & (1 << i) == 0 {
            continue;
        }
        let mut sev = SEV[i] as f32;
        if bgptools {
            sev *= if (1 << i) & BGPTOOLS_THREAT_MASK != 0 { 0.35 } else { 0.6 };
        }
        let sev = sev as u8;
        if sev > max {
            max = sev;
        }
    }
    max
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Header {
    pub version: u32,
    pub _r0: u32,
    pub v4_compact_count: u64,
    pub v4_large_count: u64,
    pub v6_count: u64,
    pub val_count: u64,
    pub str_count: u64,
    pub v4_bucket_off: u64,
    pub v4_starts_lo_off: u64,
    pub v4_lens_off: u64,
    pub v4_vals_off: u64,
    pub v4_large_starts_off: u64,
    pub v4_large_ends_off: u64,
    pub v4_large_vals_off: u64,
    pub v6_starts_off: u64,
    pub v6_ends_off: u64,
    pub v6_vals_off: u64,
    pub val_table_off: u64,
    pub str_index_off: u64,
    pub str_data_off: u64,
    pub str_data_len: u64,
}

impl Header {
    fn fields(&self) -> [u64; 20] {
        [
            self.v4_compact_count, self.v4_large_count, self.v6_count,
            self.val_count, self.str_count,
            self.v4_bucket_off, self.v4_starts_lo_off,
            self.v4_lens_off, self.v4_vals_off,
            self.v4_large_starts_off, self.v4_large_ends_off,
            self.v4_large_vals_off,
            self.v6_starts_off, self.v6_ends_off, self.v6_vals_off,
            self.val_table_off, self.str_index_off,
            self.str_data_off, self.str_data_len,
            0,
        ]
    }

    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut o = [0u8; HEADER_SIZE];
        o[0..4].copy_from_slice(&self.version.to_le_bytes());
        o[4..8].copy_from_slice(&self._r0.to_le_bytes());
        for (i, v) in self.fields().iter().enumerate() {
            o[8 + i * 8..16 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
        o
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_SIZE {
            return Err("file too small".into());
        }
        let mut h = Header::default();
        h.version = u32::from_le_bytes(b[0..4].try_into()?);
        h._r0 = u32::from_le_bytes(b[4..8].try_into()?);
        let r = |i: usize| {
            u64::from_le_bytes(b[8 + i * 8..16 + i * 8].try_into().unwrap())
        };
        h.v4_compact_count = r(0); h.v4_large_count = r(1);
        h.v6_count = r(2); h.val_count = r(3); h.str_count = r(4);
        h.v4_bucket_off = r(5); h.v4_starts_lo_off = r(6);
        h.v4_lens_off = r(7); h.v4_vals_off = r(8);
        h.v4_large_starts_off = r(9); h.v4_large_ends_off = r(10);
        h.v4_large_vals_off = r(11);
        h.v6_starts_off = r(12); h.v6_ends_off = r(13);
        h.v6_vals_off = r(14);
        h.val_table_off = r(15); h.str_index_off = r(16);
        h.str_data_off = r(17); h.str_data_len = r(18);
        Ok(h)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ValueEntry {
    pub flags: u32,
    pub provider_id: u32,
    pub source_id: u32,
    pub _pad: u32,
}

#[derive(Default)]
pub struct Builder {
    pub v4: Vec<(u32, u32, u32)>,
    pub v6: Vec<(u128, u128, u32)>,
    pub values: Vec<ValueEntry>,
    val_index: HashMap<ValueEntry, u32>,
    pub strings: Vec<String>,
    str_index: HashMap<String, u32>,

    pub bucket_index: Vec<u32>,
    pub compact_starts_lo: Vec<u16>,
    pub compact_lens: Vec<u16>,
    pub compact_vals: Vec<u16>,
    pub large_starts: Vec<u32>,
    pub large_ends: Vec<u32>,
    pub large_vals: Vec<u16>,
}

impl Builder {
    pub fn new() -> Self {
        let mut b = Self::default();
        b.intern("");
        b
    }

    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.str_index.get(s) {
            return id;
        }
        let id = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.str_index.insert(s.to_string(), id);
        id
    }

    pub fn value_id(&mut self, flags: u32, provider_id: u32, source_id: u32) -> u32 {
        let v = ValueEntry { flags, provider_id, source_id, _pad: 0 };
        if let Some(&id) = self.val_index.get(&v) {
            return id;
        }
        let id = self.values.len() as u32;
        self.values.push(v);
        self.val_index.insert(v, id);
        id
    }

    pub fn push_v4(&mut self, s: u32, e: u32, val: u32) {
        self.v4.push((s, e, val));
    }

    pub fn push_v6(&mut self, s: u128, e: u128, val: u32) {
        self.v6.push((s, e, val));
    }

    pub fn finalize(&mut self) -> Result<()> {
        if self.values.len() > u16::MAX as usize {
            return Err(format!(
                "too many distinct values: {}", self.values.len()
            ).into());
        }
        self.v4.sort_unstable_by(|a, b|
            a.2.cmp(&b.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1))
        );
        merge_adjacent_v4(&mut self.v4);

        self.v6.sort_unstable_by(|a, b|
            a.2.cmp(&b.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1))
        );
        merge_adjacent_v6(&mut self.v6);
        self.v6.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let mut compact: Vec<(u16, u16, u16, u16)> = Vec::new();
        let mut large: Vec<(u32, u32, u16)> = Vec::new();
        for &(s, e, v) in &self.v4 {
            let val = v as u16;
            if (s >> 16) == (e >> 16) {
                let bucket = (s >> 16) as u16;
                let start_lo = (s & 0xFFFF) as u16;
                let len = (e - s) as u16;
                compact.push((bucket, start_lo, len, val));
            } else {
                large.push((s, e, val));
            }
        }
        compact.sort_unstable_by_key(|r| (r.0, r.1, r.2));
        large.sort_unstable_by_key(|r| (r.0, r.1));

        let mut bucket_index = vec![0u32; V4_BUCKETS + 1];
        for r in &compact {
            bucket_index[r.0 as usize + 1] += 1;
        }
        for i in 1..=V4_BUCKETS {
            bucket_index[i] += bucket_index[i - 1];
        }

        self.compact_starts_lo = compact.iter().map(|r| r.1).collect();
        self.compact_lens = compact.iter().map(|r| r.2).collect();
        self.compact_vals = compact.iter().map(|r| r.3).collect();
        self.large_starts = large.iter().map(|r| r.0).collect();
        self.large_ends = large.iter().map(|r| r.1).collect();
        self.large_vals = large.iter().map(|r| r.2).collect();
        self.bucket_index = bucket_index;
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let cn = self.compact_starts_lo.len() as u64;
        let ln = self.large_starts.len() as u64;
        let v6n = self.v6.len() as u64;

        let mut off = align_up(HEADER_SIZE as u64, 4);
        let v4_bucket_off = off;
        off += ((V4_BUCKETS + 1) as u64) * 4;
        let v4_starts_lo_off = off; off += cn * 2;
        let v4_lens_off = off; off += cn * 2;
        let v4_vals_off = off; off += cn * 2;
        off = align_up(off, 4);
        let v4_large_starts_off = off; off += ln * 4;
        let v4_large_ends_off = off; off += ln * 4;
        let v4_large_vals_off = off; off += ln * 2;
        off = align_up(off, 16);
        let v6_starts_off = off; off += v6n * 16;
        let v6_ends_off = off; off += v6n * 16;
        let v6_vals_off = off; off += v6n * 2;
        off = align_up(off, 4);
        let val_table_off = off;
        off += (self.values.len() as u64) * 16;
        let str_index_off = off;
        off += (self.strings.len() as u64) * 8;
        let str_data_off = off;

        let mut strdata: Vec<u8> = Vec::new();
        let mut strindex: Vec<u8> = Vec::with_capacity(self.strings.len() * 8);
        for s in &self.strings {
            let so = strdata.len() as u32;
            strdata.extend_from_slice(s.as_bytes());
            strindex.extend_from_slice(&so.to_le_bytes());
            strindex.extend_from_slice(&(s.len() as u32).to_le_bytes());
        }

        let header = Header {
            version: VERSION, _r0: 0,
            v4_compact_count: cn, v4_large_count: ln,
            v6_count: v6n,
            val_count: self.values.len() as u64,
            str_count: self.strings.len() as u64,
            v4_bucket_off, v4_starts_lo_off, v4_lens_off, v4_vals_off,
            v4_large_starts_off, v4_large_ends_off, v4_large_vals_off,
            v6_starts_off, v6_ends_off, v6_vals_off,
            val_table_off, str_index_off, str_data_off,
            str_data_len: strdata.len() as u64,
        };

        let mut f = File::create(path)?;
        let mut pos = 0u64;
        f.write_all(&header.to_bytes())?;
        pos += HEADER_SIZE as u64;

        pad_to(&mut f, &mut pos, v4_bucket_off)?;
        for v in &self.bucket_index {
            f.write_all(&v.to_le_bytes())?;
            pos += 4;
        }
        pad_to(&mut f, &mut pos, v4_starts_lo_off)?;
        write_u16_col(&mut f, self.compact_starts_lo.iter().copied())?;
        pos += cn * 2;
        pad_to(&mut f, &mut pos, v4_lens_off)?;
        write_u16_col(&mut f, self.compact_lens.iter().copied())?;
        pos += cn * 2;
        pad_to(&mut f, &mut pos, v4_vals_off)?;
        write_u16_col(&mut f, self.compact_vals.iter().copied())?;
        pos += cn * 2;

        pad_to(&mut f, &mut pos, v4_large_starts_off)?;
        write_u32_col(&mut f, self.large_starts.iter().copied())?;
        pos += ln * 4;
        pad_to(&mut f, &mut pos, v4_large_ends_off)?;
        write_u32_col(&mut f, self.large_ends.iter().copied())?;
        pos += ln * 4;
        pad_to(&mut f, &mut pos, v4_large_vals_off)?;
        write_u16_col(&mut f, self.large_vals.iter().copied())?;
        pos += ln * 2;

        pad_to(&mut f, &mut pos, v6_starts_off)?;
        write_u128_col(&mut f, self.v6.iter().map(|r| r.0))?;
        pos += v6n * 16;
        pad_to(&mut f, &mut pos, v6_ends_off)?;
        write_u128_col(&mut f, self.v6.iter().map(|r| r.1))?;
        pos += v6n * 16;
        pad_to(&mut f, &mut pos, v6_vals_off)?;
        write_u16_col(&mut f, self.v6.iter().map(|r| r.2 as u16))?;
        pos += v6n * 2;

        pad_to(&mut f, &mut pos, val_table_off)?;
        for v in &self.values {
            f.write_all(&v.flags.to_le_bytes())?;
            f.write_all(&v.provider_id.to_le_bytes())?;
            f.write_all(&v.source_id.to_le_bytes())?;
            f.write_all(&v._pad.to_le_bytes())?;
            pos += 16;
        }
        pad_to(&mut f, &mut pos, str_index_off)?;
        f.write_all(&strindex)?;
        pos += strindex.len() as u64;
        pad_to(&mut f, &mut pos, str_data_off)?;
        f.write_all(&strdata)?;
        Ok(())
    }
}

fn align_up(x: u64, a: u64) -> u64 {
    (x + a - 1) & !(a - 1)
}

fn pad_to(f: &mut File, pos: &mut u64, target: u64) -> Result<()> {
    while *pos < target {
        f.write_all(&[0u8])?;
        *pos += 1;
    }
    Ok(())
}

fn write_u32_col<I: Iterator<Item = u32>>(f: &mut File, it: I) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
    for v in it {
        buf.extend_from_slice(&v.to_le_bytes());
        if buf.len() >= 1 << 20 { f.write_all(&buf)?; buf.clear(); }
    }
    f.write_all(&buf)?;
    Ok(())
}

fn write_u16_col<I: Iterator<Item = u16>>(f: &mut File, it: I) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
    for v in it {
        buf.extend_from_slice(&v.to_le_bytes());
        if buf.len() >= 1 << 20 { f.write_all(&buf)?; buf.clear(); }
    }
    f.write_all(&buf)?;
    Ok(())
}

fn write_u128_col<I: Iterator<Item = u128>>(f: &mut File, it: I) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
    for v in it {
        buf.extend_from_slice(&v.to_le_bytes());
        if buf.len() >= 1 << 20 { f.write_all(&buf)?; buf.clear(); }
    }
    f.write_all(&buf)?;
    Ok(())
}

fn merge_adjacent_v4(v: &mut Vec<(u32, u32, u32)>) {
    if v.is_empty() { return; }
    let mut out: Vec<(u32, u32, u32)> = Vec::with_capacity(v.len());
    out.push(v[0]);
    for &(s, e, val) in &v[1..] {
        let last = out.last_mut().unwrap();
        if last.2 == val && s <= last.1.saturating_add(1) {
            if e > last.1 { last.1 = e; }
        } else {
            out.push((s, e, val));
        }
    }
    *v = out;
}

fn merge_adjacent_v6(v: &mut Vec<(u128, u128, u32)>) {
    if v.is_empty() { return; }
    let mut out: Vec<(u128, u128, u32)> = Vec::with_capacity(v.len());
    out.push(v[0]);
    for &(s, e, val) in &v[1..] {
        let last = out.last_mut().unwrap();
        if last.2 == val && s <= last.1.saturating_add(1) {
            if e > last.1 { last.1 = e; }
        } else {
            out.push((s, e, val));
        }
    }
    *v = out;
}

pub struct Db {
    _h: Header,
    v4_bucket_index: Vec<u32>,
    v4_starts_lo: Vec<u16>,
    v4_lens: Vec<u16>,
    v4_vals: Vec<u16>,
    v4_max_ends_lo: Vec<u16>,
    v4_large_starts: Vec<u32>,
    v4_large_ends: Vec<u32>,
    v4_large_vals: Vec<u16>,
    v4_large_max_ends: Vec<u32>,
    v6_starts: Vec<u128>,
    v6_ends: Vec<u128>,
    v6_vals: Vec<u16>,
    v6_max_ends: Vec<u128>,
    values: Vec<u8>,
    str_index: Vec<(u32, u32)>,
    str_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Hit<'a> {
    pub start: IpAddr,
    pub end: IpAddr,
    pub flags: u32,
    pub score: u8,
    pub provider: &'a str,
    pub source: &'a str,
}

fn read_u16_vec(bytes: &[u8], off: usize, n: usize) -> Vec<u16> {
    let slice = &bytes[off..off + n * 2];
    slice.chunks_exact(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn read_u32_vec(bytes: &[u8], off: usize, n: usize) -> Vec<u32> {
    let slice = &bytes[off..off + n * 4];
    slice.chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn read_u128_vec(bytes: &[u8], off: usize, n: usize) -> Vec<u128> {
    let slice = &bytes[off..off + n * 16];
    slice.chunks_exact(16)
        .map(|c| u128::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn build_max_ends_lo(
    starts_lo: &[u16], lens: &[u16], bucket_index: &[u32],
) -> Vec<u16> {
    let mut out = Vec::with_capacity(starts_lo.len());
    for b in 0..V4_BUCKETS {
        let s = bucket_index[b] as usize;
        let e = bucket_index[b + 1] as usize;
        let mut cur = 0u16;
        for i in s..e {
            let end_lo = starts_lo[i].wrapping_add(lens[i]);
            if end_lo > cur { cur = end_lo; }
            out.push(cur);
        }
    }
    out
}

fn build_max_ends_u32(ends: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(ends.len());
    let mut cur = 0u32;
    for &e in ends {
        if e > cur { cur = e; }
        out.push(cur);
    }
    out
}

fn build_max_ends_u128(ends: &[u128]) -> Vec<u128> {
    let mut out = Vec::with_capacity(ends.len());
    let mut cur = 0u128;
    for &e in ends {
        if e > cur { cur = e; }
        out.push(cur);
    }
    out
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| format!("open {path:?}: {e}"))?;
        let h = Header::from_bytes(&bytes)?;
        if h.version != VERSION {
            return Err(format!(
                "unsupported version {} (expected {VERSION})", h.version
            ).into());
        }

        let cn = h.v4_compact_count as usize;
        let ln = h.v4_large_count as usize;
        let v6n = h.v6_count as usize;
        let valn = h.val_count as usize;
        let strn = h.str_count as usize;

        let v4_bucket_index = read_u32_vec(
            &bytes, h.v4_bucket_off as usize, V4_BUCKETS + 1,
        );
        let v4_starts_lo = read_u16_vec(&bytes, h.v4_starts_lo_off as usize, cn);
        let v4_lens = read_u16_vec(&bytes, h.v4_lens_off as usize, cn);
        let v4_vals = read_u16_vec(&bytes, h.v4_vals_off as usize, cn);
        let v4_max_ends_lo =
            build_max_ends_lo(&v4_starts_lo, &v4_lens, &v4_bucket_index);

        let v4_large_starts =
            read_u32_vec(&bytes, h.v4_large_starts_off as usize, ln);
        let v4_large_ends =
            read_u32_vec(&bytes, h.v4_large_ends_off as usize, ln);
        let v4_large_vals =
            read_u16_vec(&bytes, h.v4_large_vals_off as usize, ln);
        let v4_large_max_ends = build_max_ends_u32(&v4_large_ends);

        let v6_starts = read_u128_vec(&bytes, h.v6_starts_off as usize, v6n);
        let v6_ends = read_u128_vec(&bytes, h.v6_ends_off as usize, v6n);
        let v6_vals = read_u16_vec(&bytes, h.v6_vals_off as usize, v6n);
        let v6_max_ends = build_max_ends_u128(&v6_ends);

        let val_off = h.val_table_off as usize;
        let values = bytes[val_off..val_off + valn * 16].to_vec();

        let si = h.str_index_off as usize;
        let str_index: Vec<(u32, u32)> = (0..strn).map(|i| {
            let o = si + i * 8;
            (
                u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()),
                u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap()),
            )
        }).collect();

        let sd = h.str_data_off as usize;
        let str_data = bytes[sd..sd + h.str_data_len as usize].to_vec();

        Ok(Db {
            _h: h, v4_bucket_index,
            v4_starts_lo, v4_lens, v4_vals, v4_max_ends_lo,
            v4_large_starts, v4_large_ends, v4_large_vals, v4_large_max_ends,
            v6_starts, v6_ends, v6_vals, v6_max_ends,
            values, str_index, str_data,
        })
    }

    pub fn v4_count(&self) -> usize {
        self.v4_starts_lo.len() + self.v4_large_starts.len()
    }
    pub fn v6_count(&self) -> usize { self.v6_starts.len() }
    pub fn v4_bucket_index(&self) -> &[u32] { &self.v4_bucket_index }
    pub fn v4_starts_lo(&self) -> &[u16] { &self.v4_starts_lo }
    pub fn v4_lens(&self) -> &[u16] { &self.v4_lens }
    pub fn v4_large_starts(&self) -> &[u32] { &self.v4_large_starts }
    pub fn v4_large_ends(&self) -> &[u32] { &self.v4_large_ends }

    pub fn iter_v4<F: FnMut(u32, u32, u32, bool)>(&self, mut f: F) {
        for b in 0..V4_BUCKETS {
            let s = self.v4_bucket_index[b] as usize;
            let e = self.v4_bucket_index[b + 1] as usize;
            let prefix = (b as u32) << 16;
            for i in s..e {
                let lo = self.v4_starts_lo[i];
                let end_lo = lo.wrapping_add(self.v4_lens[i]);
                let val = self.v4_vals[i] as u32;
                f(prefix | lo as u32, prefix | end_lo as u32,
                  self.val_flags(val), self.val_is_bgptools(val));
            }
        }
        for i in 0..self.v4_large_starts.len() {
            let val = self.v4_large_vals[i] as u32;
            f(self.v4_large_starts[i], self.v4_large_ends[i],
              self.val_flags(val), self.val_is_bgptools(val));
        }
    }

    pub fn iter_v6<F: FnMut(u128, u128, u32, bool)>(&self, mut f: F) {
        for i in 0..self.v6_starts.len() {
            let val = self.v6_vals[i] as u32;
            f(self.v6_starts[i], self.v6_ends[i],
              self.val_flags(val), self.val_is_bgptools(val));
        }
    }

    #[inline]
    fn val_flags(&self, val_id: u32) -> u32 {
        let o = val_id as usize * 16;
        u32::from_le_bytes(self.values[o..o + 4].try_into().unwrap())
    }

    #[inline]
    fn val_is_bgptools(&self, val_id: u32) -> bool {
        let (_, _, src) = self.val_entry(val_id);
        self.get_str(src).starts_with("bgptools")
    }

    #[inline]
    fn val_score(&self, val_id: u32) -> u8 {
        score_for_flags_src(self.val_flags(val_id), self.val_is_bgptools(val_id))
    }

    fn val_entry(&self, val_id: u32) -> (u32, u32, u32) {
        let o = val_id as usize * 16;
        (
            u32::from_le_bytes(self.values[o..o + 4].try_into().unwrap()),
            u32::from_le_bytes(self.values[o + 4..o + 8].try_into().unwrap()),
            u32::from_le_bytes(self.values[o + 8..o + 12].try_into().unwrap()),
        )
    }

    fn get_str(&self, id: u32) -> &str {
        if id == 0 { return ""; }
        let (off, len) = self.str_index[id as usize];
        std::str::from_utf8(
            &self.str_data[off as usize..(off + len) as usize]
        ).unwrap_or("")
    }

    fn make_hit(&self, start: IpAddr, end: IpAddr, val_id: u32) -> Hit<'_> {
        let (flags, prov, src) = self.val_entry(val_id);
        let bgptools = self.get_str(src).starts_with("bgptools");
        Hit {
            start, end, flags,
            score: score_for_flags_src(flags, bgptools),
            provider: self.get_str(prov),
            source: self.get_str(src),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Vec<Hit<'_>> {
        match ip {
            IpAddr::V4(a) => self.lookup_v4(u32::from(a)),
            IpAddr::V6(a) => self.lookup_v6(u128::from(a)),
        }
    }

    pub fn lookup_v4(&self, ip: u32) -> Vec<Hit<'_>> {
        let mut hits = Vec::new();
        let bucket = (ip >> 16) as usize;
        let ip_lo = (ip & 0xFFFF) as u16;
        let bs = self.v4_bucket_index[bucket] as usize;
        let be = self.v4_bucket_index[bucket + 1] as usize;
        if bs < be {
            let starts = &self.v4_starts_lo[bs..be];
            let lens = &self.v4_lens[bs..be];
            let vals = &self.v4_vals[bs..be];
            let mends = &self.v4_max_ends_lo[bs..be];
            let i = partition_point_u16(starts, ip_lo);
            let prefix = (bucket as u32) << 16;
            let mut j = i;
            while j > 0 {
                j -= 1;
                if mends[j] < ip_lo { break; }
                let end_lo = starts[j].wrapping_add(lens[j]);
                if end_lo >= ip_lo {
                    let s = IpAddr::V4(Ipv4Addr::from(prefix | starts[j] as u32));
                    let e = IpAddr::V4(Ipv4Addr::from(prefix | end_lo as u32));
                    hits.push(self.make_hit(s, e, vals[j] as u32));
                }
            }
        }
        let ln = self.v4_large_starts.len();
        if ln > 0 {
            let i = partition_point_u32(&self.v4_large_starts, ip);
            let mut j = i;
            while j > 0 {
                j -= 1;
                if self.v4_large_max_ends[j] < ip { break; }
                if self.v4_large_ends[j] >= ip {
                    let s = IpAddr::V4(Ipv4Addr::from(self.v4_large_starts[j]));
                    let e = IpAddr::V4(Ipv4Addr::from(self.v4_large_ends[j]));
                    hits.push(self.make_hit(s, e, self.v4_large_vals[j] as u32));
                }
            }
        }
        hits
    }

    pub fn lookup_v6(&self, ip: u128) -> Vec<Hit<'_>> {
        let mut hits = Vec::new();
        let i = partition_point_u128(&self.v6_starts, ip);
        let mut j = i;
        while j > 0 {
            j -= 1;
            if self.v6_max_ends[j] < ip { break; }
            if self.v6_ends[j] >= ip {
                let s = IpAddr::V6(Ipv6Addr::from(self.v6_starts[j]));
                let e = IpAddr::V6(Ipv6Addr::from(self.v6_ends[j]));
                hits.push(self.make_hit(s, e, self.v6_vals[j] as u32));
            }
        }
        hits
    }

    #[inline]
    pub fn lookup_v4_flags(&self, ip: u32) -> u32 {
        let mut acc = 0u32;
        let bucket = (ip >> 16) as usize;
        let ip_lo = (ip & 0xFFFF) as u16;
        let bs = self.v4_bucket_index[bucket] as usize;
        let be = self.v4_bucket_index[bucket + 1] as usize;
        if bs < be {
            let starts = &self.v4_starts_lo[bs..be];
            let lens = &self.v4_lens[bs..be];
            let vals = &self.v4_vals[bs..be];
            let mends = &self.v4_max_ends_lo[bs..be];
            let i = partition_point_u16(starts, ip_lo);
            let mut j = i;
            while j > 0 {
                j -= 1;
                if mends[j] < ip_lo { break; }
                let end_lo = starts[j].wrapping_add(lens[j]);
                if end_lo >= ip_lo {
                    acc |= self.val_flags(vals[j] as u32);
                }
            }
        }
        if !self.v4_large_starts.is_empty() {
            let i = partition_point_u32(&self.v4_large_starts, ip);
            let mut j = i;
            while j > 0 {
                j -= 1;
                if self.v4_large_max_ends[j] < ip { break; }
                if self.v4_large_ends[j] >= ip {
                    acc |= self.val_flags(self.v4_large_vals[j] as u32);
                }
            }
        }
        acc
    }

    #[inline]
    pub fn lookup_v4_score(&self, ip: u32) -> u8 {
        let mut max = 0u8;
        let bucket = (ip >> 16) as usize;
        let ip_lo = (ip & 0xFFFF) as u16;
        let bs = self.v4_bucket_index[bucket] as usize;
        let be = self.v4_bucket_index[bucket + 1] as usize;
        if bs < be {
            let starts = &self.v4_starts_lo[bs..be];
            let lens = &self.v4_lens[bs..be];
            let vals = &self.v4_vals[bs..be];
            let mends = &self.v4_max_ends_lo[bs..be];
            let i = partition_point_u16(starts, ip_lo);
            let mut j = i;
            while j > 0 {
                j -= 1;
                if mends[j] < ip_lo { break; }
                let end_lo = starts[j].wrapping_add(lens[j]);
                if end_lo >= ip_lo {
                    let s = self.val_score(vals[j] as u32);
                    if s > max { max = s; }
                }
            }
        }
        if !self.v4_large_starts.is_empty() {
            let i = partition_point_u32(&self.v4_large_starts, ip);
            let mut j = i;
            while j > 0 {
                j -= 1;
                if self.v4_large_max_ends[j] < ip { break; }
                if self.v4_large_ends[j] >= ip {
                    let s = self.val_score(self.v4_large_vals[j] as u32);
                    if s > max { max = s; }
                }
            }
        }
        max
    }

    #[inline]
    pub fn lookup_v6_flags(&self, ip: u128) -> u32 {
        let mut acc = 0u32;
        let i = partition_point_u128(&self.v6_starts, ip);
        let mut j = i;
        while j > 0 {
            j -= 1;
            if self.v6_max_ends[j] < ip { break; }
            if self.v6_ends[j] >= ip {
                acc |= self.val_flags(self.v6_vals[j] as u32);
            }
        }
        acc
    }

    #[inline]
    pub fn lookup_v6_score(&self, ip: u128) -> u8 {
        let mut max = 0u8;
        let i = partition_point_u128(&self.v6_starts, ip);
        let mut j = i;
        while j > 0 {
            j -= 1;
            if self.v6_max_ends[j] < ip { break; }
            if self.v6_ends[j] >= ip {
                let s = self.val_score(self.v6_vals[j] as u32);
                if s > max { max = s; }
            }
        }
        max
    }
}

#[inline]
pub fn partition_point_u16(s: &[u16], target: u16) -> usize {
    let n = s.len();
    if n == 0 { return 0; }
    let mut base = 0usize;
    let mut size = n;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let v = s[mid];
        base = if v <= target { mid } else { base };
        size -= half;
    }
    if s[base] <= target { base + 1 } else { base }
}

#[inline]
pub fn partition_point_u32(s: &[u32], target: u32) -> usize {
    let n = s.len();
    if n == 0 { return 0; }
    let mut base = 0usize;
    let mut size = n;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let v = s[mid];
        base = if v <= target { mid } else { base };
        size -= half;
    }
    if s[base] <= target { base + 1 } else { base }
}

#[inline]
pub fn partition_point_u128(s: &[u128], target: u128) -> usize {
    let n = s.len();
    if n == 0 { return 0; }
    let mut base = 0usize;
    let mut size = n;
    while size > 1 {
        let half = size / 2;
        let mid = base + half;
        let v = s[mid];
        base = if v <= target { mid } else { base };
        size -= half;
    }
    if s[base] <= target { base + 1 } else { base }
}

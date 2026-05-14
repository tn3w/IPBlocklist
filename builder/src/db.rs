use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

pub type Err = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Err>;

pub const HEADER_SIZE: usize = 128;

#[derive(Copy, Clone, Debug, Default)]
pub struct Header {
    pub version: u32,
    pub _r0: u32,
    pub v4_count: u64,
    pub v6_count: u64,
    pub val_count: u64,
    pub str_count: u64,
    pub v4_starts_off: u64,
    pub v4_ends_off: u64,
    pub v4_vals_off: u64,
    pub v6_starts_off: u64,
    pub v6_ends_off: u64,
    pub v6_vals_off: u64,
    pub val_table_off: u64,
    pub str_index_off: u64,
    pub str_data_off: u64,
    pub str_data_len: u64,
}

impl Header {
    fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut o = [0u8; HEADER_SIZE];
        o[0..4].copy_from_slice(&self.version.to_le_bytes());
        o[4..8].copy_from_slice(&self._r0.to_le_bytes());
        let u64s = [
            self.v4_count, self.v6_count, self.val_count, self.str_count,
            self.v4_starts_off, self.v4_ends_off, self.v4_vals_off,
            self.v6_starts_off, self.v6_ends_off, self.v6_vals_off,
            self.val_table_off, self.str_index_off,
            self.str_data_off, self.str_data_len,
        ];
        for (i, v) in u64s.iter().enumerate() {
            o[8 + i * 8..8 + (i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        o
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_SIZE { return Err("file too small".into()); }
        let mut h = Header::default();
        h.version = u32::from_le_bytes(b[0..4].try_into()?);
        h._r0 = u32::from_le_bytes(b[4..8].try_into()?);
        let read64 = |i: usize| u64::from_le_bytes(b[8 + i * 8..16 + i * 8].try_into().unwrap());
        h.v4_count = read64(0);
        h.v6_count = read64(1);
        h.val_count = read64(2);
        h.str_count = read64(3);
        h.v4_starts_off = read64(4);
        h.v4_ends_off = read64(5);
        h.v4_vals_off = read64(6);
        h.v6_starts_off = read64(7);
        h.v6_ends_off = read64(8);
        h.v6_vals_off = read64(9);
        h.val_table_off = read64(10);
        h.str_index_off = read64(11);
        h.str_data_off = read64(12);
        h.str_data_len = read64(13);
        Ok(h)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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
}

impl Builder {
    pub fn new() -> Self {
        let mut b = Self::default();
        b.intern("");
        b
    }

    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.str_index.get(s) { return id; }
        let id = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.str_index.insert(s.to_string(), id);
        id
    }

    pub fn value_id(&mut self, flags: u32, provider_id: u32, source_id: u32) -> u32 {
        let v = ValueEntry { flags, provider_id, source_id, _pad: 0 };
        if let Some(&id) = self.val_index.get(&v) { return id; }
        let id = self.values.len() as u32;
        self.values.push(v);
        self.val_index.insert(v, id);
        id
    }

    pub fn push_v4(&mut self, s: u32, e: u32, val: u32) { self.v4.push((s, e, val)); }
    pub fn push_v6(&mut self, s: u128, e: u128, val: u32) { self.v6.push((s, e, val)); }

    pub fn finalize(&mut self) {
        self.v4.sort_unstable_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
        merge_adjacent_v4(&mut self.v4);
        self.v4.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        self.v6.sort_unstable_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
        merge_adjacent_v6(&mut self.v6);
        self.v6.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let v4n = self.v4.len();
        let v6n = self.v6.len();

        if self.values.len() > u16::MAX as usize {
            return Err(format!("too many distinct values: {}", self.values.len()).into());
        }
        let mut off = align_up(HEADER_SIZE as u64, 16);
        let v4_starts_off = off; off += (v4n as u64) * 4;
        let v4_ends_off = off; off += (v4n as u64) * 4;
        let v4_vals_off = align_up(off, 2); off = v4_vals_off + (v4n as u64) * 2;

        off = align_up(off, 16);
        let v6_starts_off = off; off += (v6n as u64) * 16;
        let v6_ends_off = off; off += (v6n as u64) * 16;
        let v6_vals_off = align_up(off, 2); off = v6_vals_off + (v6n as u64) * 2;

        let val_table_off = align_up(off, 4);
        off = val_table_off + (self.values.len() as u64) * 16;
        let str_index_off = align_up(off, 4);
        off = str_index_off + (self.strings.len() as u64) * 8;
        let str_data_off = off;

        let mut strdata: Vec<u8> = Vec::new();
        let mut strindex: Vec<u8> = Vec::with_capacity(self.strings.len() * 8);
        for s in &self.strings {
            let o = strdata.len() as u32;
            strdata.extend_from_slice(s.as_bytes());
            strindex.extend_from_slice(&o.to_le_bytes());
            strindex.extend_from_slice(&(s.len() as u32).to_le_bytes());
        }

        let header = Header {
            version: 4, _r0: 0,
            v4_count: v4n as u64, v6_count: v6n as u64,
            val_count: self.values.len() as u64,
            str_count: self.strings.len() as u64,
            v4_starts_off, v4_ends_off, v4_vals_off,
            v6_starts_off, v6_ends_off, v6_vals_off,
            val_table_off, str_index_off, str_data_off,
            str_data_len: strdata.len() as u64,
        };

        let mut f = File::create(path)?;
        let mut pos = 0u64;
        f.write_all(&header.to_bytes())?;
        pos += HEADER_SIZE as u64;
        pad_to(&mut f, &mut pos, v4_starts_off)?;
        write_u32_col(&mut f, self.v4.iter().map(|r| r.0))?;
        pos += v4n as u64 * 4;
        pad_to(&mut f, &mut pos, v4_ends_off)?;
        write_u32_col(&mut f, self.v4.iter().map(|r| r.1))?;
        pos += v4n as u64 * 4;
        pad_to(&mut f, &mut pos, v4_vals_off)?;
        write_u16_col(&mut f, self.v4.iter().map(|r| r.2 as u16))?;
        pos += v4n as u64 * 2;

        pad_to(&mut f, &mut pos, v6_starts_off)?;
        write_u128_col(&mut f, self.v6.iter().map(|r| r.0))?;
        pos += v6n as u64 * 16;
        pad_to(&mut f, &mut pos, v6_ends_off)?;
        write_u128_col(&mut f, self.v6.iter().map(|r| r.1))?;
        pos += v6n as u64 * 16;
        pad_to(&mut f, &mut pos, v6_vals_off)?;
        write_u16_col(&mut f, self.v6.iter().map(|r| r.2 as u16))?;
        pos += v6n as u64 * 2;

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

fn align_up(x: u64, a: u64) -> u64 { (x + a - 1) & !(a - 1) }

fn pad_to(f: &mut File, pos: &mut u64, target: u64) -> Result<()> {
    while *pos < target { f.write_all(&[0u8])?; *pos += 1; }
    Ok(())
}

fn write_u32_col<I: Iterator<Item = u32>>(f: &mut File, it: I) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
    for v in it {
        buf.extend_from_slice(&v.to_le_bytes());
        if buf.len() >= 1024 * 1024 { f.write_all(&buf)?; buf.clear(); }
    }
    f.write_all(&buf)?;
    Ok(())
}

fn write_u16_col<I: Iterator<Item = u16>>(f: &mut File, it: I) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
    for v in it {
        buf.extend_from_slice(&v.to_le_bytes());
        if buf.len() >= 1024 * 1024 { f.write_all(&buf)?; buf.clear(); }
    }
    f.write_all(&buf)?;
    Ok(())
}

fn write_u128_col<I: Iterator<Item = u128>>(f: &mut File, it: I) -> Result<()> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024 * 1024);
    for v in it {
        buf.extend_from_slice(&v.to_le_bytes());
        if buf.len() >= 1024 * 1024 { f.write_all(&buf)?; buf.clear(); }
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

#[derive(Copy, Clone)]
pub struct V4Tail { pub max_end: u32, pub end: u32, pub val: u32 }

#[derive(Copy, Clone)]
#[repr(C, align(16))]
pub struct V6Tail { pub max_end: u128, pub end: u128, pub val: u32, _p: [u32; 3] }

pub struct Db {
    v4_starts: Vec<u32>,
    v4_tail: Vec<V4Tail>,
    v6_starts: Vec<u128>,
    v6_tail: Vec<V6Tail>,
    values: Vec<ValueEntry>,
    str_offsets: Vec<(u32, u32)>,
    str_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Hit<'a> {
    pub start: IpAddr,
    pub end: IpAddr,
    pub flags: u32,
    pub provider: &'a str,
    pub source: &'a str,
}

fn read_u32_col(bytes: &[u8], off: u64, n: usize) -> Vec<u32> {
    let start = off as usize;
    let slice = &bytes[start..start + n * 4];
    let mut v = Vec::with_capacity(n);
    for c in slice.chunks_exact(4) {
        v.push(u32::from_le_bytes(c.try_into().unwrap()));
    }
    v
}

fn read_u128_col(bytes: &[u8], off: u64, n: usize) -> Vec<u128> {
    let start = off as usize;
    let slice = &bytes[start..start + n * 16];
    let mut v = Vec::with_capacity(n);
    for c in slice.chunks_exact(16) {
        v.push(u128::from_le_bytes(c.try_into().unwrap()));
    }
    v
}

fn build_v4_tail(bytes: &[u8], ends_off: u64, vals_off: u64, n: usize) -> Vec<V4Tail> {
    let es = ends_off as usize;
    let vs = vals_off as usize;
    let ends = &bytes[es..es + n * 4];
    let vals = &bytes[vs..vs + n * 2];
    let mut v = Vec::with_capacity(n);
    let mut cur = 0u32;
    for (ec, vc) in ends.chunks_exact(4).zip(vals.chunks_exact(2)) {
        let e = u32::from_le_bytes(ec.try_into().unwrap());
        if e > cur { cur = e; }
        let val = u16::from_le_bytes(vc.try_into().unwrap()) as u32;
        v.push(V4Tail { max_end: cur, end: e, val });
    }
    v
}

fn build_v6_tail(bytes: &[u8], ends_off: u64, vals_off: u64, n: usize) -> Vec<V6Tail> {
    let es = ends_off as usize;
    let vs = vals_off as usize;
    let ends = &bytes[es..es + n * 16];
    let vals = &bytes[vs..vs + n * 2];
    let mut v = Vec::with_capacity(n);
    let mut cur = 0u128;
    for (ec, vc) in ends.chunks_exact(16).zip(vals.chunks_exact(2)) {
        let e = u128::from_le_bytes(ec.try_into().unwrap());
        if e > cur { cur = e; }
        let val = u16::from_le_bytes(vc.try_into().unwrap()) as u32;
        v.push(V6Tail { max_end: cur, end: e, val, _p: [0; 3] });
    }
    v
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| format!("open {path:?}: {e}"))?;
        let header = Header::from_bytes(&bytes)?;

        let v4n = header.v4_count as usize;
        let v6n = header.v6_count as usize;
        let valn = header.val_count as usize;
        let strn = header.str_count as usize;

        let v4_starts = read_u32_col(&bytes, header.v4_starts_off, v4n);
        let v4_tail = build_v4_tail(&bytes, header.v4_ends_off, header.v4_vals_off, v4n);
        let v6_starts = read_u128_col(&bytes, header.v6_starts_off, v6n);
        let v6_tail = build_v6_tail(&bytes, header.v6_ends_off, header.v6_vals_off, v6n);

        let val_off = header.val_table_off as usize;
        let values: Vec<ValueEntry> = (0..valn).map(|i| {
            let o = val_off + i * 16;
            ValueEntry {
                flags: u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()),
                provider_id: u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap()),
                source_id: u32::from_le_bytes(bytes[o + 8..o + 12].try_into().unwrap()),
                _pad: u32::from_le_bytes(bytes[o + 12..o + 16].try_into().unwrap()),
            }
        }).collect();

        let str_off = header.str_index_off as usize;
        let str_offsets: Vec<(u32, u32)> = (0..strn).map(|i| {
            let o = str_off + i * 8;
            (u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()),
             u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap()))
        }).collect();

        let str_data_off = header.str_data_off as usize;
        let str_data = bytes[str_data_off..str_data_off + header.str_data_len as usize].to_vec();

        Ok(Db {
            v4_starts, v4_tail,
            v6_starts, v6_tail,
            values, str_offsets, str_data,
        })
    }

    fn get_str(&self, id: u32) -> &str {
        if id == 0 { return ""; }
        let (off, len) = self.str_offsets[id as usize];
        std::str::from_utf8(&self.str_data[off as usize..(off + len) as usize]).unwrap_or("")
    }

    fn make_hit(&self, val_id: u32, start: IpAddr, end: IpAddr) -> Hit<'_> {
        let v = &self.values[val_id as usize];
        Hit {
            start, end,
            flags: v.flags,
            provider: self.get_str(v.provider_id),
            source: self.get_str(v.source_id),
        }
    }

    pub fn lookup(&self, ip: IpAddr) -> Vec<Hit<'_>> {
        match ip {
            IpAddr::V4(a) => self.lookup_v4(u32::from(a)),
            IpAddr::V6(a) => self.lookup_v6(u128::from(a)),
        }
    }

    pub fn lookup_v4(&self, ip: u32) -> Vec<Hit<'_>> {
        let i = partition_point_u32(&self.v4_starts, ip);
        let mut hits = Vec::new();
        let mut j = i;
        while j > 0 {
            j -= 1;
            let t = self.v4_tail[j];
            if t.max_end < ip { break; }
            if t.end >= ip {
                let s = self.v4_starts[j];
                let h = self.make_hit(t.val,
                    IpAddr::V4(Ipv4Addr::from(s)),
                    IpAddr::V4(Ipv4Addr::from(t.end)));
                hits.push(h);
            }
        }
        hits
    }

    pub fn lookup_v6(&self, ip: u128) -> Vec<Hit<'_>> {
        let i = partition_point_u128(&self.v6_starts, ip);
        let mut hits = Vec::new();
        let mut j = i;
        while j > 0 {
            j -= 1;
            let t = &self.v6_tail[j];
            if t.max_end < ip { break; }
            if t.end >= ip {
                let s = self.v6_starts[j];
                let h = self.make_hit(t.val,
                    IpAddr::V6(Ipv6Addr::from(s)),
                    IpAddr::V6(Ipv6Addr::from(t.end)));
                hits.push(h);
            }
        }
        hits
    }

    #[inline]
    pub fn lookup_v4_flags(&self, ip: u32) -> u32 {
        let i = partition_point_u32(&self.v4_starts, ip);
        let mut acc = 0u32;
        let mut j = i;
        while j > 0 {
            j -= 1;
            let t = self.v4_tail[j];
            if t.max_end < ip { break; }
            if t.end >= ip {
                acc |= self.values[t.val as usize].flags;
            }
        }
        acc
    }

    pub fn v4_count(&self) -> usize { self.v4_starts.len() }
    pub fn v6_count(&self) -> usize { self.v6_starts.len() }
    pub fn v4_starts(&self) -> &[u32] { &self.v4_starts }
    pub fn v4_tail(&self) -> &[V4Tail] { &self.v4_tail }
}

#[inline]
fn partition_point_u32(s: &[u32], target: u32) -> usize {
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
fn partition_point_u128(s: &[u128], target: u128) -> usize {
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

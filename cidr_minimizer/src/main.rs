use std::io::{self, BufWriter, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Binary input format (little-endian):
///   f32:  score_threshold
///   u8:   coverage_percent (e.g. 90 → 29/32 for /27)
///   u32:  ipv4_range_count
///   for each: u32 start, u32 end, f32 score
///   u32:  ipv6_range_count
///   for each: u128 start, u128 end, f32 score

fn main() {
    // Parse input, then drop buffer to free memory
    let (threshold, coverage_pct, mut v4_events, mut v6_events);
    {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).unwrap();
        let mut c = Cursor::new(&buf);

        threshold = c.read_f32();
        coverage_pct = c.read_u8() as f32 / 100.0;

        let v4_count = c.read_u32() as usize;
        v4_events = Vec::with_capacity(v4_count * 2);
        for _ in 0..v4_count {
            let start = c.read_u32();
            let end = c.read_u32();
            let score = c.read_f32();
            v4_events.push((start as u64, score));
            v4_events.push((end as u64 + 1, -score));
        }

        // ::ffff:0.0.0.0/96 IPv4-mapped IPv6 range
        const V4MAPPED_START: u128 = 0xFFFF_0000_0000;
        const V4MAPPED_END: u128 = 0xFFFF_FFFF_FFFF;

        let v6_count = c.read_u32() as usize;
        v6_events = Vec::with_capacity(v6_count * 2);
        for _ in 0..v6_count {
            let start = c.read_u128();
            let end = c.read_u128();
            let score = c.read_f32();
            if start >= V4MAPPED_START && end <= V4MAPPED_END {
                // Convert IPv4-mapped IPv6 to native IPv4 events
                let v4_start = (start - V4MAPPED_START) as u32;
                let v4_end = (end - V4MAPPED_START) as u32;
                v4_events.push((v4_start as u64, score));
                v4_events.push((v4_end as u64 + 1, -score));
            } else {
                v6_events.push((start, score as f64));
                if end < u128::MAX {
                    v6_events.push((end + 1, -(score as f64)));
                }
            }
        }
    }

    // --- IPv4 ---
    let v4_ranges = sweep_line(&mut v4_events, threshold);
    drop(v4_events);
    let v4_ranges = promote_cidrs_v4(&v4_ranges, coverage_pct);
    let v4_ranges = subtract_non_routable_v4(&v4_ranges);

    // --- IPv6 ---
    let v6_ranges = sweep_line_v6(&mut v6_events, threshold as f64);
    drop(v6_events);
    let v6_ranges = promote_cidrs_v6(&v6_ranges, coverage_pct);
    let v6_ranges = subtract_non_routable_v6(&v6_ranges);

    // --- Output ---
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let v4_count = v4_ranges.len();
    let v6_count = v6_ranges.len();
    write!(
        out,
        "\
# IPBlocklist - Aggregated Threat Intelligence Blocklist
#
# This file contains IP addresses and ranges identified as malicious
# by multiple threat intelligence feeds. Entries are scored by
# aggregating signals across 100+ feeds and filtered by a threshold.
#
# Format (one entry per line):
#   1.2.3.4            Single IPv4 address
#   1.2.3.0/24         IPv4 CIDR block
#   1.2.3.1-1.2.3.5    IPv4 range (non-CIDR-aligned)
#   2001:db8::1        Single IPv6 address
#   2001:db8::/32      IPv6 CIDR block
#   a::1-a::ff         IPv6 range (non-CIDR-aligned)
#
# Non-routable addresses are excluded (private, loopback,
# link-local, multicast, reserved, documentation, CGN).
#
# IPv4 entries: {v4_count}
# IPv6 entries: {v6_count}
# Total entries: {total}
#
# Compatible with: ipset, iptables (iprange), nftables, pf
#
# Source: https://github.com/tn3w/IPBlocklist
#
",
        total = v4_count + v6_count
    )
    .unwrap();

    for &(start, end) in &v4_ranges {
        if start == end {
            writeln!(out, "{}", Ipv4Addr::from(start)).unwrap();
        } else if let Some(prefix) = single_cidr_v4(start, end) {
            writeln!(out, "{}/{}", Ipv4Addr::from(start), prefix).unwrap();
        } else {
            writeln!(out, "{}-{}", Ipv4Addr::from(start), Ipv4Addr::from(end)).unwrap();
        }
    }
    for &(start, end) in &v6_ranges {
        if start == end {
            writeln!(out, "{}", Ipv6Addr::from(start)).unwrap();
        } else if let Some(prefix) = single_cidr_v128(start, end) {
            writeln!(out, "{}/{}", Ipv6Addr::from(start), prefix).unwrap();
        } else {
            writeln!(out, "{}-{}", Ipv6Addr::from(start), Ipv6Addr::from(end)).unwrap();
        }
    }
}

// ── Sweep-line for IPv4 (u64 positions to avoid u32 overflow) ──

fn sweep_line(events: &mut [(u64, f32)], threshold: f32) -> Vec<(u32, u32)> {
    events.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut ranges: Vec<(u32, u32)> = Vec::new();
    let mut score: f32 = 0.0;
    let mut region_start: Option<u64> = None;

    let mut i = 0;
    while i < events.len() {
        let pos = events[i].0;
        while i < events.len() && events[i].0 == pos {
            score += events[i].1;
            i += 1;
        }
        if score >= threshold && region_start.is_none() {
            region_start = Some(pos);
        } else if score < threshold {
            if let Some(start) = region_start {
                let end = pos.saturating_sub(1).min(u32::MAX as u64);
                if start <= u32::MAX as u64 {
                    ranges.push((start as u32, end as u32));
                }
                region_start = None;
            }
        }
    }
    if let Some(start) = region_start {
        ranges.push((start as u32, u32::MAX));
    }
    ranges
}

// ── Sweep-line for IPv6 ──

fn sweep_line_v6(events: &mut [(u128, f64)], threshold: f64) -> Vec<(u128, u128)> {
    events.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut ranges: Vec<(u128, u128)> = Vec::new();
    let mut score: f64 = 0.0;
    let mut region_start: Option<u128> = None;

    let mut i = 0;
    while i < events.len() {
        let pos = events[i].0;
        while i < events.len() && events[i].0 == pos {
            score += events[i].1;
            i += 1;
        }
        if score >= threshold && region_start.is_none() {
            region_start = Some(pos);
        } else if score < threshold {
            if let Some(start) = region_start {
                ranges.push((start, pos.saturating_sub(1)));
                region_start = None;
            }
        }
    }
    if let Some(start) = region_start {
        ranges.push((start, u128::MAX));
    }
    ranges
}

// ── Hierarchical CIDR promotion for IPv4 ──
// Bottom-up from /27 to /8: promotions at smaller blocks cascade into larger ones.
// Only boundary blocks need checking interior blocks are already 100% covered.

fn promote_cidrs_v4(ranges: &[(u32, u32)], coverage_pct: f32) -> Vec<(u32, u32)> {
    let mut current = merge_ranges_u32(ranges);

    for prefix_len in (8u8..=27).rev() {
        let block_size = 1u64 << (32 - prefix_len);
        let block_mask = !((block_size - 1) as u32);

        let mut blocks: Vec<u32> = Vec::with_capacity(current.len() * 2);
        for &(start, end) in &current {
            let first = start & block_mask;
            let last = end & block_mask;
            blocks.push(first);
            if last != first {
                blocks.push(last);
            }
        }
        blocks.sort_unstable();
        blocks.dedup();

        let mut promoted: Vec<(u32, u32)> = Vec::new();
        for &block in &blocks {
            let block_end = block | ((block_size - 1) as u32);
            let covered = count_covered_in_block(&current, block, block_end);
            if covered as f64 / block_size as f64 >= coverage_pct as f64 {
                promoted.push((block, block_end));
            }
        }

        if !promoted.is_empty() {
            current.extend_from_slice(&promoted);
            current = merge_ranges_u32(&current);
        }
    }

    current
}

// ── Hierarchical CIDR promotion for IPv6 ──
// Bottom-up from /124 to /32 in steps of 4.

fn promote_cidrs_v6(ranges: &[(u128, u128)], coverage_pct: f32) -> Vec<(u128, u128)> {
    let mut current = merge_ranges_u128(ranges);

    for prefix_len in (32..=124u8).rev().step_by(4) {
        let block_bits = 128 - prefix_len as u32;
        let block_size: u128 = 1u128 << block_bits;
        let block_mask: u128 = !(block_size - 1);

        let mut blocks: Vec<u128> = Vec::with_capacity(current.len() * 2);
        for &(start, end) in &current {
            let first = start & block_mask;
            let last = end & block_mask;
            blocks.push(first);
            if last != first {
                blocks.push(last);
            }
        }
        blocks.sort_unstable();
        blocks.dedup();

        let mut promoted: Vec<(u128, u128)> = Vec::new();
        for &block in &blocks {
            let block_end = block | (block_size - 1);
            let covered = count_covered_in_block_v6(&current, block, block_end);
            if covered as f64 / block_size as f64 >= coverage_pct as f64 {
                promoted.push((block, block_end));
            }
        }

        if !promoted.is_empty() {
            current.extend_from_slice(&promoted);
            current = merge_ranges_u128(&current);
        }
    }

    current
}

fn count_covered_in_block(ranges: &[(u32, u32)], block_start: u32, block_end: u32) -> u64 {
    let mut count: u64 = 0;
    let idx = ranges.partition_point(|r| r.1 < block_start);
    for &(start, end) in &ranges[idx..] {
        if start > block_end {
            break;
        }
        let overlap_start = start.max(block_start);
        let overlap_end = end.min(block_end);
        count += (overlap_end - overlap_start + 1) as u64;
    }
    count
}

fn count_covered_in_block_v6(ranges: &[(u128, u128)], block_start: u128, block_end: u128) -> u128 {
    let mut count: u128 = 0;
    let idx = ranges.partition_point(|r| r.1 < block_start);
    for &(start, end) in &ranges[idx..] {
        if start > block_end {
            break;
        }
        let overlap_start = start.max(block_start);
        let overlap_end = end.min(block_end);
        count += (overlap_end - overlap_start) as u128 + 1;
    }
    count
}

// ── Merge overlapping/adjacent ranges ──

fn merge_ranges_u32(ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::new();
    let (mut cur_s, mut cur_e) = sorted[0];
    for &(s, e) in &sorted[1..] {
        if s <= cur_e.saturating_add(1) {
            cur_e = cur_e.max(e);
        } else {
            merged.push((cur_s, cur_e));
            cur_s = s;
            cur_e = e;
        }
    }
    merged.push((cur_s, cur_e));
    merged
}

fn merge_ranges_u128(ranges: &[(u128, u128)]) -> Vec<(u128, u128)> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::new();
    let (mut cur_s, mut cur_e) = sorted[0];
    for &(s, e) in &sorted[1..] {
        if s <= cur_e.saturating_add(1) {
            cur_e = cur_e.max(e);
        } else {
            merged.push((cur_s, cur_e));
            cur_s = s;
            cur_e = e;
        }
    }
    merged.push((cur_s, cur_e));
    merged
}

// ── Check if a range is exactly one CIDR block ──

fn single_cidr_v4(start: u32, end: u32) -> Option<u8> {
    let size = (end as u64) - (start as u64) + 1;
    if size.is_power_of_two() {
        let bits = size.trailing_zeros();
        if (start as u64) & (size - 1) == 0 {
            return Some((32 - bits) as u8);
        }
    }
    None
}

fn single_cidr_v128(start: u128, end: u128) -> Option<u8> {
    let size = end - start + 1;
    if size.is_power_of_two() {
        let bits = size.trailing_zeros();
        if start & (size - 1) == 0 {
            return Some((128 - bits) as u8);
        }
    }
    None
}

// ── Filter non-routable addresses ──

fn cidr_v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> (u32, u32) {
    let start = u32::from_be_bytes([a, b, c, d]);
    let size = 1u64 << (32 - prefix);
    (start, (start as u64 + size - 1) as u32)
}

fn subtract_non_routable_v4(ranges: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let exclusions: Vec<(u32, u32)> = vec![
        cidr_v4(0, 0, 0, 0, 8),       // 0.0.0.0/8        current network
        cidr_v4(10, 0, 0, 0, 8),      // 10.0.0.0/8       private (RFC 1918)
        cidr_v4(100, 64, 0, 0, 10),   // 100.64.0.0/10    CGN shared (RFC 6598)
        cidr_v4(127, 0, 0, 0, 8),     // 127.0.0.0/8      loopback
        cidr_v4(169, 254, 0, 0, 16),  // 169.254.0.0/16   link-local
        cidr_v4(172, 16, 0, 0, 12),   // 172.16.0.0/12    private (RFC 1918)
        cidr_v4(192, 0, 0, 0, 24),    // 192.0.0.0/24     IETF protocol assignments
        cidr_v4(192, 0, 2, 0, 24),    // 192.0.2.0/24     TEST-NET-1
        cidr_v4(192, 88, 99, 0, 24),  // 192.88.99.0/24   6to4 relay anycast
        cidr_v4(192, 168, 0, 0, 16),  // 192.168.0.0/16   private (RFC 1918)
        cidr_v4(198, 18, 0, 0, 15),   // 198.18.0.0/15    benchmarking
        cidr_v4(198, 51, 100, 0, 24), // 198.51.100.0/24  TEST-NET-2
        cidr_v4(203, 0, 113, 0, 24),  // 203.0.113.0/24   TEST-NET-3
        cidr_v4(224, 0, 0, 0, 4),     // 224.0.0.0/4      multicast
        cidr_v4(240, 0, 0, 0, 4),     // 240.0.0.0/4      reserved/future + broadcast
    ];
    subtract_ranges_u32(ranges, &exclusions)
}

fn subtract_non_routable_v6(ranges: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let exclusions: Vec<(u128, u128)> = vec![
        (0, 0),                        // ::/128 unspecified
        (1, 1),                        // ::1/128 loopback
        cidr_v6(0x0064_ff9b_0001, 48), // 64:ff9b:1::/48 NAT64
        cidr_v6(0x0100, 64),           // 100::/64 discard
        cidr_v6(0x2001_0db8, 32),      // 2001:db8::/32 documentation
        (
            0xfc00_0000_0000_0000_0000_0000_0000_0000,
            0xfdff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        ), // fc00::/7 unique local
        (
            0xfe80_0000_0000_0000_0000_0000_0000_0000,
            0xfebf_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        ), // fe80::/10 link-local
        (0xff00_0000_0000_0000_0000_0000_0000_0000, u128::MAX), // ff00::/8 multicast
    ];
    subtract_ranges_u128(ranges, &exclusions)
}

fn cidr_v6(prefix_val: u128, prefix_len: u8) -> (u128, u128) {
    let shift = 128 - prefix_len;
    let start = prefix_val << shift;
    let size = 1u128 << shift;
    (start, start + size - 1)
}

fn subtract_ranges_u32(ranges: &[(u32, u32)], exclusions: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut result: Vec<(u32, u32)> = ranges.to_vec();
    for &(ex_start, ex_end) in exclusions {
        let mut new_result: Vec<(u32, u32)> = Vec::with_capacity(result.len());
        for &(s, e) in &result {
            if e < ex_start || s > ex_end {
                new_result.push((s, e));
            } else {
                if s < ex_start {
                    new_result.push((s, ex_start - 1));
                }
                if e > ex_end {
                    new_result.push((ex_end + 1, e));
                }
            }
        }
        result = new_result;
    }
    result
}

fn subtract_ranges_u128(ranges: &[(u128, u128)], exclusions: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut result: Vec<(u128, u128)> = ranges.to_vec();
    for &(ex_start, ex_end) in exclusions {
        let mut new_result: Vec<(u128, u128)> = Vec::with_capacity(result.len());
        for &(s, e) in &result {
            if e < ex_start || s > ex_end {
                new_result.push((s, e));
            } else {
                if s < ex_start {
                    new_result.push((s, ex_start - 1));
                }
                if e > ex_end && ex_end < u128::MAX {
                    new_result.push((ex_end + 1, e));
                }
            }
        }
        result = new_result;
    }
    result
}

// ── Simple binary cursor ──

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }
    fn read_bytes(&mut self, n: usize) -> &'a [u8] {
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        slice
    }
    fn read_u8(&mut self) -> u8 {
        let v = self.data[self.pos];
        self.pos += 1;
        v
    }
    fn read_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.read_bytes(4).try_into().unwrap())
    }
    fn read_u128(&mut self) -> u128 {
        u128::from_le_bytes(self.read_bytes(16).try_into().unwrap())
    }
    fn read_f32(&mut self) -> f32 {
        f32::from_le_bytes(self.read_bytes(4).try_into().unwrap())
    }
}

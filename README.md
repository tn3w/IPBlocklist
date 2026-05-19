# IPBlocklist

[![Build](https://img.shields.io/github/actions/workflow/status/tn3w/IPBlocklist/aggregate-feeds.yml?label=build)](https://github.com/tn3w/IPBlocklist/actions)
[![Intel sources](https://img.shields.io/badge/intel.bin-164_sources-blue)](feeds-intel.json)
[![License](https://img.shields.io/badge/license-Apache_2.0-lightgrey)](LICENSE)

Aggregates IP/ASN threat intelligence into a single ~30 MB mmap-friendly
database with 0–100 maliciousness scoring (consumer-side).

```bash
wget https://github.com/tn3w/IPBlocklist/releases/latest/download/intel.bin
```

Live demo: [ipblocklist.tn3w.dev](https://ipblocklist.tn3w.dev).

## Artifacts

| file            | role                                       |
| --------------- | ------------------------------------------ |
| `intel.bin`     | primary, columnar mmap, 20-flag bitmask    |
| `blocklist.txt` | scored, CIDR-minimized text for firewalls  |
| `asns.json`     | ASN lists keyed by feed name               |
| `blocklist.bin` | legacy IPBL v2 (scoring + categories)      |

# intel.bin

Built by `builder/` (Rust) from `feeds-intel.json`. SoA columnar layout.
Scoring is consumer-side.

## Layout

128-byte little-endian header:

| offset | size | field         |
| -----: | ---- | ------------- |
|      0 | u32  | version (4)   |
|      4 | u32  | reserved      |
|      8 | u64  | v4_count      |
|     16 | u64  | v6_count      |
|     24 | u64  | val_count     |
|     32 | u64  | str_count     |
|     40 | u64  | v4_starts_off |
|     48 | u64  | v4_ends_off   |
|     56 | u64  | v4_vals_off   |
|     64 | u64  | v6_starts_off |
|     72 | u64  | v6_ends_off   |
|     80 | u64  | v6_vals_off   |
|     88 | u64  | val_table_off |
|     96 | u64  | str_index_off |
|    104 | u64  | str_data_off  |
|    112 | u64  | str_data_len  |

Sections:

- `v4_starts`, `v4_ends`: `v4_count × u32`, sorted by start
- `v4_vals`: `v4_count × u16` (value-table index)
- `v6_starts`, `v6_ends`: `v6_count × u128`, sorted
- `v6_vals`: `v6_count × u16`
- value table: `val_count × {flags u32, provider_id u32, source_id u32, _pad u32}`
- string index: `str_count × {offset u32, len u32}` into `str_data`
- string data: raw UTF-8

Flag bits (LSB→MSB): `vpn, proxy, tor, malware, c2, scanner, brute_force,
spammer, compromised, datacenter, cdn, anycast, crawler, bot, cloud,
private_relay, anonymizer, mobile, isp, government`.

Lookup: bisect `*_starts`, scan back while `prefix_max(ends)[i] >= ip`.

## Build

```bash
cd builder
cargo build --release
FEEDS_FILE=../feeds-intel.json OUT_FILE=../intel.bin \
  ./target/release/builder update
./target/release/builder check 1.2.3.4
```

ASN→prefix and ASN→org are resolved offline from an `asndb-mini.bin`
(via `ASNDB_FILE` env, downloaded by the workflow). HTTP cache:
`request_cache/`.

## feeds-intel.json

Top-level: `{ "flags": [...], "feeds": [...] }`. Per-source:

- `name` (required)
- `flags` (subset of the 20 canonical flags)
- `url` + `regex` for IP/CIDR sources
- `is_asn: true` with `asns` (static) or `url`+`regex` (remote)
- `provider` (optional)

## Python lookup

```bash
python3 lookup_intel.py 185.220.101.1
```

### Scoring

- Per-flag severity: `malware`/`c2`=95, `compromised`=75, `brute_force`=70,
  `spammer`=65, `scanner`=55, `tor`=45, `bot`=40, `anonymizer`=35,
  `vpn`=30, `proxy`=25, `private_relay`/`datacenter`=15,
  `cloud`/`crawler`=10, `cdn`=5, `anycast`/`mobile`/`isp`/`government`=0.
- Rarity: `severity × (1 + log2(1/prevalence) / 24)`.
- Top + 15% of remaining; multi-source boost `× (1 + 0.08·log2(sources+1))`.
- Capped at 100. Levels: `critical ≥80`, `high ≥60`, `medium ≥35`,
  `low ≥15`, else `minimal`.

20k v4 sample → Spearman 0.94, Pearson 0.83 vs top-flag severity.

# blocklist.txt

Scored ranges, thresholded, CIDR-promoted, non-routable stripped. Forms
per line: `1.2.3.4`, `1.2.3.0/24`, `1.2.3.1-1.2.3.254`, `2001:db8::1`,
`2001:db8::/32`.

```bash
ipset create blocklist hash:net
grep -v '^#' blocklist.txt | xargs -n1 ipset add blocklist
```

# Pipeline

```mermaid
flowchart LR
    F[feeds-intel.json] --> B[builder/]
    B --> I[intel.bin]
    A[feeds.json] --> P[aggregator.py]
    P --> T[blocklist.txt]
    P --> J[asns.json]
    P --> L[blocklist.bin]
```

# Deprecated: blocklist.bin

IPBL v2 self-describing binary with scoring and categories. Kept for
legacy consumers; new integrations should use `intel.bin`. Built from
`feeds.json`.

```text
[4 magic "IPBL"][1 version=2][4 timestamp LE]
[1 flag_count] flag_count × { [1 len][N utf-8] }
[1 cat_count]  cat_count  × { [1 len][N utf-8] }
[2 feed_count LE]
feed_count × {
  [1 len][N name]
  [1 base_score 0-200][1 confidence 0-200]
  [4 flags bitmask LE][1 cats bitmask]
  [4 range_count LE]
  range_count × { [varint start_delta][varint size] }
}
```

Lookup implementations for 25 languages live in `examples/`.

# License

[LICENSE](LICENSE)

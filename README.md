<div align="center">

# 🔒 IPBlocklist

Threat intelligence aggregator that collects, processes, and serves IP reputation data from 128 security feeds into an optimized binary format for fast lookups.

<p align="center">
<img src="https://img.shields.io/github/actions/workflow/status/tn3w/IPBlocklist/aggregate-feeds.yml?label=Build&style=for-the-badge" alt="GitHub Workflow Status">
<img src="https://img.shields.io/badge/dataset-8.8M_entries-blue?style=for-the-badge" alt="Dataset Size">
<img src="https://img.shields.io/badge/IPs-4.2M-green?style=for-the-badge" alt="Individual IPs">
<img src="https://img.shields.io/badge/ranges-4571K-orange?style=for-the-badge" alt="CIDR Ranges">
</p>

<p align="center">
<a href="https://github.com/tn3w/IPBlocklist/tree/master"><img src="https://img.shields.io/badge/download-compressed_splits-red?style=for-the-badge&logo=download&logoColor=white" alt="Download"></a>
</p>

</div>

## 📥 Download & Extract

The dataset is compressed with xz (maximum compression) and split into files under 95MB each for easier distribution.

### Download All Split Files

```bash
# Download all split files from GitHub
for i in {00..99}; do
  wget -q "https://raw.githubusercontent.com/tn3w/IPBlocklist/master/data.json.xz.$i.xz" 2>/dev/null && echo "Downloaded part $i" || break
done
```

### Reconstruct and Decompress

```bash
# Combine all split files back into one compressed file
cat data.json.xz.*.xz > data.json.xz

# Decompress to get the original data.json
xz -d data.json.xz

# Verify the file
ls -lh data.json
```

### One-Liner Download & Extract

```bash
# Download, combine, and decompress in one command
for i in {00..99}; do wget -q "https://raw.githubusercontent.com/tn3w/IPBlocklist/master/data.json.xz.$i.xz" 2>/dev/null || break; done && cat data.json.xz.*.xz > data.json.xz && xz -d data.json.xz && rm data.json.xz.*.xz
```

## 🚀 Key Features

- ✅ Fast IP lookups in <1ms using binary search
- ✅ 8.8M+ IPs and CIDR ranges from 143 threat intelligence feeds
- ✅ Malware C&C servers, botnets, spam networks, compromised hosts
- ✅ VPN providers, Tor nodes, datacenter/hosting ASNs
- ✅ Optimized integer storage for minimal memory footprint
- ✅ Support for both IPv4 and IPv6
- ✅ Automated daily updates via GitHub Actions

## 📊 Architecture

```
IP2PROXY-LITE-PX10.BIN → main.rs → data-ip2proxy.json
     (database)         (extractor)         |
                                            |
feeds.json ───────────────────────────────> |
  (config)                                  ↓
                                       aggregator.py
                                        (processor)
                                            ↓
                                        data.json
                                         (binary)
```

## 📖 Overview

IPBlocklist downloads threat intelligence from multiple sources (malware C&C servers, botnets, spam networks, VPN providers, Tor nodes, etc.) and converts them into a compact, searchable format. IP addresses are stored as integers and CIDR ranges as [start, end] pairs for efficient binary search lookups.

The system uses two data sources:

1. **Public Threat Feeds**: 127+ open-source security feeds (configured in feeds.json)
2. **IP2Proxy Database**: Commercial proxy/VPN/threat detection database processed by the Rust extractor

Both sources are merged by aggregator.py into a unified data.json file.

## 📁 Data Models

### feeds.json

Configuration file defining all threat intelligence sources. Each feed is an independent object with complete metadata.

**Structure**: Array of feed objects

```json
[
    {
        "name": "feodotracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "description": "Feodo Tracker - Botnet C&C",
        "regex": "^(?![#;/])([0-9a-fA-F:.]+(?:/\\d+)?)",
        "base_score": 1.0,
        "confidence": 0.95,
        "flags": ["is_malware", "is_botnet", "is_c2_server"],
        "categories": ["malware", "botnet"]
    }
]
```

**Required Fields**:

- `name`: Unique identifier for the feed
- `url`: Download URL for the threat list
- `description`: Human-readable description
- `regex`: Pattern to extract IPs/CIDRs from feed content
- `base_score`: Threat severity (0.0-1.0)
- `confidence`: Data reliability (0.0-1.0)
- `flags`: Boolean indicators (is_anycast, is_botnet, is_brute_force, is_c2_server, is_cdn, is_cloud, is_compromised, is_datacenter, is_forum_spammer, is_isp, is_malware, is_mobile, is_phishing, is_proxy, is_scanner, is_spammer, is_tor, is_vpn, is_web_attacker)
- `categories`: Categories for scoring (anonymizer, attacks, botnet, compromised, infrastructure, malware, spam)

**Optional Fields**:

- `provider_name`: VPN/hosting provider name

**Special Cases**:

IP2Proxy feeds (ip2proxy_*) have empty `regex` fields because they are not downloaded via HTTP. Instead, they are extracted from the IP2PROXY-LITE-PX10.BIN binary database by the Rust extractor (main.rs) and merged into the final dataset. These feeds include VPN, Tor, proxy, datacenter, spam, scanner, botnet, malware, and phishing detection.

### datacenter_asns.json

List of Autonomous System Numbers (ASNs) associated with datacenter and hosting providers.

**Structure**: Array of ASN strings

```json
["15169", "16509", "13335", "8075", "14061"]
```

This file is automatically generated when processing the datacenter_asns feed and can be used for O(1) ASN lookups to identify datacenter traffic.

### data.json

Processed output with all IPs converted to integers for fast lookups.

**Structure**: Object with timestamp and feeds

```json
{
    "timestamp": 1706234567,
    "feeds": {
        "feodotracker": {
            "addresses": [167772160, 167772161, 167772162],
            "networks": [
                [167772160, 167772191],
                [184549376, 184549631]
            ]
        },
        "urlhaus": {
            "addresses": [3232235777, 3232235778],
            "networks": [[3232235776, 3232235855]]
        }
    }
}
```

**Fields**:

- `timestamp`: Unix timestamp of last update
- `feeds`: Object where keys are feed names
    - `addresses`: Sorted array of individual IPs as integers
    - `networks`: Sorted array of [start, end] range pairs as integers

**Integer Conversion**:

- IPv4: `10.0.0.1` → `167772161`
- IPv6: `2001:db8::1` → `42540766411282592856903984951653826561`
- CIDR: `10.0.0.0/27` → `[167772160, 167772191]` (network to broadcast)

## 🦀 main.rs (Rust Extractor)

High-performance binary parser for IP2Proxy LITE PX10 database files. Extracts and categorizes proxy/VPN/threat IPs into separate feeds.

**Features**:

- Memory-mapped file I/O for efficient database access
- Parallel processing with Rayon (10K record chunks)
- Extracts 16 categories: VPN, TOR, PUB, WEB, RES, DCH, COM, EDU, GOV, ISP, MOB, SPAM, SCANNER, BOTNET, MALWARE, PHISHING
- Deduplication using HashSet per category
- Outputs to `data-ip2proxy.json` in the same format as aggregator.py

**Categories**:

The extractor reads the IP2Proxy database fields (proxy type, usage type, threat type) and maps them to feeds:

- `ip2proxy_vpn`: VPN providers
- `ip2proxy_tor`: Tor exit nodes
- `ip2proxy_pub`: Public proxies
- `ip2proxy_web`: Web proxies
- `ip2proxy_res`: Residential proxies
- `ip2proxy_dch`: Datacenter/hosting
- `ip2proxy_com`: Commercial networks
- `ip2proxy_edu`: Educational institutions
- `ip2proxy_gov`: Government networks
- `ip2proxy_isp`: ISP networks
- `ip2proxy_mob`: Mobile networks
- `ip2proxy_spam`: Known spammers
- `ip2proxy_scanner`: Port scanners
- `ip2proxy_botnet`: Botnet nodes
- `ip2proxy_malware`: Malware hosts
- `ip2proxy_phishing`: Phishing sites

**Usage**:

```bash
cargo build --release
cargo run --release
```

**Output**: Creates `data-ip2proxy.json` with categorized IP ranges

## ⚙️ aggregator.py

Downloads and processes all feeds in parallel, handling multiple formats and edge cases. Merges public threat feeds with IP2Proxy data.

**Features**:

- Parallel downloads with ThreadPoolExecutor (10 workers)
- IPv4/IPv6 support with embedded address extraction
- CIDR range expansion to [start, end] pairs
- ASN resolution for datacenter and Tor networks
- Deduplication and sorting for binary search
- Regex-based parsing for diverse feed formats
- Loads and merges IP2Proxy data from `data-ip2proxy.json`

**Special Handling**:

- `datacenter_asns`: Resolves ASN numbers to IP ranges via RIPE API
- `tor_onionoo`: Combines Tor relay list with known Tor ASNs
- IPv6 mapped addresses: Extracts embedded IPv4 (::ffff:192.0.2.1)
- 6to4 tunnels: Extracts IPv4 from 2002::/16 addresses
- IP2Proxy integration: Loads categorized data and converts to integer format

**Usage**:

```bash
# Run Rust extractor first (if using IP2Proxy)
cargo run --release

# Then run Python aggregator
python aggregator.py
```

**Output**: Creates/updates `data.json` with all processed feeds (public feeds + IP2Proxy) and `datacenter_asns.json` with datacenter ASN list

## 🐍 Python Lookup Examples

### Basic Lookup

```python
import json
import ipaddress

with open("data.json") as f:
    data = json.load(f)

def check_ip(ip_string, feeds):
    target = int(ipaddress.ip_address(ip_string))
    matches = []

    for name, list_data in feeds.items():
        if target in list_data["addresses"]:
            matches.append(name)
            continue

        for start, end in list_data["networks"]:
            if start <= target <= end:
                matches.append(name)
                break

    return matches

result = check_ip("10.0.0.1", data["feeds"])
print(result)
```

### Optimized Binary Search

```python
import json
import ipaddress
from bisect import bisect_left

with open("data.json") as f:
    data = json.load(f)

def check_ip_fast(ip_string, feeds):
    target = int(ipaddress.ip_address(ip_string))
    matches = []

    for name, list_data in feeds.items():
        addresses = list_data["addresses"]
        index = bisect_left(addresses, target)
        if index < len(addresses) and addresses[index] == target:
            matches.append(name)
            continue

        for start, end in list_data["networks"]:
            if start <= target <= end:
                matches.append(name)
                break

    return matches

result = check_ip_fast("192.168.1.1", data["feeds"])
print(result)
```

### Batch Lookup

```python
import json
import ipaddress
from bisect import bisect_left

with open("data.json") as f:
    data = json.load(f)

def check_batch(ip_list, feeds):
    results = {}

    for ip_string in ip_list:
        target = int(ipaddress.ip_address(ip_string))
        matches = []

        for name, list_data in feeds.items():
            addresses = list_data["addresses"]
            index = bisect_left(addresses, target)
            if index < len(addresses) and addresses[index] == target:
                matches.append(name)
                continue

            for start, end in list_data["networks"]:
                if start <= target <= end:
                    matches.append(name)
                    break

        results[ip_string] = matches

    return results

ips = ["10.0.0.1", "192.168.1.1", "8.8.8.8"]
results = check_batch(ips, data["feeds"])
for ip, feeds in results.items():
    print(f"{ip}: {feeds}")
```

### Datacenter ASN Lookup

```python
import json

def load_datacenter_asns(asn_file="datacenter_asns.json"):
    """Load datacenter ASNs into a set for O(1) lookups."""
    try:
        with open(asn_file) as f:
            return set(json.load(f))
    except Exception as e:
        print(f"Error loading ASNs: {e}")
        return set()

def is_datacenter_asn(asn, asns=None):
    """Check if ASN belongs to a datacenter."""
    if not asns:
        asns = load_datacenter_asns()
    return asn.replace("AS", "").strip() in asns

asns = load_datacenter_asns()
for asn in ["AS16509", "AS13335", "AS15169"]:
    result = "is" if is_datacenter_asn(asn, asns) else "is not"
    print(f"{asn} {result} a datacenter ASN")
```

### Reputation Scoring

```python
import json
import ipaddress
from bisect import bisect_left

with open("data.json") as f:
    data = json.load(f)

with open("feeds.json") as f:
    feeds = json.load(f)

sources = {feed["name"]: feed for feed in feeds}

def check_ip_with_reputation(ip_string, feeds, sources):
    target = int(ipaddress.ip_address(ip_string))
    matches = []

    for name, list_data in feeds.items():
        addresses = list_data["addresses"]
        index = bisect_left(addresses, target)
        if index < len(addresses) and addresses[index] == target:
            matches.append(name)
            continue

        for start, end in list_data["networks"]:
            if start <= target <= end:
                matches.append(name)
                break

    if not matches:
        return {"ip": ip_string, "score": 0.0, "feeds": []}

    flags = {}
    scores = {
        "anonymizer": [], "attacks": [], "botnet": [],
        "compromised": [], "infrastructure": [], "malware": [], "spam": []
    }

    for list_name in matches:
        source = sources.get(list_name)
        if not source:
            continue

        for flag in source.get("flags", []):
            flags[flag] = True

        provider = source.get("provider_name")
        if provider:
            flags["vpn_provider"] = provider

        base_score = source.get("base_score", 0.5)
        for category in source.get("categories", []):
            if category in scores:
                scores[category].append(base_score)

    total = 0.0
    for category_scores in scores.values():
        if not category_scores:
            continue
        combined = 1.0
        for score in sorted(category_scores, reverse=True):
            combined *= 1.0 - score
        total += 1.0 - combined

    return {
        "ip": ip_string,
        "score": min(total / 1.5, 1.0),
        "feeds": matches,
        **flags
    }

result = check_ip_with_reputation("10.0.0.1", data["feeds"], sources)
print(json.dumps(result, indent=2))
```

## ⚡ Performance Characteristics

**Dataset Statistics**:

- Total feeds: 143
- Individual IPs: 4.2M (4.2M IPv4, 5,191 IPv6)
- CIDR ranges: 4571K (4553K IPv4, 19K IPv6)
- Total entries: 8.8M
- File size: 147.6MB

**Lookup Complexity**:

- Individual IPs: 4.2M (4.2M IPv4, 5,191 IPv6)
- CIDR ranges: 4571K (4553K IPv4, 19K IPv6)
- Typical lookup: <1ms for 143 feeds with 8.8M entries

**Memory Usage**:

- Integer storage: 4 bytes per IPv4, 16 bytes per IPv6
- Range storage: 8 bytes per IPv4 range, 32 bytes per IPv6 range

## 💡 Use Cases

- **API Rate Limiting**: Block known malicious IPs
- **Fraud Detection**: Flag VPN/proxy/datacenter traffic
- **Security Analytics**: Enrich logs with threat intelligence
- **Access Control**: Restrict Tor exit nodes or anonymizers
- **Compliance**: Block traffic from sanctioned networks

## 🙏 Attribution

IPBlocklist uses the IP2Location LITE database for <a href="https://lite.ip2location.com">IP geolocation</a>.

## 📜 License

Copyright 2025 TN3W

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

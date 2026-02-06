<div align="center">

# 🔒 IPBlocklist

Threat intelligence aggregator that collects, processes, and serves IP reputation data from 128 security feeds into an optimized binary format for fast lookups.

<p align="center">
<img src="https://img.shields.io/github/actions/workflow/status/tn3w/IPBlocklist/aggregate-feeds.yml?label=Build&style=for-the-badge" alt="GitHub Workflow Status">
<img src="https://img.shields.io/badge/dataset-8.9M_entries-blue?style=for-the-badge" alt="Dataset Size">
<img src="https://img.shields.io/badge/IPs-4.3M-green?style=for-the-badge" alt="Individual IPs">
<img src="https://img.shields.io/badge/ranges-4616K-orange?style=for-the-badge" alt="CIDR Ranges">
</p>

<p align="center">
<a href="https://raw.githubusercontent.com/tn3w/IPBlocklist/master/data.json.xz"><img src="https://img.shields.io/badge/download-data.json.xz_(15MB)-red?style=for-the-badge&logo=download&logoColor=white" alt="Download Threat Data"></a>
<a href="https://raw.githubusercontent.com/tn3w/IPBlocklist/master/location.xz"><img src="https://img.shields.io/badge/download-location.xz_(16MB)-blue?style=for-the-badge&logo=download&logoColor=white" alt="Download Location DB"></a>
<a href="https://raw.githubusercontent.com/tn3w/IPBlocklist/master/proxy.xz"><img src="https://img.shields.io/badge/download-proxy.xz_(31MB)-purple?style=for-the-badge&logo=download&logoColor=white" alt="Download Proxy DB"></a>
<a href="https://raw.githubusercontent.com/tn3w/IPBlocklist/master/asn-data.json.xz"><img src="https://img.shields.io/badge/download-asn--data.json.xz_(15MB)-green?style=for-the-badge&logo=download&logoColor=white" alt="Download ASN DB"></a>
</p>

</div>

## 📥 Download & Extract

The datasets are compressed with xz and available as downloadable files.

### Threat Intelligence Data

The threat intelligence dataset is a 15MB file (from 149MB uncompressed).

```bash
# Download the compressed file
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/data.json.xz

# Decompress to get the original data.json
xz -d data.json.xz

# Verify the file
ls -lh data.json
```

### IP2Location Geolocation Database

The IP2Location LITE DB9 database includes country, region, city, latitude, longitude, and ZIP code data for both IPv4 and IPv6.

```bash
# Download the compressed database
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/location.xz

# Decompress to get the binary database
xz -d location.xz

# Verify the file
ls -lh IP2LOCATION-LITE-DB9.IPV6.BIN
```

### IP2Proxy Detection Database

The IP2Proxy LITE PX10 database detects VPN, proxy, Tor, datacenter, and threat IPs for both IPv4 and IPv6.

```bash
# Download the compressed database
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/proxy.xz

# Decompress to get the binary database
xz -d proxy.xz

# Verify the file
ls -lh IP2PROXY-LITE-PX10.BIN
```

### IPtoASN Database

The IPtoASN database maps IP addresses to their Autonomous System Numbers (ASN), country codes, and organization names for both IPv4 and IPv6. Data sourced from iptoasn.com.

```bash
# Download the compressed database
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/asn-data.json.xz

# Decompress to get the JSON database
xz -d asn-data.json.xz

# Verify the file
ls -lh asn-data.json
```

### Download All (One-Liner)

```bash
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/data.json.xz && \
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/location.xz && \
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/proxy.xz && \
wget https://raw.githubusercontent.com/tn3w/IPBlocklist/master/asn-data.json.xz && \
xz -d data.json.xz location.xz proxy.xz asn-data.json.xz
```

## 🚀 Key Features

- ✅ Fast IP lookups in <1ms using binary search
- ✅ 8.9M+ IPs and CIDR ranges from 143 threat intelligence feeds
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
                                         (threat intel)

ip2asn-combined.tsv.gz → asn_processor.rs → asn-data.json
      (iptoasn.com)         (converter)      (ASN lookup)
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

IP2Proxy feeds (ip2proxy\_\*) have empty `regex` fields because they are not downloaded via HTTP. Instead, they are extracted from the IP2PROXY-LITE-PX10.BIN binary database by the Rust extractor (main.rs) and merged into the final dataset. These feeds include VPN, Tor, proxy, datacenter, spam, scanner, botnet, malware, and phishing detection.

### datacenter_asns.json

List of Autonomous System Numbers (ASNs) associated with datacenter and hosting providers.

**Structure**: Array of ASN strings

```json
["15169", "16509", "13335", "8075", "14061"]
```

This file is automatically generated when processing the datacenter_asns feed and can be used for O(1) ASN lookups to identify datacenter traffic.

### asn-data.json

Complete ASN database mapping IP ranges to autonomous systems, countries, and organizations. Processed from iptoasn.com data.

**Structure**: Object with records array

```json
{
    "records": [
        [167772160, 184549375, 15169, "US", "GOOGLE"],
        [184549376, 184614911, 16509, "US", "AMAZON-02"],
        [3758096384, 3758161919, 13335, "US", "CLOUDFLARENET"]
    ]
}
```

**Fields** (each record is an array):
- `[0]`: Range start IP (integer)
- `[1]`: Range end IP (integer)
- `[2]`: ASN number
- `[3]`: Two-letter country code
- `[4]`: AS description/organization name

Records are sorted by range start for binary search lookups.

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

## 🦀 Rust Processors

### main.rs (IP2Proxy Extractor)

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

### asn_processor.rs (ASN Database Converter)

Converts the iptoasn.com TSV database into an optimized JSON format for fast lookups.

**Features**:

- Reads gzip-compressed TSV input
- Parses IPv4 and IPv6 addresses
- Converts IPs to integers for efficient storage
- Outputs sorted records for binary search
- Handles ~800K+ ASN records

**Usage**:

```bash
cargo build --release --bin asn_processor
cargo run --release --bin asn_processor
```

**Output**: Creates `asn-data.json` with ASN mappings

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

### ASN Lookup

```python
import json
import ipaddress
from bisect import bisect_right

class AsnLookup:
    """Fast ASN lookup using binary search on IP ranges."""

    def __init__(self, data_file="asn-data.json"):
        """Load ASN data from JSON file."""
        with open(data_file) as f:
            data = json.load(f)
            self.records = data["records"]
        
        # Extract start IPs for binary search
        self.starts = [record[0] for record in self.records]
        print(f"Loaded {len(self.records)} ASN records")

    def lookup(self, ip_string):
        """
        Look up ASN information for an IP address.
        
        Returns dict with:
        - asn: Autonomous System Number
        - country: Two-letter country code
        - description: AS description/organization name
        
        Returns None if IP not found.
        """
        try:
            ip_int = int(ipaddress.ip_address(ip_string))
        except ValueError:
            return None

        # Binary search to find the range
        index = bisect_right(self.starts, ip_int) - 1

        if index < 0 or index >= len(self.records):
            return None

        record = self.records[index]
        range_start, range_end, asn, country, description = record

        # Verify IP is within the range
        if range_start <= ip_int <= range_end:
            return {
                "asn": asn,
                "country": country,
                "description": description,
            }

        return None

# Example usage
lookup = AsnLookup()

test_ips = ["8.8.8.8", "1.1.1.1", "13.107.42.14"]
for ip in test_ips:
    result = lookup.lookup(ip)
    if result:
        print(f"{ip}: AS{result['asn']} ({result['description']}) - {result['country']}")
    else:
        print(f"{ip}: Not found")
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
- Individual IPs: 4.3M (4.3M IPv4, 5,124 IPv6)
- CIDR ranges: 4616K (4597K IPv4, 19K IPv6)
- Total entries: 8.9M
- File size: 148.8MB (uncompressed), 15MB (compressed)

**Lookup Complexity**:

- Individual IPs: 4.3M (4.3M IPv4, 5,124 IPv6)
- CIDR ranges: 4616K (4597K IPv4, 19K IPv6)
- Typical lookup: <1ms for 143 feeds with 8.9M entries

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

import hashlib
import ipaddress
import json
import mmap
import os
import re
import ssl
import struct
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

_ASNDB_MAGIC = 0x000442444E534144
_ASNDB_NO_ASN = 0xFFFFFFFF
_ASNDB_HDR = struct.Struct("<Q B 7x 6I 8Q")
_ASNDB_U32 = struct.Struct("<I")


class AsnDb:
    def __init__(self, path):
        f = open(path, "rb")
        self.mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        h = _ASNDB_HDR.unpack_from(self.mm, 0)
        if h[0] != _ASNDB_MAGIC:
            raise ValueError("asndb: bad magic")
        if h[1] != 1:
            raise ValueError(f"asndb: expected mini flavor, got {h[1]}")
        self._asn_count = h[2]
        self._seg4_count = h[3]
        self._seg6_count = h[4]
        self._asn_off = h[8]
        self._seg4_off = h[9]
        self._seg6_off = h[10]
        self._seg_cache = None

    def _asn_at(self, i):
        return _ASNDB_U32.unpack_from(self.mm, self._asn_off + i * 8)[0]

    def _asn_idx(self, asn):
        lo, hi = 0, self._asn_count
        while lo < hi:
            m = (lo + hi) >> 1
            if self._asn_at(m) < asn:
                lo = m + 1
            else:
                hi = m
        if lo < self._asn_count and self._asn_at(lo) == asn:
            return lo
        return None

    def _seg_index(self):
        if self._seg_cache is not None:
            return self._seg_cache
        v4, v6 = {}, {}
        for i in range(self._seg4_count):
            o = self._seg4_off + i * 8
            start, aidx = struct.unpack_from("<II", self.mm, o)
            if aidx == _ASNDB_NO_ASN:
                continue
            if i + 1 < self._seg4_count:
                end = _ASNDB_U32.unpack_from(
                    self.mm, self._seg4_off + (i + 1) * 8
                )[0] - 1
            else:
                end = 0xFFFFFFFF
            v4.setdefault(aidx, []).append((start, end))
        for i in range(self._seg6_count):
            o = self._seg6_off + i * 20
            start = int.from_bytes(self.mm[o:o + 16], "big")
            aidx = _ASNDB_U32.unpack_from(self.mm, o + 16)[0]
            if aidx == _ASNDB_NO_ASN:
                continue
            if i + 1 < self._seg6_count:
                no = self._seg6_off + (i + 1) * 20
                end = int.from_bytes(self.mm[no:no + 16], "big") - 1
            else:
                end = (1 << 128) - 1
            v6.setdefault(aidx, []).append((start, end))
        self._seg_cache = (v4, v6)
        return self._seg_cache

    def prefixes_cidr(self, asn):
        i = self._asn_idx(asn)
        if i is None:
            return []
        v4_map, v6_map = self._seg_index()
        out = []
        for start, end in v4_map.get(i, []):
            for net in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
            ):
                out.append(str(net))
        for start, end in v6_map.get(i, []):
            for net in ipaddress.summarize_address_range(
                ipaddress.IPv6Address(start), ipaddress.IPv6Address(end)
            ):
                out.append(str(net))
        return out

_REQUEST_CACHE_DIR = "request_cache"
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)


def _request_cache_path(url):
    return os.path.join(
        _REQUEST_CACHE_DIR, hashlib.sha256(url.encode()).hexdigest()
    )


def cached_request(url, timeout=30):
    path = _request_cache_path(url)
    if os.path.exists(path):
        with open(path, "rb") as file:
            return file.read()

    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urlopen_with_expired_cert_fallback(request, timeout=timeout) as response:
        data = response.read()

    os.makedirs(_REQUEST_CACHE_DIR, exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "wb") as file:
        file.write(data)
    os.replace(temp, path)
    return data

_asndb = None
_asndb_lock = threading.Lock()


def asndb():
    global _asndb
    with _asndb_lock:
        if _asndb is None:
            path = os.environ.get("ASNDB_FILE", "asndb-mini.bin")
            _asndb = AsnDb(path)
            print(f"Loaded ASNDB from {path}")
        return _asndb


def parse_ip(ip_str):
    try:
        if "/" in ip_str:
            return ipaddress.ip_network(ip_str, strict=False)
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def parse_line(line, regex):
    matches = re.findall(regex, line)
    results = []
    for match in matches:
        if isinstance(match, str):
            results.append(match)
        elif isinstance(match, tuple):
            results.append(next((group for group in match if group), None))
    return results


def is_expired_certificate_error(error):
    cert_error = getattr(error, "reason", error)
    return isinstance(cert_error, ssl.SSLCertVerificationError) and (
        getattr(cert_error, "verify_code", None) == 10
        or (
            "certificate has expired"
            in f"{getattr(cert_error, 'verify_message', '')} {cert_error}".lower()
        )
    )


def urlopen_with_expired_cert_fallback(request, timeout):
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except Exception as error:
        if not is_expired_certificate_error(error):
            raise

        print(f"Ignoring expired TLS certificate for {request.full_url}")
        insecure_context = ssl.create_default_context()
        insecure_context.check_hostname = False
        insecure_context.verify_mode = ssl.CERT_NONE
        return urllib.request.urlopen(
            request, timeout=timeout, context=insecure_context
        )


def download_source(url, timeout=30):
    for attempt in range(1, 4):
        try:
            data = cached_request(url, timeout=timeout)
            return data.decode("utf-8", errors="ignore").splitlines()
        except Exception as error:
            print(f"Error downloading {url} (attempt {attempt}/3): {error}")
            if attempt < 3:
                time.sleep(1)
    return []


def extract_feed_entries(source):
    regex = source.get("regex")
    if not regex:
        return []

    entries = []
    for line in download_source(source["url"]):
        entries.extend(parse_line(line, regex))

    return entries


def download_single_list(source):
    return source["name"], extract_feed_entries(source)


def normalize_asn(asn):
    asn_value = str(asn).upper().removeprefix("AS").strip()
    return asn_value if asn_value.isdigit() else None


def lookup_asn_prefixes(asn):
    asn_num = normalize_asn(asn)
    if asn_num is None:
        return []
    return asndb().prefixes_cidr(int(asn_num))


def extract_normalized_asns(source):
    static_asns = source.get("asns")
    if static_asns is not None:
        normalized = {
            normalized_asn
            for asn in static_asns
            for normalized_asn in [normalize_asn(asn)]
            if normalized_asn is not None
        }
        return sorted(normalized)

    asns = []
    for asn in extract_feed_entries(source):
        normalized_asn = normalize_asn(asn)
        if normalized_asn is not None:
            asns.append(normalized_asn)

    return sorted(set(asns))


def download_asn_feed(source):
    unique_asns = extract_normalized_asns(source)
    prefixes = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(lookup_asn_prefixes, asn): asn for asn in unique_asns
        }
        for future in as_completed(futures):
            asn = futures[future]
            asn_prefixes = future.result()
            prefixes.extend(asn_prefixes)

    return source["name"], prefixes, unique_asns


def write_json_file(path, data):
    temp_path = f"{path}.tmp"

    with open(temp_path, "w") as file:
        json.dump(data, file, indent=2, sort_keys=True)
        file.write("\n")

    os.replace(temp_path, path)


def save_asn_artifact(asn_lists, path="asns.json"):
    write_json_file(path, asn_lists)
    print(f"Saved {path} with {len(asn_lists)} ASN feeds")


def download_all_feeds(sources):
    feeds = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(download_single_list, source): source for source in sources
        }
        for future in as_completed(futures):
            name, ips = future.result()
            feeds[name] = ips
            print(f"Downloaded {name}: {len(ips)} entries")
    return feeds


def write_varint(f, value):
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        f.write(bytes([byte]))
        if value == 0:
            break


def merge_ranges(ranges):
    if not ranges:
        return ranges

    merged = [ranges[0]]
    for start, end in ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + 1:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def process_feeds(feeds):
    processed = {}
    for list_name, ip_strings in feeds.items():
        ranges = []

        for ip_str in ip_strings:
            if not ip_str:
                continue
            if "-" in ip_str and ip_str.count("-") == 1:
                parts = ip_str.split("-")
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    ranges.append((start, end))
                    continue
                except ValueError:
                    pass
            parsed = parse_ip(ip_str)
            if parsed is None:
                continue
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                start = int(parsed.network_address)
                end = int(parsed.broadcast_address)
                ranges.append((start, end))
            elif isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                addr = int(parsed)
                ranges.append((addr, addr))

        ranges = sorted(set(ranges))
        processed[list_name] = merge_ranges(ranges)
    return processed


def read_varint(f):
    result = shift = 0
    while True:
        byte = f.read(1)[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result
        shift += 7


def download_proxy_types():
    url = "https://github.com/tn3w/IP2X/releases/latest/download/proxy_types.bin"
    print(f"Downloading proxy_types.bin...")
    try:
        data = cached_request(url, timeout=60)
    except Exception as error:
        print(f"Error downloading proxy_types.bin: {error}")
        return {}

    feeds = {}
    offset = 0
    type_count = struct.unpack_from("<H", data, offset)[0]
    offset += 2

    for _ in range(type_count):
        name_len = struct.unpack_from("<B", data, offset)[0]
        offset += 1
        proxy_type = data[offset : offset + name_len].decode("utf-8")
        offset += name_len
        range_count = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        ranges = []
        current = 0
        for _ in range(range_count):
            result = shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7
            current += result

            result = shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7
            size = result

            ranges.append((current, current + size))

        feed_name = f"proxy_{proxy_type.lower()}"
        feeds[feed_name] = ranges
        print(f"Loaded {feed_name}: {len(ranges)} ranges")

    return feeds


def collect_string_table(sources, key):
    seen = []
    for source in sources:
        for value in source.get(key, []):
            if value not in seen:
                seen.append(value)
    return seen


def encode_bitmask(values, table):
    mask = 0
    for value in values:
        if value in table:
            mask |= 1 << table.index(value)
    return mask


def write_blocklist_bin(processed, source_map):
    all_sources = list(source_map.values())
    flag_table = collect_string_table(all_sources, "flags")
    category_table = collect_string_table(all_sources, "categories")

    proxy_pub = source_map.get("proxy_pub", {})
    proxy_defaults = {
        "base_score": proxy_pub.get("base_score", 0.7),
        "confidence": proxy_pub.get("confidence", 0.9),
        "flags": proxy_pub.get("flags", ["is_proxy"]),
        "categories": proxy_pub.get("categories", ["anonymizer"]),
    }

    with open("blocklist.bin", "wb") as f:
        f.write(b"IPBL")
        f.write(struct.pack("<B", 2))
        f.write(struct.pack("<I", int(time.time())))

        f.write(struct.pack("<B", len(flag_table)))
        for flag in flag_table:
            encoded = flag.encode("utf-8")
            f.write(struct.pack("<B", len(encoded)))
            f.write(encoded)

        f.write(struct.pack("<B", len(category_table)))
        for cat in category_table:
            encoded = cat.encode("utf-8")
            f.write(struct.pack("<B", len(encoded)))
            f.write(encoded)

        f.write(struct.pack("<H", len(processed)))

        for feed_name, ranges in processed.items():
            source = source_map.get(feed_name)
            if source is None:
                source = {
                    "base_score": proxy_defaults["base_score"],
                    "confidence": proxy_defaults["confidence"],
                    "flags": proxy_defaults["flags"],
                    "categories": proxy_defaults["categories"],
                }

            name_bytes = feed_name.encode("utf-8")
            f.write(struct.pack("<B", len(name_bytes)))
            f.write(name_bytes)

            score = min(200, int(source.get("base_score", 0.5) * 200))
            conf = min(200, int(source.get("confidence", 0.5) * 200))
            f.write(struct.pack("<B", score))
            f.write(struct.pack("<B", conf))

            flags_mask = encode_bitmask(source.get("flags", []), flag_table)
            cats_mask = encode_bitmask(source.get("categories", []), category_table)
            f.write(struct.pack("<I", flags_mask))
            f.write(struct.pack("<B", cats_mask))

            f.write(struct.pack("<I", len(ranges)))

            prev_from = 0
            for start, end in ranges:
                write_varint(f, start - prev_from)
                write_varint(f, end - start)
                prev_from = start


def main():
    with open("feeds.json") as file:
        sources = json.load(file)

    asn_sources = [source for source in sources if source.get("is_asn")]
    direct_sources = [
        source for source in sources if source.get("regex") and not source.get("is_asn")
    ]

    print("Downloading feeds...")
    feeds = download_all_feeds(direct_sources)
    asn_lists = {}

    for source in asn_sources:
        print(f"Resolving ASN ranges for {source['name']}...")
        feed_name, prefixes, asns = download_asn_feed(source)
        feeds[feed_name] = prefixes
        asn_lists[feed_name] = asns
        print(
            f"Resolved {len(asns)} ASNs into {len(prefixes)} prefixes for "
            f"{feed_name}"
        )

    save_asn_artifact(asn_lists)

    print("Processing feeds...")
    processed = process_feeds(feeds)

    print("Loading proxy types...")
    proxy_feeds = download_proxy_types()
    for name, ranges in proxy_feeds.items():
        processed[name] = merge_ranges(sorted(ranges))

    source_map = {s["name"]: s for s in sources}
    write_blocklist_bin(processed, source_map)

    print(f"Saved blocklist.bin with {len(processed)} feeds")


if __name__ == "__main__":
    main()

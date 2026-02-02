import json
import time
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import re

TOR_EXIT_NODE_ASNS = [
    "60729",
    "53667",
    "4224",
    "208323",
    "198093",
    "401401",
    "210731",
    "61125",
    "214503",
    "215125",
    "214094",
    "205100",
    "57860",
    "8283",
    "215659",
    "197648",
    "44925",
    "198985",
    "214996",
    "210083",
    "49770",
    "197422",
    "205235",
    "30893",
]


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


def download_source(url, timeout=30):
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read().decode("utf-8", errors="ignore")
            return content.splitlines()
    except Exception as error:
        print(f"Error downloading {url}: {error}")
        return []


def get_asn_ranges(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        with urllib.request.urlopen(url, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
            if data.get("status") == "ok":
                return [prefix["prefix"] for prefix in data["data"]["prefixes"]]
    except Exception as error:
        print(f"Error fetching ASN {asn}: {error}")
    return []


def download_single_list(source):
    ips = []

    if source["name"] == "datacenter_asns":
        for line in download_source(source["url"]):
            asns = parse_line(line, source["regex"])
            for asn in asns:
                if asn and asn.isdigit():
                    ranges = get_asn_ranges(asn)
                    ips.extend(ranges)
                    if ranges:
                        print(f"ASN {asn}: {len(ranges)} ranges")
        return source["name"], ips

    if source["name"] == "tor_onionoo":
        for line in download_source(source["url"]):
            ips.extend(parse_line(line, source["regex"]))
        for asn in TOR_EXIT_NODE_ASNS:
            ranges = get_asn_ranges(asn)
            ips.extend(ranges)
            if ranges:
                print(f"Tor ASN {asn}: {len(ranges)} ranges")
        return source["name"], ips

    for line in download_source(source["url"]):
        ips.extend(parse_line(line, source["regex"]))

    return source["name"], ips


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


def extract_ipv4_from_ipv6(ipv6_str):
    try:
        ipv6_obj = ipaddress.IPv6Address(ipv6_str)

        if ipv6_obj.ipv4_mapped:
            return [str(ipv6_obj.ipv4_mapped)]

        if ipv6_str.lower().startswith("2002:"):
            parts = ipv6_str.split(":")
            if len(parts) >= 3:
                hex_ip = parts[1] + parts[2]
                if len(hex_ip) == 8:
                    ipv4_int = int(hex_ip, 16)
                    return [str(ipaddress.IPv4Address(ipv4_int))]

        parts = ipv6_str.split(":")
        for i, part in enumerate(parts):
            if part and part.isdigit() and 0 <= int(part) <= 255:
                if i + 3 < len(parts):
                    octets = parts[i : i + 4]
                    if all(p and p.isdigit() and 0 <= int(p) <= 255 for p in octets):
                        return [".".join(octets)]
    except ValueError:
        pass
    return []


def compress_ipv6(ip_str):
    try:
        if "/" in ip_str:
            ip_part, prefix = ip_str.split("/", 1)
            if ":" in ip_part:
                return str(ipaddress.IPv6Address(ip_part).compressed) + "/" + prefix
        elif ":" in ip_str:
            return str(ipaddress.IPv6Address(ip_str).compressed)
    except Exception:
        pass
    return ip_str


def process_feeds(feeds):
    processed = {}
    for list_name, ip_strings in feeds.items():
        addresses = []
        networks = []

        for ip_str in ip_strings:
            if not ip_str:
                continue
            if "-" in ip_str and ip_str.count("-") == 1:
                parts = ip_str.split("-")
                try:
                    start = int(parts[0])
                    end = int(parts[1])
                    networks.append([start, end])
                    continue
                except ValueError:
                    pass
            parsed = parse_ip(ip_str)
            if parsed is None:
                continue
            if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                start = int(parsed.network_address)
                end = int(parsed.broadcast_address)
                networks.append([start, end])
            elif isinstance(parsed, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                addresses.append(int(parsed))

        addresses = sorted(set(addresses))
        networks = sorted(set(tuple(network) for network in networks))
        networks = [list(network) for network in networks]
        processed[list_name] = {"addresses": addresses, "networks": networks}
    return processed


def load_ip2proxy_data():
    try:
        with open("data-ip2proxy.json") as file:
            data = json.load(file)
            return data.get("lists", {})
    except FileNotFoundError:
        print("Warning: data-ip2proxy.json not found")
        return {}


def main():
    with open("feeds.json") as file:
        sources = json.load(file)

    print("Downloading feeds...")
    feeds = download_all_feeds(sources)

    print("Loading IP2Proxy data...")
    ip2proxy_lists = load_ip2proxy_data()
    for name, data in ip2proxy_lists.items():
        feeds[name] = []
        for addr in data.get("addresses", []):
            feeds[name].append(str(addr))
        for net in data.get("networks", []):
            feeds[name].append(f"{net[0]}-{net[1]}")

    print("Processing feeds...")
    processed = process_feeds(feeds)

    timestamp = int(time.time())
    output = {"timestamp": timestamp, "feeds": processed}
    with open("data.json", "w") as file:
        json.dump(output, file, separators=(",", ":"))
    print(f"Saved data.json with {len(processed)} feeds")


if __name__ == "__main__":
    main()

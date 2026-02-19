import json
import time
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import re


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
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read().decode("utf-8", errors="ignore")
                return content.splitlines()
        except Exception as error:
            print(f"Error downloading {url} (attempt {attempt}/3): {error}")
            if attempt < 3:
                time.sleep(1)
    return []


def download_single_list(source):
    ips = []

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


def main():
    with open("feeds.json") as file:
        sources = json.load(file)

    print("Downloading feeds...")
    feeds = download_all_feeds(sources)

    print("Processing feeds...")
    processed = process_feeds(feeds)

    timestamp = int(time.time())
    output = {"timestamp": timestamp, "feeds": processed}
    with open("blocklist.json", "w") as file:
        json.dump(output, file, separators=(",", ":"))
    print(f"Saved blocklist.json with {len(processed)} feeds")


if __name__ == "__main__":
    main()

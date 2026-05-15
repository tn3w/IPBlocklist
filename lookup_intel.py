import ipaddress
import json
import math
import mmap
import struct
import sys
from bisect import bisect_right
from time import perf_counter

import numpy as np

FLAGS = [
    "vpn", "proxy", "tor", "malware", "c2", "scanner", "brute_force",
    "spammer", "compromised", "datacenter", "cdn", "anycast", "crawler",
    "bot", "cloud", "private_relay", "anonymizer", "mobile", "isp",
    "government",
]

SEVERITY = {
    "malware": 95, "c2": 95, "compromised": 75, "brute_force": 70,
    "spammer": 65, "scanner": 55, "tor": 45, "bot": 40, "anonymizer": 35,
    "vpn": 30, "proxy": 25, "datacenter": 15, "private_relay": 15,
    "cloud": 10, "crawler": 10, "cdn": 5,
    "anycast": 0, "mobile": 0, "isp": 0, "government": 0,
}

HEADER = (
    "version", "_r0", "v4n", "v6n", "valn", "strn",
    "v4s", "v4e", "v4v", "v6s", "v6e", "v6v",
    "vt", "si", "sd", "sl",
)

LEVELS = [(80, "critical"), (60, "high"), (35, "medium"), (15, "low")]


def level_for(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "minimal"


class IntelDb:
    def __init__(self, path):
        self.file = open(path, "rb")
        self.mm = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        self.h = dict(zip(HEADER, struct.unpack_from("<II14Q", self.mm, 0)))

        self.v4_starts = self._u32("v4s", "v4n")
        self.v4_ends = self._u32("v4e", "v4n")
        self.v4_vals = self._u16("v4v", "v4n")
        self.v4_max = np.maximum.accumulate(self.v4_ends)

        self.v6_starts = self._u128("v6s", "v6n")
        self.v6_ends = self._u128("v6e", "v6n")
        self.v6_vals = self._u16("v6v", "v6n")
        self.v6_max = list(np.maximum.accumulate(self.v6_ends or [0]))

        self.values = self._u32("vt", "valn", width=4).reshape(-1, 4)
        self.strings = self._strings()
        self.weights = self._weights()

    def _u32(self, off_key, n_key, width=1):
        return np.frombuffer(
            self.mm, dtype="<u4",
            count=self.h[n_key] * width, offset=self.h[off_key],
        )

    def _u16(self, off_key, n_key):
        return np.frombuffer(
            self.mm, dtype="<u2", count=self.h[n_key], offset=self.h[off_key],
        )

    def _u128(self, off_key, n_key):
        n = self.h[n_key]
        if not n:
            return []
        raw = np.frombuffer(
            self.mm, dtype="<u8", count=n * 2, offset=self.h[off_key],
        ).reshape(-1, 2)
        return [int(hi) << 64 | int(lo) for lo, hi in raw]

    def _strings(self):
        idx = np.frombuffer(
            self.mm, dtype="<u4", count=self.h["strn"] * 2,
            offset=self.h["si"],
        ).reshape(-1, 2)
        data = bytes(self.mm[self.h["sd"]:self.h["sd"] + self.h["sl"]])
        return [
            data[int(o):int(o) + int(length)].decode("utf-8", "replace")
            for o, length in idx
        ]

    def _weights(self):
        bits = self.values[:, 0][self.v4_vals]
        total = max(len(bits), 1)
        weights = {}
        for i, name in enumerate(FLAGS):
            count = int(np.sum((bits & (1 << i)) != 0))
            prevalence = max(count / total, 1 / total)
            rarity = math.log2(1 / prevalence)
            weights[name] = SEVERITY[name] * (1 + rarity / 24)
        return weights

    def _scan(self, starts, ends, max_end, vals, ip, start_idx):
        out = []
        i = start_idx
        while i > 0:
            i -= 1
            if max_end[i] < ip:
                break
            if ends[i] >= ip:
                out.append((int(starts[i]), int(ends[i]), int(vals[i])))
        return out

    def _hits(self, ip, v4):
        if v4:
            i = int(np.searchsorted(self.v4_starts, ip, side="right"))
            return self._scan(
                self.v4_starts, self.v4_ends, self.v4_max, self.v4_vals, ip, i,
            )
        if not self.v6_starts:
            return []
        i = bisect_right(self.v6_starts, ip)
        return self._scan(
            self.v6_starts, self.v6_ends, self.v6_max, self.v6_vals, ip, i,
        )

    def _render(self, start, end, val_id, formatter):
        bits, provider_id, source_id, _ = self.values[val_id]
        bits = int(bits)
        return {
            "range": f"{formatter(start)}-{formatter(end)}",
            "provider": self.strings[int(provider_id)],
            "source": self.strings[int(source_id)],
            "flags": [n for i, n in enumerate(FLAGS) if bits & (1 << i)],
        }

    def lookup(self, ip_str):
        addr = ipaddress.ip_address(ip_str)
        formatter = (
            ipaddress.IPv4Address if addr.version == 4 else ipaddress.IPv6Address
        )
        matches = [
            self._render(s, e, v, formatter)
            for s, e, v in self._hits(int(addr), addr.version == 4)
        ]
        return {"matches": matches, "score": self._score(matches)}

    def _score(self, matches):
        if not matches:
            return {"score": 0, "level": "unknown", "reasons": []}

        flag_value = {}
        for match in matches:
            for flag in match["flags"]:
                value = self.weights[flag]
                if value > flag_value.get(flag, 0):
                    flag_value[flag] = value

        if not flag_value:
            return {"score": 0, "level": "unknown", "reasons": []}

        ranked = sorted(flag_value.items(), key=lambda x: -x[1])
        top = ranked[0][1]
        extras = sum(v for _, v in ranked[1:]) * 0.15

        sources = {(m["provider"], m["source"]) for m in matches}
        boost = 1 + 0.08 * math.log2(len(sources) + 1)
        score = round(min(100, (top + extras) * boost), 1)

        return {
            "score": score,
            "level": level_for(score),
            "reasons": [f for f, _ in ranked[:5]],
            "sources": len(sources),
        }


def main():
    if len(sys.argv) < 2:
        print("usage: lookup_intel.py <ip> [intel.bin]", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[2] if len(sys.argv) > 2 else "intel.bin"
    t = perf_counter()
    db = IntelDb(path)
    load_us = int((perf_counter() - t) * 1e6)

    t = perf_counter()
    result = db.lookup(sys.argv[1])
    lookup_ns = int((perf_counter() - t) * 1e9)

    print(json.dumps({
        "ip": sys.argv[1],
        "found": bool(result["matches"]),
        "score": result["score"],
        "matches": result["matches"],
        "_perf": {"load_us": load_us, "lookup_ns": lookup_ns},
    }, indent=2))


if __name__ == "__main__":
    main()

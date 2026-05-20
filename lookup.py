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
    "version", "_r0",
    "cn", "ln", "v6n", "valn", "strn",
    "bucket", "starts_lo", "lens", "vals",
    "lstarts", "lends", "lvals",
    "v6s", "v6e", "v6v",
    "vt", "si", "sd", "sl",
)

V4_BUCKETS = 65536
LEVELS = [(80, "critical"), (60, "high"), (35, "medium"), (15, "low")]


def level_for(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "minimal"


def prefer_tor(providers):
    ordered = list(dict.fromkeys(p for p in providers if p))
    for i, p in enumerate(ordered):
        if p.lower() == "tor":
            ordered.pop(i)
            ordered.insert(0, "Tor")
            break
    return ordered


class IntelDb:
    def __init__(self, path):
        self.file = open(path, "rb")
        self.mm = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        fields = struct.unpack_from("<II19Q", self.mm, 0)
        self.h = dict(zip(HEADER, fields))
        if self.h["version"] != 6:
            raise SystemExit(
                f"unsupported intel.bin version {self.h['version']} (expected 6)"
            )

        self.bucket_index = np.frombuffer(
            self.mm, dtype="<u4", count=V4_BUCKETS + 1,
            offset=self.h["bucket"],
        )
        cn = self.h["cn"]
        self.starts_lo = np.frombuffer(
            self.mm, dtype="<u2", count=cn, offset=self.h["starts_lo"],
        ) if cn else np.zeros(0, dtype="<u2")
        self.lens = np.frombuffer(
            self.mm, dtype="<u2", count=cn, offset=self.h["lens"],
        ) if cn else np.zeros(0, dtype="<u2")
        self.vals = np.frombuffer(
            self.mm, dtype="<u2", count=cn, offset=self.h["vals"],
        ) if cn else np.zeros(0, dtype="<u2")

        ln = self.h["ln"]
        self.lstarts = np.frombuffer(
            self.mm, dtype="<u4", count=ln, offset=self.h["lstarts"],
        ) if ln else np.zeros(0, dtype="<u4")
        self.lends = np.frombuffer(
            self.mm, dtype="<u4", count=ln, offset=self.h["lends"],
        ) if ln else np.zeros(0, dtype="<u4")
        self.lvals = np.frombuffer(
            self.mm, dtype="<u2", count=ln, offset=self.h["lvals"],
        ) if ln else np.zeros(0, dtype="<u2")
        self.lmax = (np.maximum.accumulate(self.lends) if ln
                     else np.zeros(0, dtype="<u4"))

        self.max_ends_lo = self._build_max_ends_lo()

        v6n = self.h["v6n"]
        self.v6_starts = self._u128("v6s", v6n)
        self.v6_ends = self._u128("v6e", v6n)
        self.v6_vals = np.frombuffer(
            self.mm, dtype="<u2", count=v6n, offset=self.h["v6v"],
        ) if v6n else np.zeros(0, dtype="<u2")
        self.v6_max = (list(np.maximum.accumulate(self.v6_ends))
                       if self.v6_ends else [])

        self.values = self._values()
        self.strings = self._strings()
        self.weights = self._weights()

    def _u128(self, key, n):
        if not n:
            return []
        raw = np.frombuffer(
            self.mm, dtype="<u8", count=n * 2, offset=self.h[key],
        ).reshape(-1, 2)
        return [int(hi) << 64 | int(lo) for lo, hi in raw]

    def _build_max_ends_lo(self):
        out = np.zeros(len(self.starts_lo), dtype="<u2")
        end_lo = (self.starts_lo.astype(np.uint32) +
                  self.lens.astype(np.uint32)).astype(np.uint16)
        for b in range(V4_BUCKETS):
            s = int(self.bucket_index[b])
            e = int(self.bucket_index[b + 1])
            if s < e:
                out[s:e] = np.maximum.accumulate(end_lo[s:e])
        return out

    def _values(self):
        n = self.h["valn"]
        if not n:
            return np.zeros((0, 4), dtype="<u4")
        return np.frombuffer(
            self.mm, dtype="<u4", count=n * 4, offset=self.h["vt"],
        ).reshape(-1, 4)

    def _strings(self):
        n = self.h["strn"]
        idx = np.frombuffer(
            self.mm, dtype="<u4", count=n * 2, offset=self.h["si"],
        ).reshape(-1, 2)
        data = bytes(self.mm[self.h["sd"]:self.h["sd"] + self.h["sl"]])
        return [
            data[int(o):int(o) + int(length)].decode("utf-8", "replace")
            for o, length in idx
        ]

    def _weights(self):
        all_vals = np.concatenate([self.vals, self.lvals])
        if len(all_vals) == 0:
            return {f: SEVERITY[f] for f in FLAGS}
        bits = self.values[:, 0][all_vals]
        total = max(len(bits), 1)
        weights = {}
        for i, name in enumerate(FLAGS):
            count = int(np.sum((bits & (1 << i)) != 0))
            prevalence = max(count / total, 1 / total)
            rarity = math.log2(1 / prevalence)
            weights[name] = SEVERITY[name] * (1 + rarity / 24)
        return weights

    def _lookup_v4(self, ip):
        out = []
        bucket = ip >> 16
        ip_lo = ip & 0xFFFF
        bs = int(self.bucket_index[bucket])
        be = int(self.bucket_index[bucket + 1])
        if bs < be:
            starts = self.starts_lo[bs:be]
            lens = self.lens[bs:be]
            vals = self.vals[bs:be]
            mends = self.max_ends_lo[bs:be]
            i = int(np.searchsorted(starts, ip_lo, side="right"))
            prefix = bucket << 16
            while i > 0:
                i -= 1
                if mends[i] < ip_lo:
                    break
                end_lo = (int(starts[i]) + int(lens[i])) & 0xFFFF
                if end_lo >= ip_lo:
                    out.append((
                        prefix | int(starts[i]),
                        prefix | end_lo,
                        int(vals[i]),
                    ))
        if len(self.lstarts):
            i = int(np.searchsorted(self.lstarts, ip, side="right"))
            while i > 0:
                i -= 1
                if self.lmax[i] < ip:
                    break
                if self.lends[i] >= ip:
                    out.append((
                        int(self.lstarts[i]),
                        int(self.lends[i]),
                        int(self.lvals[i]),
                    ))
        return out

    def _lookup_v6(self, ip):
        if not self.v6_starts:
            return []
        out = []
        i = bisect_right(self.v6_starts, ip)
        while i > 0:
            i -= 1
            if self.v6_max[i] < ip:
                break
            if self.v6_ends[i] >= ip:
                out.append((
                    int(self.v6_starts[i]),
                    int(self.v6_ends[i]),
                    int(self.v6_vals[i]),
                ))
        return out

    def _render(self, start, end, val_id, formatter):
        bits, provider_id, source_id, _ = self.values[val_id]
        bits = int(bits)
        flags = [n for i, n in enumerate(FLAGS) if bits & (1 << i)]
        weight = max((self.weights[f] for f in flags), default=0)
        return {
            "source": self.strings[int(source_id)],
            "provider": self.strings[int(provider_id)],
            "range": f"{formatter(start)}-{formatter(end)}",
            "flags": flags,
            "weight": round(weight, 1),
        }

    def lookup(self, ip_str):
        addr = ipaddress.ip_address(ip_str)
        is_v4 = addr.version == 4
        formatter = (ipaddress.IPv4Address if is_v4
                     else ipaddress.IPv6Address)
        raw = (self._lookup_v4(int(addr)) if is_v4
               else self._lookup_v6(int(addr)))
        matches = [self._render(s, e, v, formatter) for s, e, v in raw]
        matches.sort(key=lambda m: -m["weight"])
        return self._summary(ip_str, matches)

    def _score(self, matches):
        flag_value = {}
        for match in matches:
            for flag in match["flags"]:
                value = self.weights[flag]
                if value > flag_value.get(flag, 0):
                    flag_value[flag] = value
        if not flag_value:
            return 0.0, [], 0
        ranked = sorted(flag_value.items(), key=lambda x: -x[1])
        top = ranked[0][1]
        extras = sum(v for _, v in ranked[1:]) * 0.15
        sources = {(m["provider"], m["source"]) for m in matches}
        boost = 1 + 0.08 * math.log2(len(sources) + 1)
        score = round(min(100, (top + extras) * boost), 1)
        reasons = [f for f, _ in ranked[:5]]
        return score, reasons, len(sources)

    def _summary(self, ip, matches):
        score, reasons, source_count = self._score(matches)
        all_flags = []
        for match in matches:
            for flag in match["flags"]:
                if flag not in all_flags:
                    all_flags.append(flag)
        providers = prefer_tor(m["provider"] for m in matches)
        return {
            "ip": ip,
            "found": bool(matches),
            "verdict": level_for(score) if matches else "clean",
            "score": score,
            "detections": len(matches),
            "sources": source_count,
            "top_provider": providers[0] if providers else "",
            "providers": providers,
            "flags": all_flags,
            "reasons": reasons,
            "matches": matches,
        }


def main():
    if len(sys.argv) < 2:
        print("usage: lookup.py <ip> [intel.bin]", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[2] if len(sys.argv) > 2 else "intel.bin"
    t = perf_counter()
    db = IntelDb(path)
    load_us = int((perf_counter() - t) * 1e6)

    t = perf_counter()
    result = db.lookup(sys.argv[1])
    lookup_ns = int((perf_counter() - t) * 1e9)

    result["_perf"] = {"load_us": load_us, "lookup_ns": lookup_ns}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

import ipaddress
import mmap
import struct
import sys
from bisect import bisect_right
from time import perf_counter

import numpy as np

FLAG_NAMES = [
    "vpn", "proxy", "tor", "malware", "c2", "scanner", "brute_force",
    "spammer", "compromised", "datacenter", "cdn", "anycast", "crawler",
    "bot", "cloud", "private_relay", "anonymizer", "mobile", "isp",
    "government",
]
HEADER_SIZE = 128
HEADER_FIELDS = (
    "version", "_r0", "v4_count", "v6_count", "val_count", "str_count",
    "v4_starts_off", "v4_ends_off", "v4_vals_off",
    "v6_starts_off", "v6_ends_off", "v6_vals_off",
    "val_table_off", "str_index_off", "str_data_off", "str_data_len",
)


class IntelDb:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        h = struct.unpack_from("<II14Q", self.mm, 0)
        self.h = dict(zip(HEADER_FIELDS, h))
        v4n, v6n = self.h["v4_count"], self.h["v6_count"]

        self.v4_starts = self._u32(self.h["v4_starts_off"], v4n)
        self.v4_ends   = self._u32(self.h["v4_ends_off"], v4n)
        self.v4_vals   = self._u16(self.h["v4_vals_off"], v4n)
        self.v4_maxend = np.maximum.accumulate(self.v4_ends)

        self.v6_starts = self._u128_list(self.h["v6_starts_off"], v6n)
        self.v6_ends   = self._u128_list(self.h["v6_ends_off"], v6n)
        self.v6_vals   = self._u16(self.h["v6_vals_off"], v6n)
        self.v6_maxend = self._prefix_max(self.v6_ends)

        self.values = self._values(self.h["val_table_off"], self.h["val_count"])
        self.strings = self._strings(
            self.h["str_index_off"], self.h["str_count"],
            self.h["str_data_off"], self.h["str_data_len"],
        )

    def _u32(self, off, n):
        return np.frombuffer(self.mm, dtype="<u4", count=n, offset=off)

    def _u16(self, off, n):
        return np.frombuffer(self.mm, dtype="<u2", count=n, offset=off)

    def _u128_list(self, off, n):
        if n == 0:
            return []
        raw = np.frombuffer(self.mm, dtype="<u8", count=n * 2, offset=off).reshape(-1, 2)
        return [int(hi) << 64 | int(lo) for lo, hi in raw]

    @staticmethod
    def _prefix_max(xs):
        out = []
        m = 0
        for x in xs:
            if x > m:
                m = x
            out.append(m)
        return out

    def _values(self, off, n):
        arr = np.frombuffer(self.mm, dtype="<u4", count=n * 4, offset=off)
        return arr.reshape(-1, 4)

    def _strings(self, idx_off, n, data_off, data_len):
        idx = np.frombuffer(self.mm, dtype="<u4", count=n * 2, offset=idx_off)
        data = bytes(self.mm[data_off:data_off + data_len])
        out = []
        for i in range(n):
            o, ln = int(idx[i * 2]), int(idx[i * 2 + 1])
            out.append(data[o:o + ln].decode("utf-8", "replace"))
        return out

    def _hits(self, starts, ends, maxend, vals, ip):
        i = int(np.searchsorted(starts, ip, side="right"))
        out = []
        while i > 0:
            i -= 1
            if maxend[i] < ip:
                break
            if ends[i] >= ip:
                out.append((starts[i], ends[i], vals[i]))
        return out

    def lookup(self, ip_str):
        addr = ipaddress.ip_address(ip_str)
        if addr.version == 4:
            raw = self._hits(self.v4_starts, self.v4_ends, self.v4_maxend,
                             self.v4_vals, int(addr))
            fmt = ipaddress.IPv4Address
        else:
            raw = self._hits6(int(addr))
            fmt = ipaddress.IPv6Address
        return [self._render(s, e, v, fmt) for s, e, v in raw]

    def _hits6(self, ip):
        starts = self.v6_starts
        if not starts:
            return []
        i = bisect_right(starts, ip)
        ends, maxend, vals = self.v6_ends, self.v6_maxend, self.v6_vals
        out = []
        while i > 0:
            i -= 1
            if maxend[i] < ip:
                break
            if ends[i] >= ip:
                out.append((starts[i], ends[i], int(vals[i])))
        return out

    def _render(self, s, e, val_id, fmt):
        flags, prov_id, src_id, _ = self.values[val_id]
        flags = int(flags)
        return {
            "range": f"{fmt(int(s))}-{fmt(int(e))}",
            "provider": self.strings[int(prov_id)],
            "source": self.strings[int(src_id)],
            "flags": [n for i, n in enumerate(FLAG_NAMES) if flags & (1 << i)],
            "flag_bits": flags,
        }


def main():
    if len(sys.argv) < 2:
        print("usage: lookup_intel.py <ip> [intel.bin]", file=sys.stderr)
        sys.exit(1)
    path = sys.argv[2] if len(sys.argv) > 2 else "intel.bin"
    t = perf_counter()
    db = IntelDb(path)
    load_us = (perf_counter() - t) * 1e6
    t = perf_counter()
    hits = db.lookup(sys.argv[1])
    lookup_ns = (perf_counter() - t) * 1e9
    import json
    print(json.dumps({
        "ip": sys.argv[1],
        "found": bool(hits),
        "matches": hits,
        "_perf": {"load_us": int(load_us), "lookup_ns": int(lookup_ns)},
    }, indent=2))


if __name__ == "__main__":
    main()

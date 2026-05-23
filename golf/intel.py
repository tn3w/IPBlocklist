import ipaddress
import numpy as np
from bisect import bisect_right
from types import SimpleNamespace

FLAGS = ("vpn proxy tor malware c2 scanner brute_force spammer compromised "
         "datacenter cdn anycast crawler bot cloud private_relay anonymizer "
         "mobile isp government").split()
SEV = dict(zip(FLAGS, [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0]))
LEVELS = ((80,"critical"),(60,"high"),(35,"medium"),(15,"low"))


def load(path):
    d = open(path, "rb").read()
    ver = int(np.frombuffer(d, "<u4", 1)[0])
    if ver != 6: raise SystemExit(f"unsupported version {ver}")
    cn, ln, v6n, valn, strn, *o = map(int, np.frombuffer(d, "<u8", 19, 8))
    a = lambda dt, n, off: np.frombuffer(d, dt, n, off) if n else np.zeros(0, dt)
    bi = a("<u4", 65537, o[0])
    bid = np.repeat(np.arange(65536, dtype="<u4"), np.diff(bi).astype(np.intp))
    ss = (bid << 16) | a("<u2", cn, o[1]).astype("<u4")
    all_s = np.concatenate([ss, a("<u4", ln, o[4])])
    all_e = np.concatenate([ss + a("<u2", cn, o[2]), a("<u4", ln, o[5])])
    all_v = np.concatenate([a("<u2", cn, o[3]), a("<u2", ln, o[6])])
    k = np.argsort(all_s, kind="stable")
    v4s, v4e, v4v = all_s[k], all_e[k], all_v[k]
    raw6 = lambda off: ([int(h)<<64|int(l) for l,h in
                         a("<u8", v6n*2, off).reshape(-1,2)] if v6n else [])
    v6s, v6e, v6v = raw6(o[7]), raw6(o[8]), a("<u2", v6n, o[9])
    values = a("<u4", valn*4, o[10]).reshape(-1,4) if valn else np.zeros((0,4),"<u4")
    sidx = a("<u4", strn*2, o[11]).reshape(-1,2) if strn else np.zeros((0,2),"<u4")
    blob = d[o[12]:o[12]+o[13]]
    if len(v4v):
        bits, tot = values[v4v.astype(np.intp), 0], len(v4v)
        weights = {f: SEV[f] * (1 + np.log2(tot / max(int(((bits>>i)&1).sum()), 1)) / 24)
                   for i, f in enumerate(FLAGS)}
    else:
        weights = dict(SEV)
    return SimpleNamespace(
        v4_starts=v4s, v4_ends=v4e, v4_vals=v4v,
        v4_max=np.maximum.accumulate(v4e) if len(v4e) else v4e,
        v6_starts=v6s, v6_ends=v6e, v6_vals=v6v,
        v6_max=list(np.maximum.accumulate(v6e)) if v6n else [],
        values=values, weights=weights,
        strings=[blob[int(p):int(p)+int(L)].decode("utf-8","replace") for p,L in sidx])


def _hits(db, ip, v4):
    if v4:
        s, e, m, v = db.v4_starts, db.v4_ends, db.v4_max, db.v4_vals
        if not len(s): return []
        i = int(np.searchsorted(s, ip, side="right"))
    else:
        s, e, m, v = db.v6_starts, db.v6_ends, db.v6_max, db.v6_vals
        if not s: return []
        i = bisect_right(s, ip)
    out = []
    while i > 0:
        i -= 1
        if m[i] < ip: break
        if e[i] >= ip: out.append((int(s[i]), int(e[i]), int(v[i])))
    return out


def lookup(db, ip_str):
    addr = ipaddress.ip_address(ip_str)
    v4 = addr.version == 4
    fmt = ipaddress.IPv4Address if v4 else ipaddress.IPv6Address
    matches = []
    for s, e, vid in _hits(db, int(addr), v4):
        b, prov, src, _ = (int(x) for x in db.values[vid])
        flags = [n for i, n in enumerate(FLAGS) if b & (1 << i)]
        matches.append({"source": db.strings[src], "provider": db.strings[prov],
                        "range": f"{fmt(s)}-{fmt(e)}", "flags": flags,
                        "weight": round(max((db.weights[f] for f in flags), default=0), 1)})
    matches.sort(key=lambda m: -m["weight"])
    ranked = sorted({f for m in matches for f in m["flags"]}, key=lambda f: -db.weights[f])
    sources = {(m["provider"], m["source"]) for m in matches}
    score = round(min(100, (db.weights[ranked[0]] + sum(db.weights[f] for f in ranked[1:]) * 0.15)
                  * (1 + 0.08 * np.log2(len(sources) + 1))), 1) if ranked else 0.0
    all_flags = list(dict.fromkeys(f for m in matches for f in m["flags"]))
    providers = list(dict.fromkeys(m["provider"] for m in matches if m["provider"]))
    if any(p.lower() == "tor" for p in providers):
        providers = ["Tor"] + [p for p in providers if p.lower() != "tor"]
    return {"ip": ip_str, "found": bool(matches),
            "verdict": (next((n for t,n in LEVELS if score>=t), "minimal") if matches else "clean"),
            "score": score, "detections": len(matches), "sources": len(sources),
            "top_provider": providers[0] if providers else "",
            "providers": providers, "flags": all_flags,
            "reasons": ranked[:5], "matches": matches}


if __name__ == "__main__":
    import sys, json
    db = load("../intel.bin")
    print(json.dumps(lookup(db, sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"), indent=2))

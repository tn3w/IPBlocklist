import std.stdio;
import std.file : read;
import std.bigint;
import std.math;
import std.algorithm;
import std.array;
import std.range;
import std.string;
import std.conv;
import std.format;
import std.bitmanip : littleEndianToNative;

immutable string[20] FLAGS = ["vpn","proxy","tor","malware","c2","scanner",
    "brute_force","spammer","compromised","datacenter","cdn","anycast",
    "crawler","bot","cloud","private_relay","anonymizer","mobile","isp","government"];
immutable double[20] SEV = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0];
immutable Tup!(double,string)[4] LEVELS = [
    Tup!(double,string)(80,"critical"), Tup!(double,string)(60,"high"),
    Tup!(double,string)(35,"medium"), Tup!(double,string)(15,"low")];

struct Tup(A,B) { A a; B b; }

uint u32(const(ubyte)[] d, size_t o) {
    return littleEndianToNative!uint(d[o..o+4][0..4]);
}
ulong u64(const(ubyte)[] d, size_t o) {
    return littleEndianToNative!ulong(d[o..o+8][0..8]);
}
ushort u16(const(ubyte)[] d, size_t o) {
    return littleEndianToNative!ushort(d[o..o+2][0..2]);
}

struct Match {
    string source, provider, range;
    string[] flags;
    double weight;
}

struct DB {
    uint[] v4s, v4e, v4m;
    ushort[] v4v;
    BigInt[] v6s, v6e, v6m;
    ushort[] v6v;
    uint[4][] vt;
    string[] st;
    double[20] w;
}

DB load(string path) {
    auto d = cast(ubyte[]) read(path);
    if (u32(d, 0) != 6) throw new Exception("unsupported version");
    ulong[19] o;
    foreach (i; 0..19) o[i] = u64(d, 8 + i*8);
    auto cn = cast(size_t)o[0], ln = cast(size_t)o[1], v6n = cast(size_t)o[2];
    auto valn = cast(size_t)o[3], strn = cast(size_t)o[4];
    auto bOff = cast(size_t)o[5], sLoOff = cast(size_t)o[6];
    auto lensOff = cast(size_t)o[7], valsOff = cast(size_t)o[8];
    auto lsOff = cast(size_t)o[9], leOff = cast(size_t)o[10], lvOff = cast(size_t)o[11];
    auto v6sOff = cast(size_t)o[12], v6eOff = cast(size_t)o[13], v6vOff = cast(size_t)o[14];
    auto vtOff = cast(size_t)o[15], siOff = cast(size_t)o[16];
    auto sd = cast(size_t)o[17], sl = cast(size_t)o[18];

    auto bi = new uint[](65537);
    foreach (i; 0..65537) bi[i] = u32(d, bOff + i*4);

    auto N = cn + ln;
    auto v4s = new uint[](N), v4e = new uint[](N);
    auto v4v = new ushort[](N);
    uint j = 0;
    foreach (b; 0..65536) {
        for (; j < bi[b+1]; j++) {
            uint lo = u16(d, sLoOff + j*2);
            v4s[j] = (cast(uint)b << 16) | lo;
            v4e[j] = v4s[j] + u16(d, lensOff + j*2);
            v4v[j] = u16(d, valsOff + j*2);
        }
    }
    foreach (i; 0..ln) {
        v4s[cn+i] = u32(d, lsOff + i*4);
        v4e[cn+i] = u32(d, leOff + i*4);
        v4v[cn+i] = u16(d, lvOff + i*2);
    }
    auto idx = iota(N).array;
    sort!((a,b) => v4s[a] < v4s[b], SwapStrategy.stable)(idx);
    auto ts = new uint[](N), te = new uint[](N);
    auto tv = new ushort[](N);
    foreach (i, k; idx) { ts[i] = v4s[k]; te[i] = v4e[k]; tv[i] = v4v[k]; }
    v4s = ts; v4e = te; v4v = tv;
    auto v4m = new uint[](N);
    uint mx = 0;
    foreach (i, e; v4e) { if (e > mx) mx = e; v4m[i] = mx; }

    BigInt[] readV6(size_t off) {
        auto r = new BigInt[](v6n);
        foreach (i; 0..v6n) {
            BigInt lo = BigInt(u64(d, off + i*16));
            BigInt hi = BigInt(u64(d, off + i*16 + 8));
            r[i] = (hi << 64) | lo;
        }
        return r;
    }
    auto v6s = readV6(v6sOff), v6e = readV6(v6eOff);
    auto v6v = new ushort[](v6n);
    foreach (i; 0..v6n) v6v[i] = u16(d, v6vOff + i*2);
    auto v6m = new BigInt[](v6n);
    BigInt mb = BigInt(0);
    foreach (i, ref e; v6e) { if (e > mb) mb = e; v6m[i] = mb; }

    auto vt = new uint[4][](valn);
    foreach (i; 0..valn) foreach (k2; 0..4)
        vt[i][k2] = u32(d, vtOff + (i*4 + k2)*4);

    auto st = new string[](strn);
    foreach (i; 0..strn) {
        auto so = u32(d, siOff + i*8);
        auto slen = u32(d, siOff + i*8 + 4);
        st[i] = cast(string) d[sd+so .. sd+so+slen].idup;
    }

    double[20] w;
    if (N > 0) {
        int[20] c;
        foreach (vid; v4v) {
            auto bits = vt[vid][0];
            foreach (i; 0..20) if (bits & (1 << i)) c[i]++;
        }
        foreach (i; 0..20) {
            auto cc = c[i] == 0 ? 1 : c[i];
            w[i] = SEV[i] * (1 + log2(cast(double)N / cc) / 24);
        }
    } else {
        w = SEV;
    }
    DB db;
    db.v4s = v4s; db.v4e = v4e; db.v4m = v4m; db.v4v = v4v;
    db.v6s = v6s; db.v6e = v6e; db.v6m = v6m; db.v6v = v6v;
    db.vt = vt; db.st = st; db.w = w;
    return db;
}

double r1(double x) { return round(x * 10) / 10.0; }

string fmtV4(uint ip) {
    return format("%d.%d.%d.%d", (ip>>24)&0xff, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);
}

string fmtV6(BigInt ip) {
    ushort[8] g;
    BigInt mask = BigInt(0xffff);
    foreach (i; 0..8) {
        auto sh = (7 - i) * 16;
        g[i] = cast(ushort) ((ip >> sh) & mask).toLong;
    }
    int bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
    foreach (i; 0..8) {
        if (g[i] == 0) {
            if (curStart < 0) { curStart = cast(int)i; curLen = 1; }
            else curLen++;
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
        } else { curStart = -1; curLen = 0; }
    }
    if (bestLen < 2) { bestStart = -1; bestLen = 0; }
    auto buf = appender!string;
    int i = 0;
    while (i < 8) {
        if (i == bestStart) {
            buf.put(i == 0 ? "::" : ":");
            i += bestLen;
            if (i >= 8) return buf.data;
            continue;
        }
        if (i > 0 && (buf.data.length == 0 || buf.data[$-1] != ':')) buf.put(":");
        buf.put(format("%x", g[i]));
        i++;
    }
    return buf.data;
}

bool parseV4(string ip, out uint res) {
    auto parts = ip.split(".");
    if (parts.length != 4) return false;
    uint r = 0;
    foreach (p; parts) {
        if (p.length == 0 || p.length > 3) return false;
        foreach (c; p) if (c < '0' || c > '9') return false;
        auto v = to!uint(p);
        if (v > 255) return false;
        r = (r << 8) | v;
    }
    res = r;
    return true;
}

bool parseV6(string ip, out BigInt res) {
    string left = ip, right = "";
    auto dd = ip.indexOf("::");
    if (dd >= 0) {
        left = ip[0..dd];
        right = ip[dd+2..$];
    }
    auto lp = left.length ? left.split(":") : [];
    auto rp = right.length ? right.split(":") : [];
    if (dd < 0 && lp.length != 8) return false;
    auto total = lp.length + rp.length;
    if (total > 8) return false;
    auto zeros = 8 - total;
    if (dd < 0) zeros = 0;
    ushort[8] g;
    size_t idx = 0;
    foreach (p; lp) {
        if (p.length == 0 || p.length > 4) return false;
        g[idx++] = cast(ushort) to!uint(p, 16);
    }
    foreach (_; 0..zeros) g[idx++] = 0;
    foreach (p; rp) {
        if (p.length == 0 || p.length > 4) return false;
        g[idx++] = cast(ushort) to!uint(p, 16);
    }
    BigInt r = BigInt(0);
    foreach (v; g) r = (r << 16) | BigInt(cast(uint)v);
    res = r;
    return true;
}

string jStr(string s) {
    auto buf = appender!string;
    buf.put('"');
    foreach (c; s) {
        switch (c) {
            case '"': buf.put("\\\""); break;
            case '\\': buf.put("\\\\"); break;
            case '\n': buf.put("\\n"); break;
            case '\r': buf.put("\\r"); break;
            case '\t': buf.put("\\t"); break;
            case '\b': buf.put("\\b"); break;
            case '\f': buf.put("\\f"); break;
            default:
                if (c < 0x20) buf.put(format("\\u%04x", cast(int)c));
                else buf.put(c);
        }
    }
    buf.put('"');
    return buf.data;
}

string jNum(double v) {
    if (v == cast(long)v) return format("%d", cast(long)v);
    auto s = format("%.1f", v);
    return s;
}

string jArrStr(string[] arr, string indent) {
    if (arr.length == 0) return "[]";
    auto inner = indent ~ "  ";
    auto items = arr.map!(s => inner ~ jStr(s)).join(",\n");
    return "[\n" ~ items ~ "\n" ~ indent ~ "]";
}

string buildMatches(Match[] ms, string indent) {
    if (ms.length == 0) return "[]";
    auto inner = indent ~ "  ";
    auto inner2 = inner ~ "  ";
    string[] parts;
    foreach (m; ms) {
        auto s = "{\n";
        s ~= inner2 ~ jStr("source") ~ ": " ~ jStr(m.source) ~ ",\n";
        s ~= inner2 ~ jStr("provider") ~ ": " ~ jStr(m.provider) ~ ",\n";
        s ~= inner2 ~ jStr("range") ~ ": " ~ jStr(m.range) ~ ",\n";
        s ~= inner2 ~ jStr("flags") ~ ": " ~ jArrStr(m.flags, inner2) ~ ",\n";
        s ~= inner2 ~ jStr("weight") ~ ": " ~ jNum(m.weight) ~ "\n";
        s ~= inner ~ "}";
        parts ~= s;
    }
    return "[\n" ~ inner ~ parts.join(",\n" ~ inner) ~ "\n" ~ indent ~ "]";
}

string lookup(ref DB db, string ipStr) {
    Match[] matches;
    uint v4ip;
    BigInt v6ip;
    bool isV4 = parseV4(ipStr, v4ip);
    if (!isV4 && !parseV6(ipStr, v6ip))
        throw new Exception("bad ip");

    void push(ushort vid, string rng) {
        auto bits = db.vt[vid][0];
        string[] fl;
        double mxw = 0;
        foreach (i; 0..20) {
            if (bits & (1 << i)) {
                fl ~= FLAGS[i];
                if (db.w[i] > mxw) mxw = db.w[i];
            }
        }
        matches ~= Match(db.st[db.vt[vid][2]], db.st[db.vt[vid][1]], rng, fl, r1(mxw));
    }

    if (isV4) {
        auto n = db.v4s.length;
        size_t lo = 0, hi = n;
        while (lo < hi) {
            auto mid = (lo + hi) / 2;
            if (db.v4s[mid] > v4ip) hi = mid;
            else lo = mid + 1;
        }
        auto i = lo;
        while (i > 0) {
            i--;
            if (db.v4m[i] < v4ip) break;
            if (db.v4e[i] >= v4ip)
                push(db.v4v[i], fmtV4(db.v4s[i]) ~ "-" ~ fmtV4(db.v4e[i]));
        }
    } else {
        auto n = db.v6s.length;
        size_t lo = 0, hi = n;
        while (lo < hi) {
            auto mid = (lo + hi) / 2;
            if (db.v6s[mid] > v6ip) hi = mid;
            else lo = mid + 1;
        }
        auto i = lo;
        while (i > 0) {
            i--;
            if (db.v6m[i] < v6ip) break;
            if (db.v6e[i] >= v6ip)
                push(db.v6v[i], fmtV6(db.v6s[i]) ~ "-" ~ fmtV6(db.v6e[i]));
        }
    }

    sort!((a,b) => a.weight > b.weight, SwapStrategy.stable)(matches);

    int[string] fIdx;
    foreach (i, f; FLAGS) fIdx[f] = cast(int)i;

    bool[string] seenF;
    bool[string] seenSrc;
    foreach (m; matches) {
        foreach (f; m.flags) seenF[f] = true;
        seenSrc[m.provider ~ "|" ~ m.source] = true;
    }
    string[] ranked = seenF.keys;
    sort!((a,b) => db.w[fIdx[a]] > db.w[fIdx[b]], SwapStrategy.stable)(ranked);

    double score = 0;
    if (ranked.length > 0) {
        double top = db.w[fIdx[ranked[0]]];
        double ex = 0;
        foreach (f; ranked[1..$]) ex += db.w[fIdx[f]];
        score = r1(fmin(100.0, (top + ex * 0.15) * (1 + 0.08 * log2(cast(double)(seenSrc.length + 1)))));
    }
    string verdict = "clean";
    if (matches.length > 0) {
        verdict = "minimal";
        foreach (lv; LEVELS) if (score >= lv.a) { verdict = lv.b; break; }
    }

    string[] allFlags, providers;
    bool[string] sf, sp;
    foreach (m; matches) {
        foreach (f; m.flags) if (f !in sf) { sf[f] = true; allFlags ~= f; }
        if (m.provider.length && m.provider !in sp) { sp[m.provider] = true; providers ~= m.provider; }
    }
    foreach (i, p; providers) {
        if (p.toLower == "tor") {
            providers = ["Tor"] ~ providers[0..i] ~ providers[i+1..$];
            break;
        }
    }
    string topProv = providers.length ? providers[0] : "";
    auto reasons = ranked.length > 5 ? ranked[0..5] : ranked;

    auto buf = appender!string;
    buf.put("{\n");
    buf.put("  " ~ jStr("ip") ~ ": " ~ jStr(ipStr) ~ ",\n");
    buf.put("  " ~ jStr("found") ~ ": " ~ (matches.length ? "true" : "false") ~ ",\n");
    buf.put("  " ~ jStr("verdict") ~ ": " ~ jStr(verdict) ~ ",\n");
    buf.put("  " ~ jStr("score") ~ ": " ~ jNum(score) ~ ",\n");
    buf.put("  " ~ jStr("detections") ~ ": " ~ format("%d", matches.length) ~ ",\n");
    buf.put("  " ~ jStr("sources") ~ ": " ~ format("%d", seenSrc.length) ~ ",\n");
    buf.put("  " ~ jStr("top_provider") ~ ": " ~ jStr(topProv) ~ ",\n");
    buf.put("  " ~ jStr("providers") ~ ": " ~ jArrStr(providers, "  ") ~ ",\n");
    buf.put("  " ~ jStr("flags") ~ ": " ~ jArrStr(allFlags, "  ") ~ ",\n");
    buf.put("  " ~ jStr("reasons") ~ ": " ~ jArrStr(reasons, "  ") ~ ",\n");
    buf.put("  " ~ jStr("matches") ~ ": " ~ buildMatches(matches, "  ") ~ "\n");
    buf.put("}");
    return buf.data;
}

void main(string[] args) {
    auto db = load("../intel.bin");
    auto ip = args.length > 1 ? args[1] : "8.8.8.8";
    writeln(lookup(db, ip));
}

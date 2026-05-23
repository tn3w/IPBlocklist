#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <numeric>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using u128 = __uint128_t;
using json = nlohmann::ordered_json;

static const char* FLAGS[20] = {
    "vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
    "compromised","datacenter","cdn","anycast","crawler","bot","cloud",
    "private_relay","anonymizer","mobile","isp","government"};
static const double SEV[20] = {30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0};
static const struct { double t; const char* n; } LEVELS[4] =
    {{80,"critical"},{60,"high"},{35,"medium"},{15,"low"}};

template<typename T> static T rd(const char* p) { T v; std::memcpy(&v, p, sizeof(T)); return v; }

struct DB {
    std::vector<u32> v4s, v4e, v4m;
    std::vector<u16> v4v;
    std::vector<u128> v6s, v6e, v6m;
    std::vector<u16> v6v;
    std::vector<std::array<u32,4>> vt;
    std::vector<std::string> st;
    double W[20];
};

static DB load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::string d((std::istreambuf_iterator<char>(f)), {});
    const char* p = d.data();
    if (rd<u32>(p) != 6) { std::fprintf(stderr, "bad version\n"); std::exit(1); }
    u64 o[19];
    for (int i = 0; i < 19; i++) o[i] = rd<u64>(p + 8 + i*8);
    size_t cn=o[0], ln=o[1], v6n=o[2], valn=o[3], strn=o[4];
    const u64* off = o + 5;

    std::vector<u32> bi(65537);
    for (int i = 0; i < 65537; i++) bi[i] = rd<u32>(p + off[0] + i*4);

    size_t N = cn + ln;
    std::vector<u32> s(N), e(N);
    std::vector<u16> v(N);
    for (u32 b = 0, j = 0; b < 65536; b++) {
        for (; j < bi[b+1]; j++) {
            u32 lo = rd<u16>(p + off[1] + j*2);
            s[j] = (b << 16) | lo;
            e[j] = s[j] + rd<u16>(p + off[2] + j*2);
            v[j] = rd<u16>(p + off[3] + j*2);
        }
    }
    for (size_t i = 0; i < ln; i++) {
        s[cn+i] = rd<u32>(p + off[4] + i*4);
        e[cn+i] = rd<u32>(p + off[5] + i*4);
        v[cn+i] = rd<u16>(p + off[6] + i*2);
    }
    std::vector<size_t> idx(N);
    std::iota(idx.begin(), idx.end(), 0);
    std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b){ return s[a] < s[b]; });

    DB db;
    db.v4s.resize(N); db.v4e.resize(N); db.v4v.resize(N); db.v4m.resize(N);
    for (size_t i = 0; i < N; i++) {
        db.v4s[i] = s[idx[i]]; db.v4e[i] = e[idx[i]]; db.v4v[i] = v[idx[i]];
    }
    u32 mx = 0;
    for (size_t i = 0; i < N; i++) { if (db.v4e[i] > mx) mx = db.v4e[i]; db.v4m[i] = mx; }

    auto r6 = [&](u64 oo) {
        std::vector<u128> r(v6n);
        for (size_t i = 0; i < v6n; i++) {
            u64 lo = rd<u64>(p + oo + i*16);
            u64 hi = rd<u64>(p + oo + i*16 + 8);
            r[i] = ((u128)hi << 64) | lo;
        }
        return r;
    };
    db.v6s = r6(off[7]); db.v6e = r6(off[8]);
    db.v6v.resize(v6n);
    for (size_t i = 0; i < v6n; i++) db.v6v[i] = rd<u16>(p + off[9] + i*2);
    db.v6m.resize(v6n);
    u128 m6 = 0;
    for (size_t i = 0; i < v6n; i++) { if (db.v6e[i] > m6) m6 = db.v6e[i]; db.v6m[i] = m6; }

    db.vt.resize(valn);
    for (size_t i = 0; i < valn; i++)
        for (int j = 0; j < 4; j++)
            db.vt[i][j] = rd<u32>(p + off[10] + (i*4+j)*4);

    u64 sd = off[12];
    db.st.resize(strn);
    for (size_t i = 0; i < strn; i++) {
        u32 so = rd<u32>(p + off[11] + i*8);
        u32 sl = rd<u32>(p + off[11] + i*8 + 4);
        db.st[i].assign(p + sd + so, sl);
    }

    if (N > 0) {
        int c[20] = {0};
        for (auto vid : db.v4v) {
            u32 b = db.vt[vid][0];
            for (int i = 0; i < 20; i++) if (b & (1u<<i)) c[i]++;
        }
        for (int i = 0; i < 20; i++) {
            int cc = c[i] ? c[i] : 1;
            db.W[i] = SEV[i] * (1 + std::log2((double)N / cc) / 24);
        }
    } else {
        for (int i = 0; i < 20; i++) db.W[i] = SEV[i];
    }
    return db;
}

static double r1(double x) { return std::round(x * 10) / 10; }

static std::string ipFmt4(u32 ip) {
    u32 n = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &n, buf, sizeof(buf));
    return buf;
}

static std::string ipFmt6(u128 ip) {
    unsigned char b[16];
    for (int i = 0; i < 16; i++) b[15-i] = (unsigned char)(ip >> (i*8));
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, b, buf, sizeof(buf));
    return buf;
}

struct Match {
    std::string source, provider, range;
    std::vector<std::string> flags;
    double weight;
};

int main(int argc, char** argv) {
    std::string ip_str = argc > 1 ? argv[1] : "8.8.8.8";
    DB db = load("../intel.bin");

    std::vector<Match> matches;
    bool isV4 = ip_str.find(':') == std::string::npos;

    auto push = [&](u16 vid, const std::string& rng) {
        u32 b = db.vt[vid][0];
        Match m;
        double mxw = 0;
        for (int i = 0; i < 20; i++) {
            if (b & (1u<<i)) {
                m.flags.push_back(FLAGS[i]);
                if (db.W[i] > mxw) mxw = db.W[i];
            }
        }
        m.source = db.st[db.vt[vid][2]];
        m.provider = db.st[db.vt[vid][1]];
        m.range = rng;
        m.weight = r1(mxw);
        matches.push_back(std::move(m));
    };

    if (isV4) {
        in_addr a;
        inet_pton(AF_INET, ip_str.c_str(), &a);
        u32 ip = ntohl(a.s_addr);
        auto it = std::upper_bound(db.v4s.begin(), db.v4s.end(), ip);
        size_t i = it - db.v4s.begin();
        while (i > 0) {
            size_t j = --i;
            if (db.v4m[j] < ip) break;
            if (db.v4e[j] >= ip) push(db.v4v[j], ipFmt4(db.v4s[j]) + "-" + ipFmt4(db.v4e[j]));
        }
    } else {
        in6_addr a6;
        inet_pton(AF_INET6, ip_str.c_str(), &a6);
        u128 ip = 0;
        for (int i = 0; i < 16; i++) ip = (ip << 8) | a6.s6_addr[i];
        auto it = std::upper_bound(db.v6s.begin(), db.v6s.end(), ip);
        size_t i = it - db.v6s.begin();
        while (i > 0) {
            size_t j = --i;
            if (db.v6m[j] < ip) break;
            if (db.v6e[j] >= ip) push(db.v6v[j], ipFmt6(db.v6s[j]) + "-" + ipFmt6(db.v6e[j]));
        }
    }

    std::stable_sort(matches.begin(), matches.end(),
                     [](const Match& a, const Match& b){ return a.weight > b.weight; });

    auto fIdx = [&](const std::string& f) {
        for (int i = 0; i < 20; i++) if (f == FLAGS[i]) return i;
        return -1;
    };

    std::vector<std::string> all_flags, providers;
    std::set<std::string> seen_f, seen_p, rankedSet;
    std::set<std::string> sources;
    for (auto& m : matches) {
        for (auto& f : m.flags) {
            if (!seen_f.count(f)) { seen_f.insert(f); all_flags.push_back(f); }
            rankedSet.insert(f);
        }
        if (!m.provider.empty() && !seen_p.count(m.provider)) {
            seen_p.insert(m.provider);
            providers.push_back(m.provider);
        }
        sources.insert(m.provider + "|" + m.source);
    }
    std::vector<std::string> ranked(rankedSet.begin(), rankedSet.end());
    std::stable_sort(ranked.begin(), ranked.end(),
                     [&](const std::string& a, const std::string& b){
                         return db.W[fIdx(a)] > db.W[fIdx(b)];
                     });

    double score = 0;
    if (!ranked.empty()) {
        double top = db.W[fIdx(ranked[0])], ex = 0;
        for (size_t i = 1; i < ranked.size(); i++) ex += db.W[fIdx(ranked[i])];
        score = r1(std::min(100.0,
                  (top + ex * 0.15) * (1 + 0.08 * std::log2(sources.size() + 1))));
    }

    std::string verdict = "clean";
    if (!matches.empty()) {
        verdict = "minimal";
        for (auto& lv : LEVELS) if (score >= lv.t) { verdict = lv.n; break; }
    }

    for (size_t i = 0; i < providers.size(); i++) {
        std::string lo = providers[i];
        std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
        if (lo == "tor") {
            providers.erase(providers.begin() + i);
            providers.insert(providers.begin(), "Tor");
            break;
        }
    }

    std::vector<std::string> reasons(ranked.begin(),
        ranked.begin() + std::min<size_t>(5, ranked.size()));

    json out;
    out["ip"] = ip_str;
    out["found"] = !matches.empty();
    out["verdict"] = verdict;
    out["score"] = score;
    out["detections"] = matches.size();
    out["sources"] = sources.size();
    out["top_provider"] = providers.empty() ? "" : providers[0];
    out["providers"] = providers;
    out["flags"] = all_flags;
    out["reasons"] = reasons;
    out["matches"] = json::array();
    for (auto& m : matches) {
        out["matches"].push_back({
            {"source", m.source}, {"provider", m.provider}, {"range", m.range},
            {"flags", m.flags}, {"weight", m.weight}
        });
    }
    std::cout << out.dump(2) << "\n";
    return 0;
}

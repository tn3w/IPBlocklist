#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/stat.h>

typedef unsigned __int128 u128;

static const char *FLAGS[20] = {
    "vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
    "compromised","datacenter","cdn","anycast","crawler","bot","cloud",
    "private_relay","anonymizer","mobile","isp","government"};
static const double SEV[20] = {30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0};
static const struct { double t; const char *n; } LEVELS[4] =
    {{80,"critical"},{60,"high"},{35,"medium"},{15,"low"}};

static uint8_t *D;
static uint32_t *V4s, *V4e, *V4m;
static u128 *V6s, *V6e, *V6m;
static uint16_t *V4v, *V6v;
static uint32_t (*VT)[4];
static char **STR;
static double W[20];
static size_t N4, N6, NSTR;

static uint32_t rd_u32(size_t o) { uint32_t x; memcpy(&x, D+o, 4); return x; }
static uint64_t rd_u64(size_t o) { uint64_t x; memcpy(&x, D+o, 8); return x; }
static uint16_t rd_u16(size_t o) { uint16_t x; memcpy(&x, D+o, 2); return x; }

typedef struct { uint32_t s, e; uint16_t v; } V4Rec;
static int cmp_v4(const void *a, const void *b) {
    uint32_t x = ((V4Rec*)a)->s, y = ((V4Rec*)b)->s;
    return x < y ? -1 : x > y ? 1 : 0;
}

static void load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    struct stat st; fstat(fileno(f), &st);
    D = malloc(st.st_size);
    fread(D, 1, st.st_size, f);
    fclose(f);
    if (rd_u32(0) != 6) { fprintf(stderr, "bad version\n"); exit(1); }
    uint64_t H[19];
    for (int i = 0; i < 19; i++) H[i] = rd_u64(8 + i*8);
    size_t cn = H[0], ln = H[1], v6n = H[2], valn = H[3], strn = H[4];
    size_t o_bucket = H[5], o_starts = H[6], o_lens = H[7], o_vals = H[8];
    size_t o_lstarts = H[9], o_lends = H[10], o_lvals = H[11];
    size_t o_v6s = H[12], o_v6e = H[13], o_v6v = H[14];
    size_t o_vt = H[15], o_si = H[16], o_sd = H[17];

    N4 = cn + ln;
    V4Rec *recs = malloc(N4 * sizeof(V4Rec));
    uint32_t prev = rd_u32(o_bucket);
    for (size_t b = 0; b < 65536; b++) {
        uint32_t next = rd_u32(o_bucket + (b+1)*4);
        for (uint32_t j = prev; j < next; j++) {
            uint32_t lo = rd_u16(o_starts + j*2);
            recs[j].s = ((uint32_t)b << 16) | lo;
            recs[j].e = recs[j].s + rd_u16(o_lens + j*2);
            recs[j].v = rd_u16(o_vals + j*2);
        }
        prev = next;
    }
    for (size_t i = 0; i < ln; i++) {
        recs[cn+i].s = rd_u32(o_lstarts + i*4);
        recs[cn+i].e = rd_u32(o_lends + i*4);
        recs[cn+i].v = rd_u16(o_lvals + i*2);
    }
    qsort(recs, N4, sizeof(V4Rec), cmp_v4);
    V4s = malloc(N4*4); V4e = malloc(N4*4); V4v = malloc(N4*2); V4m = malloc(N4*4);
    uint32_t mx = 0;
    for (size_t i = 0; i < N4; i++) {
        V4s[i] = recs[i].s; V4e[i] = recs[i].e; V4v[i] = recs[i].v;
        if (V4e[i] > mx) mx = V4e[i];
        V4m[i] = mx;
    }
    free(recs);

    N6 = v6n;
    V6s = malloc(N6*sizeof(u128)); V6e = malloc(N6*sizeof(u128));
    V6m = malloc(N6*sizeof(u128)); V6v = malloc(N6*2);
    u128 mx6 = 0;
    for (size_t i = 0; i < N6; i++) {
        uint64_t lo = rd_u64(o_v6s + i*16), hi = rd_u64(o_v6s + i*16 + 8);
        V6s[i] = ((u128)hi << 64) | lo;
        lo = rd_u64(o_v6e + i*16); hi = rd_u64(o_v6e + i*16 + 8);
        V6e[i] = ((u128)hi << 64) | lo;
        V6v[i] = rd_u16(o_v6v + i*2);
        if (V6e[i] > mx6) mx6 = V6e[i];
        V6m[i] = mx6;
    }

    VT = malloc(valn * 16);
    for (size_t i = 0; i < valn; i++)
        for (int j = 0; j < 4; j++)
            VT[i][j] = rd_u32(o_vt + (i*4 + j)*4);

    NSTR = strn;
    STR = malloc(strn * sizeof(char*));
    for (size_t i = 0; i < strn; i++) {
        uint32_t so = rd_u32(o_si + i*8), sl = rd_u32(o_si + i*8 + 4);
        STR[i] = malloc(sl + 1);
        memcpy(STR[i], D + o_sd + so, sl);
        STR[i][sl] = 0;
    }

    if (N4 > 0) {
        size_t c[20] = {0};
        for (size_t i = 0; i < N4; i++) {
            uint32_t b = VT[V4v[i]][0];
            for (int k = 0; k < 20; k++) if (b & (1u << k)) c[k]++;
        }
        for (int k = 0; k < 20; k++) {
            size_t cc = c[k] ? c[k] : 1;
            W[k] = SEV[k] * (1 + log2((double)N4 / cc) / 24);
        }
    } else {
        memcpy(W, SEV, sizeof(SEV));
    }
}

static double r1(double x) { return round(x * 10) / 10; }

typedef struct {
    const char *source, *provider;
    char range[80];
    int flags[20], nflags;
    double weight;
} Match;

static void fmt_v4(uint32_t ip, char *out) {
    struct in_addr a; a.s_addr = htonl(ip);
    inet_ntop(AF_INET, &a, out, INET_ADDRSTRLEN);
}

static void fmt_v6(u128 ip, char *out) {
    uint8_t b[16];
    for (int i = 0; i < 16; i++) b[15-i] = (uint8_t)(ip >> (i*8));
    inet_ntop(AF_INET6, b, out, INET6_ADDRSTRLEN);
}

static void json_str(const char *s, char **buf, size_t *cap, size_t *len) {
    if (*len + strlen(s)*6 + 4 > *cap) {
        *cap = (*len + strlen(s)*6 + 4) * 2;
        *buf = realloc(*buf, *cap);
    }
    char *p = *buf + *len;
    *p++ = '"';
    for (const unsigned char *c = (const unsigned char*)s; *c; c++) {
        if (*c == '"') { *p++ = '\\'; *p++ = '"'; }
        else if (*c == '\\') { *p++ = '\\'; *p++ = '\\'; }
        else if (*c < 0x20) { p += sprintf(p, "\\u%04x", *c); }
        else *p++ = *c;
    }
    *p++ = '"';
    *len = p - *buf;
}

static void out_append(char **buf, size_t *cap, size_t *len, const char *s) {
    size_t n = strlen(s);
    if (*len + n + 1 > *cap) { *cap = (*len + n + 1) * 2; *buf = realloc(*buf, *cap); }
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = 0;
}

static int cmp_match_w(const void *a, const void *b) {
    double wa = ((Match*)a)->weight, wb = ((Match*)b)->weight;
    return wa < wb ? 1 : wa > wb ? -1 : 0;
}

static void push_match(Match *m, uint16_t vid, const char *range) {
    uint32_t bits = VT[vid][0];
    m->source = STR[VT[vid][2]];
    m->provider = STR[VT[vid][1]];
    strcpy(m->range, range);
    m->nflags = 0;
    double mxw = 0;
    for (int i = 0; i < 20; i++) {
        if (bits & (1u << i)) {
            m->flags[m->nflags++] = i;
            if (W[i] > mxw) mxw = W[i];
        }
    }
    m->weight = r1(mxw);
}

static void lookup(const char *ipstr) {
    struct in_addr a4; struct in6_addr a6;
    int is4 = inet_pton(AF_INET, ipstr, &a4) == 1;
    int is6 = !is4 && inet_pton(AF_INET6, ipstr, &a6) == 1;
    if (!is4 && !is6) { fprintf(stderr, "bad ip\n"); exit(1); }

    Match *matches = malloc(sizeof(Match) * 256);
    size_t nm = 0, mcap = 256;

    if (is4) {
        uint32_t ip = ntohl(a4.s_addr);
        size_t lo = 0, hi = N4;
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (V4s[mid] > ip) hi = mid; else lo = mid + 1;
        }
        while (lo > 0) {
            lo--;
            if (V4m[lo] < ip) break;
            if (V4e[lo] >= ip) {
                char sb[20], eb[20], r[64];
                fmt_v4(V4s[lo], sb); fmt_v4(V4e[lo], eb);
                snprintf(r, sizeof(r), "%s-%s", sb, eb);
                if (nm == mcap) { mcap *= 2; matches = realloc(matches, mcap * sizeof(Match)); }
                push_match(&matches[nm++], V4v[lo], r);
            }
        }
    } else {
        u128 ip = 0;
        for (int i = 0; i < 16; i++) ip = (ip << 8) | a6.s6_addr[i];
        size_t lo = 0, hi = N6;
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (V6s[mid] > ip) hi = mid; else lo = mid + 1;
        }
        while (lo > 0) {
            lo--;
            if (V6m[lo] < ip) break;
            if (V6e[lo] >= ip) {
                char sb[INET6_ADDRSTRLEN], eb[INET6_ADDRSTRLEN], r[2*INET6_ADDRSTRLEN+2];
                fmt_v6(V6s[lo], sb); fmt_v6(V6e[lo], eb);
                snprintf(r, sizeof(r), "%s-%s", sb, eb);
                if (nm == mcap) { mcap *= 2; matches = realloc(matches, mcap * sizeof(Match)); }
                push_match(&matches[nm++], V6v[lo], r);
            }
        }
    }

    qsort(matches, nm, sizeof(Match), cmp_match_w);

    int seen[20] = {0}, ranked[20], nranked = 0;
    for (size_t i = 0; i < nm; i++)
        for (int j = 0; j < matches[i].nflags; j++)
            if (!seen[matches[i].flags[j]]) {
                seen[matches[i].flags[j]] = 1;
                ranked[nranked++] = matches[i].flags[j];
            }
    for (int i = 0; i < nranked; i++)
        for (int j = i+1; j < nranked; j++)
            if (W[ranked[j]] > W[ranked[i]]) {
                int t = ranked[i]; ranked[i] = ranked[j]; ranked[j] = t;
            }

    char **srckeys = malloc(nm * sizeof(char*));
    size_t nsrc = 0;
    for (size_t i = 0; i < nm; i++) {
        char key[1024];
        snprintf(key, sizeof(key), "%s|%s", matches[i].provider, matches[i].source);
        int found = 0;
        for (size_t k = 0; k < nsrc; k++) if (!strcmp(srckeys[k], key)) { found = 1; break; }
        if (!found) { srckeys[nsrc] = strdup(key); nsrc++; }
    }

    double score = 0;
    if (nranked > 0) {
        double top = W[ranked[0]], ex = 0;
        for (int i = 1; i < nranked; i++) ex += W[ranked[i]];
        double s = (top + ex * 0.15) * (1 + 0.08 * log2((double)nsrc + 1));
        score = r1(s > 100 ? 100 : s);
    }

    const char *verdict = "clean";
    if (nm > 0) {
        verdict = "minimal";
        for (int i = 0; i < 4; i++) if (score >= LEVELS[i].t) { verdict = LEVELS[i].n; break; }
    }

    const char *all_flags[20]; int nall = 0; int sf[20] = {0};
    const char **provs = malloc(nm * sizeof(char*) + 8); size_t nprov = 0;
    for (size_t i = 0; i < nm; i++) {
        for (int j = 0; j < matches[i].nflags; j++)
            if (!sf[matches[i].flags[j]]) { sf[matches[i].flags[j]] = 1; all_flags[nall++] = FLAGS[matches[i].flags[j]]; }
        if (matches[i].provider[0]) {
            int found = 0;
            for (size_t k = 0; k < nprov; k++) if (!strcmp(provs[k], matches[i].provider)) { found = 1; break; }
            if (!found) provs[nprov++] = matches[i].provider;
        }
    }
    int has_tor = 0;
    for (size_t i = 0; i < nprov; i++) {
        const char *p = provs[i];
        if (strlen(p) == 3 && (p[0]|32)=='t' && (p[1]|32)=='o' && (p[2]|32)=='r') { has_tor = 1; break; }
    }
    const char **provs2 = malloc((nprov + 1) * sizeof(char*));
    size_t np2 = 0;
    if (has_tor) {
        provs2[np2++] = "Tor";
        for (size_t i = 0; i < nprov; i++) {
            const char *p = provs[i];
            if (!(strlen(p) == 3 && (p[0]|32)=='t' && (p[1]|32)=='o' && (p[2]|32)=='r'))
                provs2[np2++] = p;
        }
    } else {
        for (size_t i = 0; i < nprov; i++) provs2[np2++] = provs[i];
    }

    char *buf = malloc(4096); size_t cap = 4096, len = 0; buf[0] = 0;
    char tmp[256];
    out_append(&buf, &cap, &len, "{\n  \"ip\": ");
    json_str(ipstr, &buf, &cap, &len);
    out_append(&buf, &cap, &len, ",\n  \"found\": ");
    out_append(&buf, &cap, &len, nm > 0 ? "true" : "false");
    out_append(&buf, &cap, &len, ",\n  \"verdict\": ");
    json_str(verdict, &buf, &cap, &len);
    snprintf(tmp, sizeof(tmp), ",\n  \"score\": %g", score);
    out_append(&buf, &cap, &len, tmp);
    snprintf(tmp, sizeof(tmp), ",\n  \"detections\": %zu,\n  \"sources\": %zu,\n  \"top_provider\": ", nm, nsrc);
    out_append(&buf, &cap, &len, tmp);
    json_str(np2 > 0 ? provs2[0] : "", &buf, &cap, &len);
    out_append(&buf, &cap, &len, ",\n  \"providers\": [");
    for (size_t i = 0; i < np2; i++) {
        if (i) out_append(&buf, &cap, &len, ",");
        out_append(&buf, &cap, &len, "\n    ");
        json_str(provs2[i], &buf, &cap, &len);
    }
    out_append(&buf, &cap, &len, np2 ? "\n  ]" : "]");
    out_append(&buf, &cap, &len, ",\n  \"flags\": [");
    for (int i = 0; i < nall; i++) {
        if (i) out_append(&buf, &cap, &len, ",");
        out_append(&buf, &cap, &len, "\n    ");
        json_str(all_flags[i], &buf, &cap, &len);
    }
    out_append(&buf, &cap, &len, nall ? "\n  ]" : "]");
    int nreasons = nranked > 5 ? 5 : nranked;
    out_append(&buf, &cap, &len, ",\n  \"reasons\": [");
    for (int i = 0; i < nreasons; i++) {
        if (i) out_append(&buf, &cap, &len, ",");
        out_append(&buf, &cap, &len, "\n    ");
        json_str(FLAGS[ranked[i]], &buf, &cap, &len);
    }
    out_append(&buf, &cap, &len, nreasons ? "\n  ]" : "]");
    out_append(&buf, &cap, &len, ",\n  \"matches\": [");
    for (size_t i = 0; i < nm; i++) {
        out_append(&buf, &cap, &len, i ? ",\n    {\n      \"source\": " : "\n    {\n      \"source\": ");
        json_str(matches[i].source, &buf, &cap, &len);
        out_append(&buf, &cap, &len, ",\n      \"provider\": ");
        json_str(matches[i].provider, &buf, &cap, &len);
        out_append(&buf, &cap, &len, ",\n      \"range\": ");
        json_str(matches[i].range, &buf, &cap, &len);
        out_append(&buf, &cap, &len, ",\n      \"flags\": [");
        for (int j = 0; j < matches[i].nflags; j++) {
            if (j) out_append(&buf, &cap, &len, ",");
            out_append(&buf, &cap, &len, "\n        ");
            json_str(FLAGS[matches[i].flags[j]], &buf, &cap, &len);
        }
        out_append(&buf, &cap, &len, matches[i].nflags ? "\n      ]" : "]");
        snprintf(tmp, sizeof(tmp), ",\n      \"weight\": %g\n    }", matches[i].weight);
        out_append(&buf, &cap, &len, tmp);
    }
    out_append(&buf, &cap, &len, nm ? "\n  ]\n}" : "]\n}");
    puts(buf);
    free(buf);
}

int main(int argc, char **argv) {
    load("../intel.bin");
    lookup(argc > 1 ? argv[1] : "8.8.8.8");
    return 0;
}

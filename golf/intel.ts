import * as fs from "node:fs";
import * as process from "node:process";

const F = "vpn proxy tor malware c2 scanner brute_force spammer compromised datacenter cdn anycast crawler bot cloud private_relay anonymizer mobile isp government".split(" ");
const S = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0];
const L: [number, string][] = [[80,"critical"],[60,"high"],[35,"medium"],[15,"low"]];

interface DB {
  v4s: Uint32Array; v4e: Uint32Array; v4m: Uint32Array; v4v: Uint16Array;
  v6s: bigint[]; v6e: bigint[]; v6m: bigint[]; v6v: Uint16Array;
  vt: Uint32Array; st: string[]; w: Record<string, number>;
}

export function load(path: string): DB {
  const d = fs.readFileSync(path);
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  if (dv.getUint32(0, true) !== 6) throw "ver";
  const o: number[] = [];
  for (let i = 0; i < 19; i++) o.push(Number(dv.getBigUint64(8 + i*8, true)));
  const [cn, ln, v6n, valn, strn, ...off] = o;
  const all = cn + ln;
  const bi = new Uint32Array(d.buffer, d.byteOffset + off[0], 65537);
  const ss = new Uint32Array(all);
  const se = new Uint32Array(all);
  const sv = new Uint16Array(all);
  for (let b = 0; b < 65536; b++) {
    for (let j = bi[b]; j < bi[b+1]; j++) {
      const lo = dv.getUint16(off[1] + j*2, true);
      const l2 = dv.getUint16(off[2] + j*2, true);
      ss[j] = ((b << 16) >>> 0) | lo;
      se[j] = (ss[j] + l2) >>> 0;
      sv[j] = dv.getUint16(off[3] + j*2, true);
    }
  }
  for (let i = 0; i < ln; i++) {
    ss[cn+i] = dv.getUint32(off[4] + i*4, true);
    se[cn+i] = dv.getUint32(off[5] + i*4, true);
    sv[cn+i] = dv.getUint16(off[6] + i*2, true);
  }
  const idx = new Int32Array(all);
  for (let i = 0; i < all; i++) idx[i] = i;
  const idxArr = Array.from(idx);
  idxArr.sort((a, b) => ss[a] - ss[b]);
  const v4s = new Uint32Array(all);
  const v4e = new Uint32Array(all);
  const v4v = new Uint16Array(all);
  for (let i = 0; i < all; i++) { const k = idxArr[i]; v4s[i] = ss[k]; v4e[i] = se[k]; v4v[i] = sv[k]; }
  const v4m = new Uint32Array(all);
  let mx = 0;
  for (let i = 0; i < all; i++) { if (v4e[i] > mx) mx = v4e[i]; v4m[i] = mx; }

  const v6s: bigint[] = [], v6e: bigint[] = [];
  for (let i = 0; i < v6n; i++) {
    const lo = dv.getBigUint64(off[7] + i*16, true);
    const hi = dv.getBigUint64(off[7] + i*16 + 8, true);
    v6s.push((hi << 64n) | lo);
    const lo2 = dv.getBigUint64(off[8] + i*16, true);
    const hi2 = dv.getBigUint64(off[8] + i*16 + 8, true);
    v6e.push((hi2 << 64n) | lo2);
  }
  const v6v = new Uint16Array(v6n);
  for (let i = 0; i < v6n; i++) v6v[i] = dv.getUint16(off[9] + i*2, true);
  const v6m: bigint[] = []; let mm = 0n;
  for (let i = 0; i < v6n; i++) { if (v6e[i] > mm) mm = v6e[i]; v6m.push(mm); }

  const vt = new Uint32Array(valn * 4);
  for (let i = 0; i < valn*4; i++) vt[i] = dv.getUint32(off[10] + i*4, true);
  const sd = off[12];
  const st: string[] = [];
  for (let i = 0; i < strn; i++) {
    const so = dv.getUint32(off[11] + i*8, true);
    const sl = dv.getUint32(off[11] + i*8 + 4, true);
    st.push(d.slice(sd+so, sd+so+sl).toString("utf8"));
  }
  const w: Record<string, number> = {};
  if (all > 0) {
    const cnt = new Array(20).fill(0);
    for (let k = 0; k < all; k++) {
      const b = vt[v4v[k] * 4];
      for (let i = 0; i < 20; i++) if (b & (1 << i)) cnt[i]++;
    }
    for (let i = 0; i < 20; i++) {
      const c = cnt[i] || 1;
      w[F[i]] = S[i] * (1 + Math.log2(all / c) / 24);
    }
  } else {
    for (let i = 0; i < 20; i++) w[F[i]] = S[i];
  }
  return { v4s, v4e, v4m, v4v, v6s, v6e, v6m, v6v, vt, st, w };
}

function upperU32(a: Uint32Array, ip: number): number {
  let lo = 0, hi = a.length;
  while (lo < hi) { const m = (lo + hi) >>> 1; if (a[m] > ip) hi = m; else lo = m + 1; }
  return lo;
}
function upperBig(a: bigint[], ip: bigint): number {
  let lo = 0, hi = a.length;
  while (lo < hi) { const m = (lo + hi) >>> 1; if (a[m] > ip) hi = m; else lo = m + 1; }
  return lo;
}

function fmt4(x: number): string {
  return `${(x>>>24)&0xff}.${(x>>>16)&0xff}.${(x>>>8)&0xff}.${x&0xff}`;
}
function fmt6(x: bigint): string {
  const parts: string[] = [];
  for (let i = 7; i >= 0; i--) parts.push(Number((x >> BigInt(i*16)) & 0xffffn).toString(16));
  let best = -1, bestLen = 0, cur = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (parts[i] === "0") { if (cur === -1) cur = i; curLen++; if (curLen > bestLen) { best = cur; bestLen = curLen; } }
    else { cur = -1; curLen = 0; }
  }
  if (bestLen < 2) return parts.join(":");
  const left = parts.slice(0, best).join(":");
  const right = parts.slice(best + bestLen).join(":");
  return left + "::" + right;
}

function parseIp(s: string): { v4: boolean; ip4?: number; ip6?: bigint } {
  if (s.includes(":")) {
    let parts = s.split("::");
    let head: string[] = [], tail: string[] = [];
    if (parts.length === 2) {
      head = parts[0] ? parts[0].split(":") : [];
      tail = parts[1] ? parts[1].split(":") : [];
    } else head = parts[0].split(":");
    const fill = 8 - head.length - tail.length;
    const all = [...head, ...new Array(fill).fill("0"), ...tail];
    let ip = 0n;
    for (const p of all) ip = (ip << 16n) | BigInt(parseInt(p || "0", 16));
    return { v4: false, ip6: ip };
  }
  const p = s.split(".").map(Number);
  return { v4: true, ip4: ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]) >>> 0 };
}

function r1(x: number): number { return Math.round(x * 10) / 10; }

export function lookup(db: DB, ipStr: string): any {
  const a = parseIp(ipStr);
  type M = { source: string; provider: string; range: string; flags: string[]; weight: number };
  const matches: M[] = [];
  const push = (vid: number, rng: string) => {
    const b = db.vt[vid * 4];
    const fl: string[] = [];
    let mxw = 0;
    for (let i = 0; i < 20; i++) {
      if (b & (1 << i)) { fl.push(F[i]); const v = db.w[F[i]]; if (v > mxw) mxw = v; }
    }
    matches.push({
      source: db.st[db.vt[vid*4+2]], provider: db.st[db.vt[vid*4+1]],
      range: rng, flags: fl, weight: r1(mxw),
    });
  };
  if (a.v4) {
    const ip = a.ip4!;
    if (db.v4s.length) {
      let i = upperU32(db.v4s, ip);
      while (i > 0) {
        i--;
        if (db.v4m[i] < ip) break;
        if (db.v4e[i] >= ip) push(db.v4v[i], fmt4(db.v4s[i]) + "-" + fmt4(db.v4e[i]));
      }
    }
  } else {
    const ip = a.ip6!;
    if (db.v6s.length) {
      let i = upperBig(db.v6s, ip);
      while (i > 0) {
        i--;
        if (db.v6m[i] < ip) break;
        if (db.v6e[i] >= ip) push(db.v6v[i], fmt6(db.v6s[i]) + "-" + fmt6(db.v6e[i]));
      }
    }
  }
  matches.sort((x, y) => y.weight - x.weight);

  const flagset = new Set<string>();
  for (const m of matches) for (const f of m.flags) flagset.add(f);
  const ranked = Array.from(flagset).sort((x, y) => db.w[y] - db.w[x]);
  const src = new Set<string>();
  for (const m of matches) src.add(m.provider + "|" + m.source);
  let score = 0;
  if (ranked.length) {
    const top = db.w[ranked[0]];
    const extras = ranked.slice(1).reduce((s, f) => s + db.w[f], 0);
    score = r1(Math.min(100, (top + extras * 0.15) * (1 + 0.08 * Math.log2(src.size + 1))));
  }
  let verdict = "clean";
  if (matches.length) {
    verdict = "minimal";
    for (const [t, n] of L) if (score >= t) { verdict = n; break; }
  }
  const allFlags: string[] = [];
  for (const m of matches) for (const f of m.flags) if (!allFlags.includes(f)) allFlags.push(f);
  let providers: string[] = [];
  for (const m of matches) if (m.provider && !providers.includes(m.provider)) providers.push(m.provider);
  const ti = providers.findIndex(p => p.toLowerCase() === "tor");
  if (ti >= 0) { providers.splice(ti, 1); providers.unshift("Tor"); }
  return {
    ip: ipStr, found: matches.length > 0, verdict, score,
    detections: matches.length, sources: src.size,
    top_provider: providers[0] || "", providers, flags: allFlags,
    reasons: ranked.slice(0, 5), matches,
  };
}

const ip = process.argv[2] || "8.8.8.8";
const db = load("../intel.bin");
console.log(JSON.stringify(lookup(db, ip), null, 2));

const fs = require("node:fs");

const F = "vpn proxy tor malware c2 scanner brute_force spammer compromised datacenter cdn anycast crawler bot cloud private_relay anonymizer mobile isp government".split(" ");
const S = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0];
const L = [[80,"critical"],[60,"high"],[35,"medium"],[15,"low"]];
const r1 = x => Math.round(x * 10) / 10;

function load(path) {
  const d = fs.readFileSync(path);
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  if (dv.getUint32(0, true) !== 6) throw "ver";
  const o = [];
  for (let i = 0; i < 19; i++) o.push(Number(dv.getBigUint64(8 + i*8, true)));
  const [cn, ln, v6n, valn, strn, ...off] = o;
  const all = cn + ln;
  const ss = new Uint32Array(all), se = new Uint32Array(all), sv = new Uint16Array(all);
  let bPrev = dv.getUint32(off[0], true);
  for (let b = 0; b < 65536; b++) {
    const bNext = dv.getUint32(off[0] + (b+1)*4, true);
    for (let j = bPrev; j < bNext; j++) {
      ss[j] = ((b << 16) >>> 0) | dv.getUint16(off[1] + j*2, true);
      se[j] = (ss[j] + dv.getUint16(off[2] + j*2, true)) >>> 0;
      sv[j] = dv.getUint16(off[3] + j*2, true);
    }
    bPrev = bNext;
  }
  for (let i = 0; i < ln; i++) {
    ss[cn+i] = dv.getUint32(off[4] + i*4, true);
    se[cn+i] = dv.getUint32(off[5] + i*4, true);
    sv[cn+i] = dv.getUint16(off[6] + i*2, true);
  }
  const idx = Array.from({length: all}, (_, i) => i);
  idx.sort((a, b) => ss[a] - ss[b]);
  const v4s = new Uint32Array(all), v4e = new Uint32Array(all), v4v = new Uint16Array(all);
  for (let i = 0; i < all; i++) { const k = idx[i]; v4s[i] = ss[k]; v4e[i] = se[k]; v4v[i] = sv[k]; }
  const v4m = new Uint32Array(all);
  let mx = 0;
  for (let i = 0; i < all; i++) { if (v4e[i] > mx) mx = v4e[i]; v4m[i] = mx; }

  const v6s = [], v6e = [];
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
  const v6m = []; let mm = 0n;
  for (let i = 0; i < v6n; i++) { if (v6e[i] > mm) mm = v6e[i]; v6m.push(mm); }

  const vt = new Uint32Array(valn * 4);
  for (let i = 0; i < valn*4; i++) vt[i] = dv.getUint32(off[10] + i*4, true);
  const sd = off[12], st = [];
  for (let i = 0; i < strn; i++) {
    const so = dv.getUint32(off[11] + i*8, true);
    const sl = dv.getUint32(off[11] + i*8 + 4, true);
    st.push(d.slice(sd+so, sd+so+sl).toString("utf8"));
  }
  const w = {};
  if (all > 0) {
    const cnt = new Array(20).fill(0);
    for (let k = 0; k < all; k++) {
      const b = vt[v4v[k] * 4];
      for (let i = 0; i < 20; i++) if (b & (1 << i)) cnt[i]++;
    }
    for (let i = 0; i < 20; i++) w[F[i]] = S[i] * (1 + Math.log2(all / (cnt[i] || 1)) / 24);
  } else {
    for (let i = 0; i < 20; i++) w[F[i]] = S[i];
  }
  return { v4s, v4e, v4m, v4v, v6s, v6e, v6m, v6v, vt, st, w };
}

function upper(a, ip) {
  let lo = 0, hi = a.length;
  while (lo < hi) { const m = (lo + hi) >>> 1; if (a[m] > ip) hi = m; else lo = m + 1; }
  return lo;
}

function fmt4(x) {
  return `${(x>>>24)&0xff}.${(x>>>16)&0xff}.${(x>>>8)&0xff}.${x&0xff}`;
}

function fmt6(x) {
  const parts = [];
  for (let i = 7; i >= 0; i--) parts.push(Number((x >> BigInt(i*16)) & 0xffffn).toString(16));
  let best = -1, bestLen = 0, cur = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (parts[i] === "0") {
      if (cur === -1) cur = i;
      curLen++;
      if (curLen > bestLen) { best = cur; bestLen = curLen; }
    } else { cur = -1; curLen = 0; }
  }
  if (bestLen < 2) return parts.join(":");
  return parts.slice(0, best).join(":") + "::" + parts.slice(best + bestLen).join(":");
}

function parseIp(s) {
  if (s.includes(":")) {
    const parts = s.split("::");
    let head = [], tail = [];
    if (parts.length === 2) {
      head = parts[0] ? parts[0].split(":") : [];
      tail = parts[1] ? parts[1].split(":") : [];
    } else head = parts[0].split(":");
    const fill = 8 - head.length - tail.length;
    const all = [...head, ...new Array(fill).fill("0"), ...tail];
    let ip = 0n;
    for (const p of all) ip = (ip << 16n) | BigInt(parseInt(p || "0", 16));
    return { v4: false, ip };
  }
  const p = s.split(".").map(Number);
  return { v4: true, ip: ((p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]) >>> 0 };
}

function lookup(db, ipStr) {
  const a = parseIp(ipStr);
  const matches = [];
  const push = (vid, rng) => {
    const b = db.vt[vid * 4];
    const fl = [];
    let mxw = 0;
    for (let i = 0; i < 20; i++) {
      if (b & (1 << i)) { fl.push(F[i]); const v = db.w[F[i]]; if (v > mxw) mxw = v; }
    }
    matches.push({
      source: db.st[db.vt[vid*4+2]], provider: db.st[db.vt[vid*4+1]],
      range: rng, flags: fl, weight: r1(mxw),
    });
  };
  const [s, e, m, v, fmt] = a.v4
    ? [db.v4s, db.v4e, db.v4m, db.v4v, fmt4]
    : [db.v6s, db.v6e, db.v6m, db.v6v, fmt6];
  if (s.length) {
    let i = upper(s, a.ip);
    while (i > 0) {
      i--;
      if (m[i] < a.ip) break;
      if (e[i] >= a.ip) push(v[i], fmt(s[i]) + "-" + fmt(e[i]));
    }
  }
  matches.sort((x, y) => y.weight - x.weight);

  const flagset = new Set();
  for (const mt of matches) for (const f of mt.flags) flagset.add(f);
  const ranked = Array.from(flagset).sort((x, y) => db.w[y] - db.w[x]);
  const src = new Set();
  for (const mt of matches) src.add(mt.provider + "|" + mt.source);
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
  const allFlags = [];
  for (const mt of matches) for (const f of mt.flags) if (!allFlags.includes(f)) allFlags.push(f);
  let providers = [];
  for (const mt of matches) if (mt.provider && !providers.includes(mt.provider)) providers.push(mt.provider);
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
console.log(JSON.stringify(lookup(load("../intel.bin"), ip), null, 2));

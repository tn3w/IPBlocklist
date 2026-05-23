import std/[algorithm, json, math, net, os, strformat, strutils, tables]

const FLAGS = ["vpn","proxy","tor","malware","c2","scanner","brute_force",
  "spammer","compromised","datacenter","cdn","anycast","crawler","bot","cloud",
  "private_relay","anonymizer","mobile","isp","government"]
const SEV = [30.0,25.0,45.0,95.0,95.0,55.0,70.0,65.0,75.0,15.0,5.0,0.0,10.0,
  40.0,10.0,15.0,35.0,0.0,0.0,0.0]
const LEVELS = [(80.0,"critical"),(60.0,"high"),(35.0,"medium"),(15.0,"low")]

type U128 = tuple[hi, lo: uint64]

proc `<`(a, b: U128): bool =
  if a.hi != b.hi: a.hi < b.hi else: a.lo < b.lo
proc `<=`(a, b: U128): bool = not (b < a)
proc `>=`(a, b: U128): bool = not (a < b)

proc rdU16(d: string, o: int): uint16 = cast[ptr uint16](unsafeAddr d[o])[]
proc rdU32(d: string, o: int): uint32 = cast[ptr uint32](unsafeAddr d[o])[]
proc rdU64(d: string, o: int): uint64 = cast[ptr uint64](unsafeAddr d[o])[]

type DB = object
  v4s, v4e, v4m: seq[uint32]
  v4v: seq[uint16]
  v6s, v6e, v6m: seq[U128]
  v6v: seq[uint16]
  vt: seq[array[4, uint32]]
  st: seq[string]
  w: array[20, float]

proc round1(x: float): float = round(x * 10.0) / 10.0

proc fmtV4(x: uint32): string =
  let a = [uint8((x shr 24) and 0xff), uint8((x shr 16) and 0xff),
           uint8((x shr 8) and 0xff), uint8(x and 0xff)]
  $IpAddress(family: IPv4, address_v4: a)

proc fmtV6(x: U128): string =
  var a: array[16, uint8]
  for i in 0 ..< 8:
    a[i] = uint8((x.hi shr (56 - i*8)) and 0xff)
    a[8+i] = uint8((x.lo shr (56 - i*8)) and 0xff)
  $IpAddress(family: IPv6, address_v6: a)

proc ipToU32(a: IpAddress): uint32 =
  for b in a.address_v4: result = (result shl 8) or uint32(b)

proc ipToU128(a: IpAddress): U128 =
  for i in 0 ..< 8:
    result.hi = (result.hi shl 8) or uint64(a.address_v6[i])
    result.lo = (result.lo shl 8) or uint64(a.address_v6[8+i])

proc load(path: string): DB =
  let d = readFile(path)
  if rdU32(d, 0) != 6: quit("unsupported version")
  var o: array[19, int]
  for i in 0 ..< 19: o[i] = int(rdU64(d, 8 + i*8))
  let cn = o[0]; let ln = o[1]; let v6n = o[2]; let valn = o[3]; let strn = o[4]
  let off = o[5 .. 18]
  var bi = newSeq[uint32](65537)
  for i in 0 .. 65536: bi[i] = rdU32(d, off[0] + i*4)
  let n = cn + ln
  var s = newSeq[uint32](n)
  var e = newSeq[uint32](n)
  var v = newSeq[uint16](n)
  for b in 0 ..< 65536:
    for j in bi[b] ..< bi[b+1]:
      let ji = int(j)
      let lo = uint32(rdU16(d, off[1] + ji*2))
      s[ji] = (uint32(b) shl 16) or lo
      e[ji] = s[ji] + uint32(rdU16(d, off[2] + ji*2))
      v[ji] = rdU16(d, off[3] + ji*2)
  for i in 0 ..< ln:
    s[cn+i] = rdU32(d, off[4] + i*4)
    e[cn+i] = rdU32(d, off[5] + i*4)
    v[cn+i] = rdU16(d, off[6] + i*2)
  var idx = newSeq[int](n)
  for i in 0 ..< n: idx[i] = i
  idx.sort(proc(a, b: int): int = cmp(s[a], s[b]))
  result.v4s = newSeq[uint32](n)
  result.v4e = newSeq[uint32](n)
  result.v4v = newSeq[uint16](n)
  for i in 0 ..< n:
    result.v4s[i] = s[idx[i]]
    result.v4e[i] = e[idx[i]]
    result.v4v[i] = v[idx[i]]
  result.v4m = newSeq[uint32](n)
  var mx: uint32 = 0
  for i in 0 ..< n:
    if result.v4e[i] > mx: mx = result.v4e[i]
    result.v4m[i] = mx

  result.v6s = newSeq[U128](v6n)
  result.v6e = newSeq[U128](v6n)
  result.v6v = newSeq[uint16](v6n)
  for i in 0 ..< v6n:
    result.v6s[i] = (rdU64(d, off[7] + i*16 + 8), rdU64(d, off[7] + i*16))
    result.v6e[i] = (rdU64(d, off[8] + i*16 + 8), rdU64(d, off[8] + i*16))
    result.v6v[i] = rdU16(d, off[9] + i*2)
  result.v6m = newSeq[U128](v6n)
  var m6: U128 = (0'u64, 0'u64)
  for i in 0 ..< v6n:
    if m6 < result.v6e[i]: m6 = result.v6e[i]
    result.v6m[i] = m6

  result.vt = newSeq[array[4, uint32]](valn)
  for i in 0 ..< valn:
    for k in 0 ..< 4:
      result.vt[i][k] = rdU32(d, off[10] + i*16 + k*4)
  let sd = off[12]
  result.st = newSeq[string](strn)
  for i in 0 ..< strn:
    let so = int(rdU32(d, off[11] + i*8))
    let sl = int(rdU32(d, off[11] + i*8 + 4))
    result.st[i] = d[sd+so ..< sd+so+sl]

  if n > 0:
    var c: array[20, int]
    for vid in result.v4v:
      let b = result.vt[int(vid)][0]
      for i in 0 ..< 20:
        if (b and (1'u32 shl i)) != 0: inc c[i]
    for i in 0 ..< 20:
      result.w[i] = SEV[i] * (1.0 + log2(float(n) / float(max(c[i], 1))) / 24.0)
  else:
    for i in 0 ..< 20: result.w[i] = SEV[i]

proc upperU32(a: seq[uint32], ip: uint32): int =
  var lo = 0; var hi = a.len
  while lo < hi:
    let m = (lo + hi) div 2
    if a[m] > ip: hi = m else: lo = m + 1
  lo

proc upperU128(a: seq[U128], ip: U128): int =
  var lo = 0; var hi = a.len
  while lo < hi:
    let m = (lo + hi) div 2
    if ip < a[m]: hi = m else: lo = m + 1
  lo

type Match = object
  source, provider, rng: string
  flags: seq[string]
  weight: float

proc lookup(db: DB, ipStr: string): JsonNode =
  let addr0 = parseIpAddress(ipStr)
  let v4 = addr0.family == IPv4
  var matches: seq[Match]

  proc add(vid: uint16, rng: string) =
    let vt = db.vt[int(vid)]
    let b = vt[0]
    var fl: seq[string]
    var mxw = 0.0
    for i in 0 ..< 20:
      if (b and (1'u32 shl i)) != 0:
        fl.add(FLAGS[i])
        if db.w[i] > mxw: mxw = db.w[i]
    matches.add(Match(source: db.st[int(vt[2])], provider: db.st[int(vt[1])],
                      rng: rng, flags: fl, weight: round1(mxw)))

  if v4:
    let ip = ipToU32(addr0)
    var i = upperU32(db.v4s, ip)
    while i > 0:
      dec i
      if db.v4m[i] < ip: break
      if db.v4e[i] >= ip:
        add(db.v4v[i], &"{fmtV4(db.v4s[i])}-{fmtV4(db.v4e[i])}")
  else:
    let ip = ipToU128(addr0)
    var i = upperU128(db.v6s, ip)
    while i > 0:
      dec i
      if db.v6m[i] < ip: break
      if db.v6e[i] >= ip:
        add(db.v6v[i], &"{fmtV6(db.v6s[i])}-{fmtV6(db.v6e[i])}")

  matches.sort(proc(a, b: Match): int = cmp(b.weight, a.weight))

  var allFlags: seq[string]
  for m in matches:
    for f in m.flags:
      if f notin allFlags: allFlags.add(f)
  let fi = proc(f: string): int =
    for i, x in FLAGS: (if x == f: return i)
    -1
  var ranked = allFlags
  ranked.sort(proc(a, b: string): int = cmp(db.w[fi(b)], db.w[fi(a)]))

  var srcSet = initTable[string, bool]()
  for m in matches: srcSet[m.provider & "\x00" & m.source] = true
  let srcN = srcSet.len

  var score = 0.0
  if ranked.len > 0:
    let top = db.w[fi(ranked[0])]
    var ex = 0.0
    for i in 1 ..< ranked.len: ex += db.w[fi(ranked[i])]
    score = round1(min(100.0, (top + ex * 0.15) *
                       (1.0 + 0.08 * log2(float(srcN + 1)))))

  var verdict = "clean"
  if matches.len > 0:
    verdict = "minimal"
    for (t, n) in LEVELS:
      if score >= t: verdict = n; break

  var providers: seq[string]
  for m in matches:
    if m.provider.len > 0 and m.provider notin providers:
      providers.add(m.provider)
  var torIdx = -1
  for i, p in providers:
    if p.toLowerAscii == "tor": torIdx = i; break
  if torIdx >= 0:
    providers.delete(torIdx)
    providers.insert("Tor", 0)

  var reasons: seq[string]
  for i in 0 ..< min(5, ranked.len): reasons.add(ranked[i])
  let topProv = if providers.len > 0: providers[0] else: ""

  var ms = newJArray()
  for m in matches:
    ms.add(%* {"source": m.source, "provider": m.provider, "range": m.rng,
               "flags": m.flags, "weight": %m.weight})

  result = %* {
    "ip": ipStr, "found": matches.len > 0, "verdict": verdict,
    "score": %score, "detections": matches.len, "sources": srcN,
    "top_provider": topProv, "providers": providers, "flags": allFlags,
    "reasons": reasons, "matches": ms
  }

when isMainModule:
  let ip = if paramCount() > 0: paramStr(1) else: "8.8.8.8"
  let db = load("../intel.bin")
  echo pretty(lookup(db, ip), 2)

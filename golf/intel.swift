import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

let FLAGS = ["vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
    "compromised","datacenter","cdn","anycast","crawler","bot","cloud","private_relay",
    "anonymizer","mobile","isp","government"]
let SEV: [Double] = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0]
let LEVELS: [(Double, String)] = [(80,"critical"),(60,"high"),(35,"medium"),(15,"low")]

struct U128: Comparable {
    let hi: UInt64; let lo: UInt64
    static func < (a: U128, b: U128) -> Bool {
        a.hi != b.hi ? a.hi < b.hi : a.lo < b.lo
    }
    static func == (a: U128, b: U128) -> Bool { a.hi == b.hi && a.lo == b.lo }
}

struct Match {
    let source: String; let provider: String; let range: String
    let flags: [String]; let weight: Double
}

final class DB {
    var v4s: [UInt32] = [], v4e: [UInt32] = [], v4m: [UInt32] = [], v4v: [UInt16] = []
    var v6s: [U128] = [], v6e: [U128] = [], v6m: [U128] = [], v6v: [UInt16] = []
    var vt: [[UInt32]] = [], strings: [String] = []
    var weights = [Double](repeating: 0, count: 20)
}

func readU16(_ d: Data, _ o: Int) -> UInt16 {
    d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt16.self) }
}
func readU32(_ d: Data, _ o: Int) -> UInt32 {
    d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt32.self) }
}
func readU64(_ d: Data, _ o: Int) -> UInt64 {
    d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt64.self) }
}

func load(_ path: String) -> DB {
    let d = try! Data(contentsOf: URL(fileURLWithPath: path))
    guard readU32(d, 0) == 6 else { fatalError("unsupported version") }
    let h = (0..<19).map { Int(readU64(d, 8 + $0 * 8)) }
    let cn = h[0], ln = h[1], v6n = h[2], valn = h[3], strn = h[4]
    let off = Array(h[5...])
    let bi = (0...65536).map { readU32(d, off[0] + $0 * 4) }
    let N = cn + ln
    var starts = [UInt32](repeating: 0, count: N)
    var ends = [UInt32](repeating: 0, count: N)
    var vals = [UInt16](repeating: 0, count: N)
    for b in 0..<65536 {
        for j in Int(bi[b])..<Int(bi[b+1]) {
            let lo = UInt32(readU16(d, off[1] + j * 2))
            let s = (UInt32(b) << 16) | lo
            starts[j] = s
            ends[j] = s + UInt32(readU16(d, off[2] + j * 2))
            vals[j] = readU16(d, off[3] + j * 2)
        }
    }
    for i in 0..<ln {
        starts[cn + i] = readU32(d, off[4] + i * 4)
        ends[cn + i] = readU32(d, off[5] + i * 4)
        vals[cn + i] = readU16(d, off[6] + i * 2)
    }
    let order = (0..<N).sorted { starts[$0] < starts[$1] }
    let db = DB()
    db.v4s = order.map { starts[$0] }
    db.v4e = order.map { ends[$0] }
    db.v4v = order.map { vals[$0] }
    db.v4m = [UInt32](repeating: 0, count: N)
    var mx: UInt32 = 0
    for i in 0..<N { if db.v4e[i] > mx { mx = db.v4e[i] }; db.v4m[i] = mx }

    db.v6s = (0..<v6n).map {
        U128(hi: readU64(d, off[7] + $0 * 16 + 8), lo: readU64(d, off[7] + $0 * 16))
    }
    db.v6e = (0..<v6n).map {
        U128(hi: readU64(d, off[8] + $0 * 16 + 8), lo: readU64(d, off[8] + $0 * 16))
    }
    db.v6v = (0..<v6n).map { readU16(d, off[9] + $0 * 2) }
    db.v6m = [U128](repeating: U128(hi: 0, lo: 0), count: v6n)
    var m6 = U128(hi: 0, lo: 0)
    for i in 0..<v6n { if db.v6e[i] > m6 { m6 = db.v6e[i] }; db.v6m[i] = m6 }

    db.vt = (0..<valn).map { i in
        (0..<4).map { k in readU32(d, off[10] + (i * 4 + k) * 4) }
    }
    let sd = off[12]
    db.strings = (0..<strn).map { i in
        let so = Int(readU32(d, off[11] + i * 8))
        let sl = Int(readU32(d, off[11] + i * 8 + 4))
        return String(data: d.subdata(in: (sd+so)..<(sd+so+sl)), encoding: .utf8) ?? ""
    }
    if N > 0 {
        var cnt = [Int](repeating: 0, count: 20)
        for vid in db.v4v {
            let bits = db.vt[Int(vid)][0]
            for i in 0..<20 { if bits & (UInt32(1) << i) != 0 { cnt[i] += 1 } }
        }
        for i in 0..<20 {
            let c = max(cnt[i], 1)
            db.weights[i] = SEV[i] * (1 + log2(Double(N) / Double(c)) / 24)
        }
    } else {
        db.weights = SEV
    }
    return db
}

func r1(_ x: Double) -> Double { (x * 10).rounded() / 10 }

func parseIP(_ s: String) -> (v4: UInt32?, v6: U128?) {
    var buf4 = in_addr()
    if inet_pton(AF_INET, s, &buf4) == 1 {
        return (UInt32(bigEndian: buf4.s_addr), nil)
    }
    var buf6 = in6_addr()
    if inet_pton(AF_INET6, s, &buf6) == 1 {
        var bytes = [UInt8](repeating: 0, count: 16)
        withUnsafeBytes(of: &buf6) { raw in
            for i in 0..<16 { bytes[i] = raw[i] }
        }
        var hi: UInt64 = 0, lo: UInt64 = 0
        for i in 0..<8 { hi = (hi << 8) | UInt64(bytes[i]) }
        for i in 8..<16 { lo = (lo << 8) | UInt64(bytes[i]) }
        return (nil, U128(hi: hi, lo: lo))
    }
    fatalError("invalid ip: \(s)")
}

func fmtV4(_ ip: UInt32) -> String {
    "\((ip >> 24) & 0xFF).\((ip >> 16) & 0xFF).\((ip >> 8) & 0xFF).\(ip & 0xFF)"
}

func fmtV6(_ ip: U128) -> String {
    var bytes = [UInt8](repeating: 0, count: 16)
    for i in 0..<8 { bytes[i] = UInt8((ip.hi >> (56 - i*8)) & 0xFF) }
    for i in 0..<8 { bytes[8+i] = UInt8((ip.lo >> (56 - i*8)) & 0xFF) }
    var addr = in6_addr()
    withUnsafeMutableBytes(of: &addr) { raw in
        for i in 0..<16 { raw[i] = bytes[i] }
    }
    var out = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    inet_ntop(AF_INET6, &addr, &out, socklen_t(INET6_ADDRSTRLEN))
    return String(cString: out)
}

func upperU32(_ a: [UInt32], _ k: UInt32) -> Int {
    var lo = 0, hi = a.count
    while lo < hi { let m = (lo + hi) / 2; if a[m] > k { hi = m } else { lo = m + 1 } }
    return lo
}

func upperU128(_ a: [U128], _ k: U128) -> Int {
    var lo = 0, hi = a.count
    while lo < hi { let m = (lo + hi) / 2; if a[m] > k { hi = m } else { lo = m + 1 } }
    return lo
}

func buildMatch(_ db: DB, _ vid: UInt16, _ rng: String) -> Match {
    let row = db.vt[Int(vid)]
    let bits = row[0]
    var fl: [String] = []
    var mxw: Double = 0
    for i in 0..<20 {
        if bits & (UInt32(1) << i) != 0 {
            fl.append(FLAGS[i])
            if db.weights[i] > mxw { mxw = db.weights[i] }
        }
    }
    return Match(source: db.strings[Int(row[2])], provider: db.strings[Int(row[1])],
                 range: rng, flags: fl, weight: r1(mxw))
}

func num(_ d: Double) -> String {
    if d == d.rounded() && abs(d) < 1e16 {
        return "\(Int64(d)).0"
    }
    return String(format: "%.1f", d)
}

func jstr(_ s: String) -> String {
    var b = "\""
    for c in s.unicodeScalars {
        switch c.value {
        case 0x22: b += "\\\""
        case 0x5C: b += "\\\\"
        case 0x0A: b += "\\n"
        case 0x0D: b += "\\r"
        case 0x09: b += "\\t"
        case 0x08: b += "\\b"
        case 0x0C: b += "\\f"
        default:
            if c.value < 0x20 { b += String(format: "\\u%04x", c.value) }
            else { b += String(c) }
        }
    }
    return b + "\""
}

func jarr(_ items: [String], _ indent: String) -> String {
    if items.isEmpty { return "[]" }
    let inner = indent + "  "
    return "[\n" + items.map { "\(inner)\(jstr($0))" }.joined(separator: ",\n")
        + "\n\(indent)]"
}

func jmatches(_ ms: [Match], _ indent: String) -> String {
    if ms.isEmpty { return "[]" }
    let inner = indent + "  "
    let deep = inner + "  "
    let parts = ms.map { m -> String in
        "\(inner){\n"
        + "\(deep)\"source\": \(jstr(m.source)),\n"
        + "\(deep)\"provider\": \(jstr(m.provider)),\n"
        + "\(deep)\"range\": \(jstr(m.range)),\n"
        + "\(deep)\"flags\": \(jarr(m.flags, deep)),\n"
        + "\(deep)\"weight\": \(num(m.weight))\n"
        + "\(inner)}"
    }
    return "[\n" + parts.joined(separator: ",\n") + "\n\(indent)]"
}

func lookup(_ db: DB, _ ipStr: String) -> String {
    let (v4, v6) = parseIP(ipStr)
    var matches: [Match] = []
    if let ip = v4 {
        var i = upperU32(db.v4s, ip)
        while i > 0 {
            i -= 1
            if db.v4m[i] < ip { break }
            if db.v4e[i] >= ip {
                matches.append(buildMatch(db, db.v4v[i],
                    "\(fmtV4(db.v4s[i]))-\(fmtV4(db.v4e[i]))"))
            }
        }
    } else if let ip = v6 {
        var i = upperU128(db.v6s, ip)
        while i > 0 {
            i -= 1
            if db.v6m[i] < ip { break }
            if db.v6e[i] >= ip {
                matches.append(buildMatch(db, db.v6v[i],
                    "\(fmtV6(db.v6s[i]))-\(fmtV6(db.v6e[i]))"))
            }
        }
    }
    matches.sort { $0.weight > $1.weight }

    var allFlags: [String] = [], providers: [String] = [], srcs: [String] = []
    var rankedSet: [String] = []
    var seenFlag = Set<String>(), seenProv = Set<String>(), seenSrc = Set<String>()
    for m in matches {
        for f in m.flags where !seenFlag.contains(f) {
            seenFlag.insert(f); allFlags.append(f); rankedSet.append(f)
        }
        if !m.provider.isEmpty && !seenProv.contains(m.provider) {
            seenProv.insert(m.provider); providers.append(m.provider)
        }
        let key = "\(m.provider)|\(m.source)"
        if !seenSrc.contains(key) { seenSrc.insert(key); srcs.append(key) }
    }
    let fi = Dictionary(uniqueKeysWithValues: FLAGS.enumerated().map { ($1, $0) })
    let ranked = rankedSet.sorted { db.weights[fi[$0]!] > db.weights[fi[$1]!] }

    var score = 0.0
    if !ranked.isEmpty {
        let top = db.weights[fi[ranked[0]]!]
        let ex = ranked.dropFirst().reduce(0.0) { $0 + db.weights[fi[$1]!] }
        score = r1(min(100, (top + ex * 0.15) * (1 + 0.08 * log2(Double(srcs.count + 1)))))
    }
    var verdict = "clean"
    if !matches.isEmpty {
        verdict = "minimal"
        for (t, n) in LEVELS where score >= t { verdict = n; break }
    }

    var provList = providers
    if let idx = provList.firstIndex(where: { $0.lowercased() == "tor" }) {
        provList.remove(at: idx)
        provList.insert("Tor", at: 0)
    }
    let reasons = Array(ranked.prefix(5))
    let topProv = provList.first ?? ""

    var out = "{\n"
    out += "  \"ip\": \(jstr(ipStr)),\n"
    out += "  \"found\": \(matches.isEmpty ? "false" : "true"),\n"
    out += "  \"verdict\": \(jstr(verdict)),\n"
    out += "  \"score\": \(num(score)),\n"
    out += "  \"detections\": \(matches.count),\n"
    out += "  \"sources\": \(srcs.count),\n"
    out += "  \"top_provider\": \(jstr(topProv)),\n"
    out += "  \"providers\": \(jarr(provList, "  ")),\n"
    out += "  \"flags\": \(jarr(allFlags, "  ")),\n"
    out += "  \"reasons\": \(jarr(reasons, "  ")),\n"
    out += "  \"matches\": \(jmatches(matches, "  "))\n"
    out += "}"
    return out
}

let args = CommandLine.arguments
let ip = args.count > 1 ? args[1] : "8.8.8.8"
let db = load("../intel.bin")
print(lookup(db, ip))

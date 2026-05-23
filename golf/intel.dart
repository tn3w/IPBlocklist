import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

const F = [
  "vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
  "compromised","datacenter","cdn","anycast","crawler","bot","cloud",
  "private_relay","anonymizer","mobile","isp","government"
];
const S = [30.0,25.0,45.0,95.0,95.0,55.0,70.0,65.0,75.0,15.0,
           5.0,0.0,10.0,40.0,10.0,15.0,35.0,0.0,0.0,0.0];
const L = [[80,"critical"],[60,"high"],[35,"medium"],[15,"low"]];

final _l2 = log(2);
double log2(num x) => log(x) / _l2;
double r1(double x) => (x * 10).round() / 10;

class DB {
  Uint32List v4s, v4e, v4m;
  Uint16List v4v;
  List<BigInt> v6s, v6e, v6m;
  Uint16List v6v;
  Uint32List vt;
  List<String> st;
  Map<String, double> w;
  DB(this.v4s, this.v4e, this.v4m, this.v4v, this.v6s, this.v6e, this.v6m,
     this.v6v, this.vt, this.st, this.w);
}

DB load(String path) {
  final d = File(path).readAsBytesSync();
  final dv = ByteData.view(d.buffer, d.offsetInBytes, d.lengthInBytes);
  if (dv.getUint32(0, Endian.little) != 6) throw "version";
  final o = <int>[];
  for (var i = 0; i < 19; i++) {
    o.add(dv.getUint64(8 + i * 8, Endian.little));
  }
  final cn = o[0], ln = o[1], v6n = o[2], valn = o[3], strn = o[4];
  final off = o.sublist(5);
  final all = cn + ln;

  final bi = Uint32List.view(d.buffer, d.offsetInBytes + off[0], 65537);
  final ss = Uint32List(all);
  final se = Uint32List(all);
  final sv = Uint16List(all);
  for (var b = 0; b < 65536; b++) {
    for (var j = bi[b]; j < bi[b + 1]; j++) {
      final lo = dv.getUint16(off[1] + j * 2, Endian.little);
      final l2 = dv.getUint16(off[2] + j * 2, Endian.little);
      ss[j] = (b << 16) | lo;
      se[j] = ss[j] + l2;
      sv[j] = dv.getUint16(off[3] + j * 2, Endian.little);
    }
  }
  for (var i = 0; i < ln; i++) {
    ss[cn + i] = dv.getUint32(off[4] + i * 4, Endian.little);
    se[cn + i] = dv.getUint32(off[5] + i * 4, Endian.little);
    sv[cn + i] = dv.getUint16(off[6] + i * 2, Endian.little);
  }
  final idx = List<int>.generate(all, (i) => i);
  idx.sort((a, b) => ss[a].compareTo(ss[b]));
  final v4s = Uint32List(all);
  final v4e = Uint32List(all);
  final v4v = Uint16List(all);
  for (var i = 0; i < all; i++) {
    final k = idx[i];
    v4s[i] = ss[k]; v4e[i] = se[k]; v4v[i] = sv[k];
  }
  final v4m = Uint32List(all);
  var mx = 0;
  for (var i = 0; i < all; i++) {
    if (v4e[i] > mx) mx = v4e[i];
    v4m[i] = mx;
  }

  BigInt u64(int i) => BigInt.from(i).toUnsigned(64);
  final v6s = <BigInt>[], v6e = <BigInt>[];
  for (var i = 0; i < v6n; i++) {
    final lo = u64(dv.getUint64(off[7] + i * 16, Endian.little));
    final hi = u64(dv.getUint64(off[7] + i * 16 + 8, Endian.little));
    v6s.add((hi << 64) | lo);
    final lo2 = u64(dv.getUint64(off[8] + i * 16, Endian.little));
    final hi2 = u64(dv.getUint64(off[8] + i * 16 + 8, Endian.little));
    v6e.add((hi2 << 64) | lo2);
  }
  final v6v = Uint16List(v6n);
  for (var i = 0; i < v6n; i++) {
    v6v[i] = dv.getUint16(off[9] + i * 2, Endian.little);
  }
  final v6m = <BigInt>[];
  var mm = BigInt.zero;
  for (var i = 0; i < v6n; i++) {
    if (v6e[i] > mm) mm = v6e[i];
    v6m.add(mm);
  }

  final vt = Uint32List(valn * 4);
  for (var i = 0; i < valn * 4; i++) {
    vt[i] = dv.getUint32(off[10] + i * 4, Endian.little);
  }
  final sd = off[12];
  final st = <String>[];
  for (var i = 0; i < strn; i++) {
    final so = dv.getUint32(off[11] + i * 8, Endian.little);
    final sl = dv.getUint32(off[11] + i * 8 + 4, Endian.little);
    st.add(utf8.decode(d.sublist(sd + so, sd + so + sl), allowMalformed: true));
  }

  final w = <String, double>{};
  if (all > 0) {
    final cnt = List<int>.filled(20, 0);
    for (var k = 0; k < all; k++) {
      final b = vt[v4v[k] * 4];
      for (var i = 0; i < 20; i++) if ((b & (1 << i)) != 0) cnt[i]++;
    }
    for (var i = 0; i < 20; i++) {
      final c = cnt[i] == 0 ? 1 : cnt[i];
      w[F[i]] = S[i] * (1 + log2(all / c) / 24);
    }
  } else {
    for (var i = 0; i < 20; i++) w[F[i]] = S[i];
  }
  return DB(v4s, v4e, v4m, v4v, v6s, v6e, v6m, v6v, vt, st, w);
}

int upperU32(Uint32List a, int ip) {
  var lo = 0, hi = a.length;
  while (lo < hi) {
    final m = (lo + hi) >> 1;
    if (a[m] > ip) hi = m; else lo = m + 1;
  }
  return lo;
}

int upperBig(List<BigInt> a, BigInt ip) {
  var lo = 0, hi = a.length;
  while (lo < hi) {
    final m = (lo + hi) >> 1;
    if (a[m] > ip) hi = m; else lo = m + 1;
  }
  return lo;
}

String fmt4(int x) =>
    "${(x >> 24) & 0xff}.${(x >> 16) & 0xff}.${(x >> 8) & 0xff}.${x & 0xff}";

String fmt6(BigInt x) {
  final bytes = Uint8List(16);
  for (var i = 0; i < 16; i++) {
    bytes[15 - i] = ((x >> (i * 8)) & BigInt.from(0xff)).toInt();
  }
  return InternetAddress.fromRawAddress(bytes).address;
}

(bool, int?, BigInt?) parseIp(String s) {
  final addr = InternetAddress.tryParse(s);
  if (addr == null) throw "invalid ip: $s";
  final r = addr.rawAddress;
  if (r.length == 4) {
    return (true, (r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3], null);
  }
  var ip = BigInt.zero;
  for (var i = 0; i < 16; i++) {
    ip = (ip << 8) | BigInt.from(r[i]);
  }
  return (false, null, ip);
}

Map<String, dynamic> lookup(DB db, String ipStr) {
  final (v4, ip4, ip6) = parseIp(ipStr);
  final matches = <Map<String, dynamic>>[];

  void push(int vid, String rng) {
    final b = db.vt[vid * 4];
    final fl = <String>[];
    var mxw = 0.0;
    for (var i = 0; i < 20; i++) {
      if ((b & (1 << i)) != 0) {
        fl.add(F[i]);
        final v = db.w[F[i]]!;
        if (v > mxw) mxw = v;
      }
    }
    matches.add({
      "source": db.st[db.vt[vid * 4 + 2]],
      "provider": db.st[db.vt[vid * 4 + 1]],
      "range": rng,
      "flags": fl,
      "weight": r1(mxw),
    });
  }

  if (v4) {
    final ip = ip4!;
    if (db.v4s.isNotEmpty) {
      var i = upperU32(db.v4s, ip);
      while (i > 0) {
        i--;
        if (db.v4m[i] < ip) break;
        if (db.v4e[i] >= ip) {
          push(db.v4v[i], "${fmt4(db.v4s[i])}-${fmt4(db.v4e[i])}");
        }
      }
    }
  } else {
    final ip = ip6!;
    if (db.v6s.isNotEmpty) {
      var i = upperBig(db.v6s, ip);
      while (i > 0) {
        i--;
        if (db.v6m[i] < ip) break;
        if (db.v6e[i] >= ip) {
          push(db.v6v[i], "${fmt6(db.v6s[i])}-${fmt6(db.v6e[i])}");
        }
      }
    }
  }

  matches.sort((x, y) => (y["weight"] as num).compareTo(x["weight"] as num));

  final flagset = <String>{};
  for (final m in matches) flagset.addAll((m["flags"] as List).cast<String>());
  final ranked = flagset.toList()..sort((a, b) => db.w[b]!.compareTo(db.w[a]!));
  final src = <String>{};
  for (final m in matches) src.add("${m["provider"]}|${m["source"]}");

  num score = 0;
  if (ranked.isNotEmpty) {
    final top = db.w[ranked[0]]!;
    final extras = ranked.skip(1).fold(0.0, (s, f) => s + db.w[f]!);
    score = r1(min(100.0,
        (top + extras * 0.15) * (1 + 0.08 * log2(src.length + 1))));
  }
  var verdict = "clean";
  if (matches.isNotEmpty) {
    verdict = "minimal";
    for (final lv in L) {
      if (score >= (lv[0] as int)) { verdict = lv[1] as String; break; }
    }
  }
  final allFlags = <String>[];
  for (final m in matches) {
    for (final f in (m["flags"] as List).cast<String>()) {
      if (!allFlags.contains(f)) allFlags.add(f);
    }
  }
  var providers = <String>[];
  for (final m in matches) {
    final p = m["provider"] as String;
    if (p.isNotEmpty && !providers.contains(p)) providers.add(p);
  }
  final ti = providers.indexWhere((p) => p.toLowerCase() == "tor");
  if (ti >= 0) {
    providers.removeAt(ti);
    providers.insert(0, "Tor");
  }
  return {
    "ip": ipStr,
    "found": matches.isNotEmpty,
    "verdict": verdict,
    "score": score,
    "detections": matches.length,
    "sources": src.length,
    "top_provider": providers.isNotEmpty ? providers[0] : "",
    "providers": providers,
    "flags": allFlags,
    "reasons": ranked.take(5).toList(),
    "matches": matches,
  };
}

void main(List<String> args) {
  final ip = args.isNotEmpty ? args[0] : "8.8.8.8";
  final db = load("../intel.bin");
  print(JsonEncoder.withIndent("  ").convert(lookup(db, ip)));
}

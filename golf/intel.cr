require "json"
require "socket"

FLAGS = %w[vpn proxy tor malware c2 scanner brute_force spammer compromised
           datacenter cdn anycast crawler bot cloud private_relay anonymizer
           mobile isp government]
SEV    = [30.0, 25.0, 45.0, 95.0, 95.0, 55.0, 70.0, 65.0, 75.0, 15.0,
          5.0, 0.0, 10.0, 40.0, 10.0, 15.0, 35.0, 0.0, 0.0, 0.0]
LEVELS = [{80.0, "critical"}, {60.0, "high"}, {35.0, "medium"}, {15.0, "low"}]
LE     = IO::ByteFormat::LittleEndian

def u16(d : Bytes, off : Int) : UInt16
  LE.decode(UInt16, d[off, 2])
end

def u32(d : Bytes, off : Int) : UInt32
  LE.decode(UInt32, d[off, 4])
end

def u64(d : Bytes, off : Int) : UInt64
  LE.decode(UInt64, d[off, 8])
end

def read_u16s(d : Bytes, off : Int, n : Int) : Array(UInt32)
  Array(UInt32).new(n) { |i| u16(d, off + i*2).to_u32 }
end

def read_u32s(d : Bytes, off : Int, n : Int) : Array(UInt32)
  Array(UInt32).new(n) { |i| u32(d, off + i*4) }
end

class DB
  property v4s : Array(UInt32), v4e : Array(UInt32), v4v : Array(UInt32), v4m : Array(UInt32)
  property v6s : Array(UInt128), v6e : Array(UInt128), v6v : Array(UInt32), v6m : Array(UInt128)
  property values : Array(Tuple(UInt32, UInt32, UInt32, UInt32))
  property strings : Array(String)
  property weights : Hash(String, Float64)

  def initialize(@v4s, @v4e, @v4v, @v4m, @v6s, @v6e, @v6v, @v6m,
                 @values, @strings, @weights)
  end
end

def load_db(path : String) : DB
  d = File.read(path).to_slice
  ver = u32(d, 0)
  raise "unsupported version #{ver}" unless ver == 6
  h = Array(UInt64).new(19) { |i| u64(d, 8 + i*8) }
  cn, ln, v6n, valn, strn = h[0].to_i, h[1].to_i, h[2].to_i, h[3].to_i, h[4].to_i
  o = h[5..].map(&.to_i)

  bi = read_u32s(d, o[0], 65537)
  bid = Array(UInt32).new(cn)
  65536.times do |b|
    (bi[b + 1] - bi[b]).times { bid << b.to_u32 }
  end
  starts_lo = read_u16s(d, o[1], cn)
  lens = read_u16s(d, o[2], cn)
  vals_s = read_u16s(d, o[3], cn)
  ss = Array(UInt32).new(cn) { |i| (bid[i] << 16) | starts_lo[i] }
  se = Array(UInt32).new(cn) { |i| ss[i] + lens[i] }

  lstarts = read_u32s(d, o[4], ln)
  lends = read_u32s(d, o[5], ln)
  lvals = read_u16s(d, o[6], ln)

  combined = Array(Tuple(UInt32, UInt32, UInt32)).new(cn + ln)
  cn.times { |i| combined << {ss[i], se[i], vals_s[i]} }
  ln.times { |i| combined << {lstarts[i], lends[i], lvals[i]} }
  combined.sort! { |a, b| a[0] <=> b[0] }
  v4s = combined.map &.[0]
  v4e = combined.map &.[1]
  v4v = combined.map &.[2]
  v4m = Array(UInt32).new(v4e.size)
  m32 = 0_u32
  v4e.each { |e| m32 = e if e > m32; v4m << m32 }

  v6s = Array(UInt128).new(v6n)
  v6e = Array(UInt128).new(v6n)
  v6n.times do |i|
    lo = u64(d, o[7] + i*16)
    hi = u64(d, o[7] + i*16 + 8)
    v6s << ((hi.to_u128 << 64) | lo.to_u128)
    lo = u64(d, o[8] + i*16)
    hi = u64(d, o[8] + i*16 + 8)
    v6e << ((hi.to_u128 << 64) | lo.to_u128)
  end
  v6v = read_u16s(d, o[9], v6n)
  v6m = Array(UInt128).new(v6n)
  m128 = 0_u128
  v6e.each { |e| m128 = e if e > m128; v6m << m128 }

  values = Array(Tuple(UInt32, UInt32, UInt32, UInt32)).new(valn) do |i|
    base = o[10] + i*16
    {u32(d, base), u32(d, base + 4), u32(d, base + 8), u32(d, base + 12)}
  end

  blob = d[o[12], o[13]]
  strings = Array(String).new(strn) do |i|
    p = u32(d, o[11] + i*8).to_i
    l = u32(d, o[11] + i*8 + 4).to_i
    String.new(blob[p, l])
  end

  weights = {} of String => Float64
  if v4v.size > 0
    tot = v4v.size.to_f
    FLAGS.each_with_index do |f, i|
      cnt = 0
      v4v.each { |vid| cnt += 1 if (values[vid][0] >> i) & 1 == 1 }
      weights[f] = SEV[i] * (1 + Math.log2(tot / Math.max(cnt, 1)) / 24)
    end
  else
    FLAGS.each_with_index { |f, i| weights[f] = SEV[i] }
  end

  DB.new(v4s, v4e, v4v, v4m, v6s, v6e, v6v, v6m, values, strings, weights)
end

def upper_bound(arr, x) : Int32
  lo, hi = 0, arr.size
  while lo < hi
    mid = (lo + hi) // 2
    if arr[mid] <= x
      lo = mid + 1
    else
      hi = mid
    end
  end
  lo
end

def fmt_v4(n : UInt32) : String
  "%d.%d.%d.%d" % [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]
end

def fmt_v6(n : UInt128) : String
  groups = Array(UInt16).new(8) { |i| ((n >> ((7 - i) * 64 // 8 * 8)) & 0xffff_u128).to_u16 }
  groups = Array(UInt16).new(8) { |i| ((n >> ((7 - i) * 16)) & 0xffff_u128).to_u16 }
  best_start, best_len, cur_start, cur_len = -1, 0, -1, 0
  groups.each_with_index do |g, i|
    if g == 0
      cur_start = i if cur_len == 0
      cur_len += 1
      if cur_len > best_len && cur_len >= 2
        best_start, best_len = cur_start, cur_len
      end
    else
      cur_len = 0
    end
  end
  if best_start < 0
    groups.map { |g| g.to_s(16) }.join(":")
  else
    left = groups[0, best_start].map { |g| g.to_s(16) }.join(":")
    right = groups[best_start + best_len, 8 - best_start - best_len].map { |g| g.to_s(16) }.join(":")
    "#{left}::#{right}"
  end
end

def hits_v4(db : DB, ip : UInt32)
  s, e, m, v = db.v4s, db.v4e, db.v4m, db.v4v
  return [] of Tuple(UInt32, UInt32, UInt32) if s.empty?
  i = upper_bound(s, ip)
  out = [] of Tuple(UInt32, UInt32, UInt32)
  while i > 0
    i -= 1
    break if m[i] < ip
    out << {s[i], e[i], v[i]} if e[i] >= ip
  end
  out
end

def hits_v6(db : DB, ip : UInt128)
  s, e, m, v = db.v6s, db.v6e, db.v6m, db.v6v
  return [] of Tuple(UInt128, UInt128, UInt32) if s.empty?
  i = upper_bound(s, ip)
  out = [] of Tuple(UInt128, UInt128, UInt32)
  while i > 0
    i -= 1
    break if m[i] < ip
    out << {s[i], e[i], v[i]} if e[i] >= ip
  end
  out
end

record Match, source : String, provider : String, range : String,
  flags : Array(String), weight : Float64

def round1(x : Float64) : Float64
  (x * 10).round / 10
end

def lookup(db : DB, ip_str : String)
  v4 = !ip_str.includes?(':')
  matches = [] of Match
  if v4
    parts = ip_str.split(".").map &.to_u32
    ip32 = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    hits_v4(db, ip32).each do |s, e, vid|
      b, prov, src, _ = db.values[vid]
      flags = [] of String
      FLAGS.each_with_index { |f, i| flags << f if (b >> i) & 1 == 1 }
      w = flags.map { |f| db.weights[f] }.max? || 0.0
      matches << Match.new(db.strings[src], db.strings[prov],
        "#{fmt_v4(s)}-#{fmt_v4(e)}", flags, round1(w))
    end
  else
    ip128 = parse_v6(ip_str)
    hits_v6(db, ip128).each do |s, e, vid|
      b, prov, src, _ = db.values[vid]
      flags = [] of String
      FLAGS.each_with_index { |f, i| flags << f if (b >> i) & 1 == 1 }
      w = flags.map { |f| db.weights[f] }.max? || 0.0
      matches << Match.new(db.strings[src], db.strings[prov],
        "#{fmt_v6(s)}-#{fmt_v6(e)}", flags, round1(w))
    end
  end
  matches.sort! { |a, b| b.weight <=> a.weight }

  uniq_flags = matches.flat_map(&.flags).uniq
  ranked = uniq_flags.sort { |a, b| db.weights[b] <=> db.weights[a] }
  sources = matches.map { |m| {m.provider, m.source} }.uniq
  score = if ranked.empty?
            0.0
          else
            base = db.weights[ranked[0]] + ranked[1..].sum { |f| db.weights[f] } * 0.15
            round1(Math.min(100.0, base * (1 + 0.08 * Math.log2(sources.size + 1))))
          end
  all_flags = matches.flat_map(&.flags).uniq
  providers = matches.map(&.provider).reject(&.empty?).uniq
  if providers.any? { |p| p.downcase == "tor" }
    providers = ["Tor"] + providers.reject { |p| p.downcase == "tor" }
  end
  verdict = if matches.empty?
              "clean"
            else
              found = LEVELS.find { |t, _| score >= t }
              found ? found[1] : "minimal"
            end

  {
    "ip"           => JSON::Any.new(ip_str),
    "found"        => JSON::Any.new(!matches.empty?),
    "verdict"      => JSON::Any.new(verdict),
    "score"        => JSON::Any.new(score),
    "detections"   => JSON::Any.new(matches.size.to_i64),
    "sources"      => JSON::Any.new(sources.size.to_i64),
    "top_provider" => JSON::Any.new(providers.first? || ""),
    "providers"    => JSON::Any.new(providers.map { |p| JSON::Any.new(p) }),
    "flags"        => JSON::Any.new(all_flags.map { |f| JSON::Any.new(f) }),
    "reasons"      => JSON::Any.new(ranked.first(5).map { |f| JSON::Any.new(f) }),
    "matches"      => JSON::Any.new(matches.map { |m|
      JSON::Any.new({
        "source"   => JSON::Any.new(m.source),
        "provider" => JSON::Any.new(m.provider),
        "range"    => JSON::Any.new(m.range),
        "flags"    => JSON::Any.new(m.flags.map { |f| JSON::Any.new(f) }),
        "weight"   => JSON::Any.new(m.weight),
      } of String => JSON::Any)
    }),
  } of String => JSON::Any
end

def parse_v6(s : String) : UInt128
  if s.includes?("::")
    left, right = s.split("::", 2)
    lp = left.empty? ? [] of String : left.split(":")
    rp = right.empty? ? [] of String : right.split(":")
    fill = 8 - lp.size - rp.size
    parts = lp + Array.new(fill, "0") + rp
  else
    parts = s.split(":")
  end
  raise "bad v6" unless parts.size == 8
  result = 0_u128
  parts.each do |p|
    result = (result << 16) | p.to_u16(16).to_u128
  end
  result
end

ip = ARGV[0]? || "8.8.8.8"
db = load_db("../intel.bin")
puts lookup(db, ip).to_json

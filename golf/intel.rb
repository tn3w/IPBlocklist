require 'ipaddr'
require 'json'
require 'socket'

FLAGS = %w[vpn proxy tor malware c2 scanner brute_force spammer compromised
           datacenter cdn anycast crawler bot cloud private_relay anonymizer
           mobile isp government]
SEV = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0]
LEVELS = [[80,'critical'],[60,'high'],[35,'medium'],[15,'low']]

def load_db(path)
  d = File.binread(path)
  ver = d[0,4].unpack1('V')
  raise "unsupported version #{ver}" unless ver == 6
  h = d[8, 19*8].unpack('Q<*')
  cn, ln, v6n, valn, strn = h[0,5]
  o = h[5..]

  bi = d[o[0], 65537*4].unpack('V*')
  bid = []
  65536.times { |b| (bi[b+1]-bi[b]).times { bid << b } }
  starts_lo = cn > 0 ? d[o[1], cn*2].unpack('v*') : []
  lens = cn > 0 ? d[o[2], cn*2].unpack('v*') : []
  vals_s = cn > 0 ? d[o[3], cn*2].unpack('v*') : []
  ss = Array.new(cn) { |i| (bid[i] << 16) | starts_lo[i] }
  se = Array.new(cn) { |i| ss[i] + lens[i] }

  lstarts = ln > 0 ? d[o[4], ln*4].unpack('V*') : []
  lends = ln > 0 ? d[o[5], ln*4].unpack('V*') : []
  lvals = ln > 0 ? d[o[6], ln*2].unpack('v*') : []

  all = (ss.zip(se, vals_s) + lstarts.zip(lends, lvals)).sort_by { |r| r[0] }
  v4s = all.map { |r| r[0] }
  v4e = all.map { |r| r[1] }
  v4v = all.map { |r| r[2] }
  v4_max = []
  m = 0
  v4e.each { |e| m = e if e > m; v4_max << m }

  v6_raw_s = v6n > 0 ? d[o[7], v6n*16].unpack('Q<*') : []
  v6_raw_e = v6n > 0 ? d[o[8], v6n*16].unpack('Q<*') : []
  v6s = Array.new(v6n) { |i| (v6_raw_s[i*2+1] << 64) | v6_raw_s[i*2] }
  v6e = Array.new(v6n) { |i| (v6_raw_e[i*2+1] << 64) | v6_raw_e[i*2] }
  v6v = v6n > 0 ? d[o[9], v6n*2].unpack('v*') : []
  v6_max = []
  m = 0
  v6e.each { |e| m = e if e > m; v6_max << m }

  values_flat = valn > 0 ? d[o[10], valn*16].unpack('V*') : []
  values = Array.new(valn) { |i| values_flat[i*4, 4] }

  sidx = strn > 0 ? d[o[11], strn*8].unpack('V*') : []
  blob = d[o[12], o[13]]
  strings = Array.new(strn) { |i| blob[sidx[i*2], sidx[i*2+1]].force_encoding('UTF-8') }

  if v4v.length > 0
    tot = v4v.length
    weights = {}
    FLAGS.each_with_index do |f, i|
      cnt = v4v.count { |vid| (values[vid][0] >> i) & 1 == 1 }
      weights[f] = SEV[i] * (1 + Math.log2(tot.to_f / [cnt, 1].max) / 24)
    end
  else
    weights = FLAGS.zip(SEV).to_h
  end

  { v4s: v4s, v4e: v4e, v4v: v4v, v4m: v4_max,
    v6s: v6s, v6e: v6e, v6v: v6v, v6m: v6_max,
    values: values, weights: weights, strings: strings }
end

def upper_bound(arr, x)
  lo, hi = 0, arr.length
  while lo < hi
    mid = (lo + hi) / 2
    if arr[mid] <= x then lo = mid + 1 else hi = mid end
  end
  lo
end

def hits(db, ip, v4)
  s, e, m, v = v4 ? [db[:v4s], db[:v4e], db[:v4m], db[:v4v]]
                  : [db[:v6s], db[:v6e], db[:v6m], db[:v6v]]
  return [] if s.empty?
  i = upper_bound(s, ip)
  out = []
  while i > 0
    i -= 1
    break if m[i] < ip
    out << [s[i], e[i], v[i]] if e[i] >= ip
  end
  out
end

def fmt_ip(n, v4)
  IPAddr.new(n, v4 ? Socket::AF_INET : Socket::AF_INET6).to_s
end

def lookup(db, ip_str)
  addr = IPAddr.new(ip_str)
  v4 = addr.ipv4?
  ip = addr.to_i
  matches = hits(db, ip, v4).map do |s, e, vid|
    b, prov, src, _ = db[:values][vid]
    flags = FLAGS.each_with_index.select { |_, i| (b >> i) & 1 == 1 }.map(&:first)
    w = flags.map { |f| db[:weights][f] }.max || 0
    { source: db[:strings][src], provider: db[:strings][prov],
      range: "#{fmt_ip(s, v4)}-#{fmt_ip(e, v4)}", flags: flags, weight: w.round(1) }
  end
  matches.sort_by! { |m| -m[:weight] }
  ranked = matches.flat_map { |m| m[:flags] }.uniq.sort_by { |f| -db[:weights][f] }
  sources = matches.map { |m| [m[:provider], m[:source]] }.uniq
  score = if ranked.empty?
    0.0
  else
    base = db[:weights][ranked[0]] + ranked[1..].sum { |f| db[:weights][f] } * 0.15
    [100, base * (1 + 0.08 * Math.log2(sources.length + 1))].min.round(1)
  end
  all_flags = matches.flat_map { |m| m[:flags] }.uniq
  providers = matches.map { |m| m[:provider] }.reject(&:empty?).uniq
  if providers.any? { |p| p.downcase == 'tor' }
    providers = ['Tor'] + providers.reject { |p| p.downcase == 'tor' }
  end
  verdict = matches.empty? ? 'clean' : (LEVELS.find { |t, _| score >= t }&.last || 'minimal')
  { ip: ip_str, found: !matches.empty?, verdict: verdict, score: score,
    detections: matches.length, sources: sources.length,
    top_provider: providers.first || '', providers: providers,
    flags: all_flags, reasons: ranked.first(5), matches: matches }
end

if __FILE__ == $0
  db = load_db('../intel.bin')
  puts JSON.pretty_generate(lookup(db, ARGV[0] || '8.8.8.8'), indent: '  ')
end

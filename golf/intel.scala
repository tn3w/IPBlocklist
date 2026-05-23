import java.math.BigInteger
import java.net.InetAddress
import java.nio.{ByteBuffer, ByteOrder}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util.Locale
import scala.collection.mutable

val FLAGS = Vector("vpn","proxy","tor","malware","c2","scanner","brute_force",
  "spammer","compromised","datacenter","cdn","anycast","crawler","bot","cloud",
  "private_relay","anonymizer","mobile","isp","government")
val SEV = Vector(30.0,25.0,45.0,95.0,95.0,55.0,70.0,65.0,75.0,15.0,
  5.0,0.0,10.0,40.0,10.0,15.0,35.0,0.0,0.0,0.0)
val LEVELS = Vector(80.0 -> "critical", 60.0 -> "high", 35.0 -> "medium", 15.0 -> "low")

case class Match(source: String, provider: String, range: String,
                 flags: Vector[String], weight: Double)

class DB(
  val v4s: Array[Long], val v4e: Array[Long], val v4v: Array[Int], val v4m: Array[Long],
  val v6s: Array[BigInteger], val v6e: Array[BigInteger],
  val v6v: Array[Int], val v6m: Array[BigInteger],
  val vt: Array[Array[Long]], val strings: Array[String], val weights: Array[Double]
)

def u64BI(v: Long): BigInteger =
  var r = BigInteger.valueOf(v & 0x7FFFFFFFFFFFFFFFL)
  if v < 0 then r = r.setBit(63)
  r

def load(path: String): DB =
  val data = Files.readAllBytes(Paths.get(path))
  val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
  if b.getInt(0) != 6 then sys.error("unsupported version")
  val h = Array.tabulate(19)(i => b.getLong(8 + i * 8))
  val cn = h(0).toInt; val ln = h(1).toInt; val v6n = h(2).toInt
  val valn = h(3).toInt; val strn = h(4).toInt
  val oBucket = h(5).toInt; val oSLo = h(6).toInt; val oLens = h(7).toInt
  val oVals = h(8).toInt; val oLs = h(9).toInt; val oLe = h(10).toInt
  val oLv = h(11).toInt; val oV6s = h(12).toInt; val oV6e = h(13).toInt
  val oV6v = h(14).toInt; val oVt = h(15).toInt; val oSi = h(16).toInt
  val oSd = h(17).toInt

  val bi = Array.tabulate(65537)(i => b.getInt(oBucket + i * 4).toLong & 0xFFFFFFFFL)
  val N = cn + ln
  val starts = new Array[Long](N)
  val ends = new Array[Long](N)
  val vals = new Array[Int](N)
  var j = 0L
  var bk = 0
  while bk < 65536 do
    while j < bi(bk + 1) do
      val idx = j.toInt
      val lo = b.getShort(oSLo + idx * 2).toInt & 0xFFFF
      val s = (bk.toLong << 16) | lo.toLong
      starts(idx) = s
      ends(idx) = s + (b.getShort(oLens + idx * 2).toInt & 0xFFFF)
      vals(idx) = b.getShort(oVals + idx * 2).toInt & 0xFFFF
      j += 1
    bk += 1
  var i = 0
  while i < ln do
    starts(cn + i) = b.getInt(oLs + i * 4).toLong & 0xFFFFFFFFL
    ends(cn + i) = b.getInt(oLe + i * 4).toLong & 0xFFFFFFFFL
    vals(cn + i) = b.getShort(oLv + i * 2).toInt & 0xFFFF
    i += 1

  val order = (0 until N).sortBy(starts(_))
  val s2 = order.map(starts).toArray
  val e2 = order.map(ends).toArray
  val v2 = order.map(vals).toArray
  val m4 = new Array[Long](N)
  var mx = 0L
  i = 0
  while i < N do
    if e2(i) > mx then mx = e2(i)
    m4(i) = mx
    i += 1

  val v6s = Array.tabulate(v6n)(k =>
    u64BI(b.getLong(oV6s + k * 16 + 8)).shiftLeft(64)
      .or(u64BI(b.getLong(oV6s + k * 16))))
  val v6e = Array.tabulate(v6n)(k =>
    u64BI(b.getLong(oV6e + k * 16 + 8)).shiftLeft(64)
      .or(u64BI(b.getLong(oV6e + k * 16))))
  val v6v = Array.tabulate(v6n)(k => b.getShort(oV6v + k * 2).toInt & 0xFFFF)
  val v6m = new Array[BigInteger](v6n)
  var m6 = BigInteger.ZERO
  i = 0
  while i < v6n do
    if v6e(i).compareTo(m6) > 0 then m6 = v6e(i)
    v6m(i) = m6
    i += 1

  val vt = Array.tabulate(valn)(idx =>
    Array.tabulate(4)(k => b.getInt(oVt + (idx * 4 + k) * 4).toLong & 0xFFFFFFFFL))
  val strings = Array.tabulate(strn) { idx =>
    val so = (b.getInt(oSi + idx * 8).toLong & 0xFFFFFFFFL).toInt
    val sl = (b.getInt(oSi + idx * 8 + 4).toLong & 0xFFFFFFFFL).toInt
    new String(data, oSd + so, sl, StandardCharsets.UTF_8)
  }

  val weights = new Array[Double](20)
  if N > 0 then
    val cnt = new Array[Int](20)
    for vid <- v2 do
      val bits = vt(vid)(0)
      var k = 0
      while k < 20 do
        if (bits & (1L << k)) != 0L then cnt(k) += 1
        k += 1
    var k = 0
    while k < 20 do
      val cc = if cnt(k) == 0 then 1 else cnt(k)
      weights(k) = SEV(k) * (1 + math.log(N.toDouble / cc) / math.log(2) / 24)
      k += 1
  else
    SEV.copyToArray(weights)

  new DB(s2, e2, v2, m4, v6s, v6e, v6v, v6m, vt, strings, weights)

def r1(x: Double): Double = math.round(x * 10) / 10.0

def v4str(ip: Long): String =
  s"${(ip >> 24) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 8) & 0xFF}.${ip & 0xFF}"

def v6str(ip: BigInteger): String =
  val full = new Array[Byte](16)
  val raw = ip.toByteArray
  val copy = math.min(raw.length, 16)
  System.arraycopy(raw, raw.length - copy, full, 16 - copy, copy)
  InetAddress.getByAddress(full).getHostAddress

def buildMatch(db: DB, vid: Int, range: String): Match =
  val bits = db.vt(vid)(0)
  val fl = mutable.ArrayBuffer.empty[String]
  var mxw = 0.0
  var i = 0
  while i < 20 do
    if (bits & (1L << i)) != 0L then
      fl += FLAGS(i)
      if db.weights(i) > mxw then mxw = db.weights(i)
    i += 1
  Match(db.strings(db.vt(vid)(2).toInt), db.strings(db.vt(vid)(1).toInt),
    range, fl.toVector, r1(mxw))

def upperBoundL(arr: Array[Long], key: Long): Int =
  var lo = 0; var hi = arr.length
  while lo < hi do
    val mid = (lo + hi) >>> 1
    if arr(mid) <= key then lo = mid + 1 else hi = mid
  lo

def upperBoundB(arr: Array[BigInteger], key: BigInteger): Int =
  var lo = 0; var hi = arr.length
  while lo < hi do
    val mid = (lo + hi) >>> 1
    if arr(mid).compareTo(key) <= 0 then lo = mid + 1 else hi = mid
  lo

def lookup(db: DB, ipStr: String): String =
  val addr = InetAddress.getByName(ipStr)
  val raw = addr.getAddress
  val matches = mutable.ArrayBuffer.empty[Match]
  if raw.length == 4 then
    var ip = 0L
    for v <- raw do ip = (ip << 8) | (v.toLong & 0xFF)
    var i = upperBoundL(db.v4s, ip)
    var stop = false
    while i > 0 && !stop do
      i -= 1
      if db.v4m(i) < ip then stop = true
      else if db.v4e(i) >= ip then
        matches += buildMatch(db, db.v4v(i),
          s"${v4str(db.v4s(i))}-${v4str(db.v4e(i))}")
  else
    val ip = new BigInteger(1, raw)
    var i = upperBoundB(db.v6s, ip)
    var stop = false
    while i > 0 && !stop do
      i -= 1
      if db.v6m(i).compareTo(ip) < 0 then stop = true
      else if db.v6e(i).compareTo(ip) >= 0 then
        matches += buildMatch(db, db.v6v(i),
          s"${v6str(db.v6s(i))}-${v6str(db.v6e(i))}")
  val sorted = matches.sortBy(-_.weight).toVector

  val allFlags = mutable.LinkedHashSet.empty[String]
  val providers = mutable.LinkedHashSet.empty[String]
  val srcs = mutable.LinkedHashSet.empty[String]
  val rankedSet = mutable.LinkedHashSet.empty[String]
  for m <- sorted do
    for f <- m.flags do
      allFlags += f
      rankedSet += f
    if m.provider.nonEmpty then providers += m.provider
    srcs += s"${m.provider}|${m.source}"
  val flagIdx = FLAGS.zipWithIndex.toMap
  val ranked = rankedSet.toVector.sortBy(f => -db.weights(flagIdx(f)))

  val score =
    if ranked.isEmpty then 0.0
    else
      val top = db.weights(flagIdx(ranked.head))
      val ex = ranked.tail.map(f => db.weights(flagIdx(f))).sum
      r1(math.min(100.0, (top + ex * 0.15) *
        (1 + 0.08 * math.log(srcs.size + 1.0) / math.log(2))))

  val verdict =
    if sorted.isEmpty then "clean"
    else LEVELS.find((t, _) => score >= t).map(_._2).getOrElse("minimal")

  val provList = mutable.ArrayBuffer.from(providers)
  if provList.exists(_.equalsIgnoreCase("tor")) then
    val filtered = provList.filterNot(_.equalsIgnoreCase("tor"))
    provList.clear()
    provList += "Tor"
    provList ++= filtered
  val reasons = ranked.take(5)
  val topProv = provList.headOption.getOrElse("")

  val sb = StringBuilder()
  sb ++= "{\n"
  sb ++= s"  \"ip\": ${jstr(ipStr)},\n"
  sb ++= s"  \"found\": ${sorted.nonEmpty},\n"
  sb ++= s"  \"verdict\": ${jstr(verdict)},\n"
  sb ++= s"  \"score\": ${num(score)},\n"
  sb ++= s"  \"detections\": ${sorted.size},\n"
  sb ++= s"  \"sources\": ${srcs.size},\n"
  sb ++= s"  \"top_provider\": ${jstr(topProv)},\n"
  sb ++= s"  \"providers\": ${jarr(provList.toVector, "  ")},\n"
  sb ++= s"  \"flags\": ${jarr(allFlags.toVector, "  ")},\n"
  sb ++= s"  \"reasons\": ${jarr(reasons, "  ")},\n"
  sb ++= s"  \"matches\": ${jmatches(sorted, "  ")}\n"
  sb ++= "}"
  sb.toString

def num(d: Double): String =
  if d == d.toLong.toDouble then s"${d.toLong}.0"
  else String.format(Locale.ROOT, "%.1f", d)

def jstr(s: String): String =
  val b = StringBuilder("\"")
  for c <- s do c match
    case '"' => b ++= "\\\""
    case '\\' => b ++= "\\\\"
    case '\n' => b ++= "\\n"
    case '\r' => b ++= "\\r"
    case '\t' => b ++= "\\t"
    case '\b' => b ++= "\\b"
    case '\f' => b ++= "\\f"
    case c if c < 0x20 => b ++= "\\u" + f"${c.toInt}%04x"
    case c => b += c
  b += '"'
  b.toString

def jarr(items: Vector[String], indent: String): String =
  if items.isEmpty then "[]"
  else
    val inner = indent + "  "
    items.map(s => s"$inner${jstr(s)}").mkString("[\n", ",\n", s"\n$indent]")

def jmatches(ms: Vector[Match], indent: String): String =
  if ms.isEmpty then "[]"
  else
    val inner = indent + "  "
    val deep = inner + "  "
    ms.map { m =>
      s"$inner{\n" +
      s"$deep\"source\": ${jstr(m.source)},\n" +
      s"$deep\"provider\": ${jstr(m.provider)},\n" +
      s"$deep\"range\": ${jstr(m.range)},\n" +
      s"$deep\"flags\": ${jarr(m.flags, deep)},\n" +
      s"$deep\"weight\": ${num(m.weight)}\n" +
      s"$inner}"
    }.mkString("[\n", ",\n", s"\n$indent]")

@main def Intel(args: String*): Unit =
  val ip = if args.nonEmpty then args(0) else "8.8.8.8"
  val db = load("../intel.bin")
  println(lookup(db, ip))

import java.math.BigInteger
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Paths
import java.util.Locale
import kotlin.math.ln
import kotlin.math.min
import kotlin.math.round

val FLAGS = listOf("vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
    "compromised","datacenter","cdn","anycast","crawler","bot","cloud","private_relay",
    "anonymizer","mobile","isp","government")
val SEV = doubleArrayOf(30.0,25.0,45.0,95.0,95.0,55.0,70.0,65.0,75.0,15.0,
    5.0,0.0,10.0,40.0,10.0,15.0,35.0,0.0,0.0,0.0)
val LEVELS = listOf(80.0 to "critical", 60.0 to "high", 35.0 to "medium", 15.0 to "low")

data class Match(val source: String, val provider: String, val range: String,
                 val flags: List<String>, val weight: Double)

class DB(
    val v4s: LongArray, val v4e: LongArray, val v4v: IntArray, val v4m: LongArray,
    val v6s: Array<BigInteger>, val v6e: Array<BigInteger>, val v6v: IntArray,
    val v6m: Array<BigInteger>, val vt: Array<LongArray>, val strings: Array<String>,
    val weights: DoubleArray
)

fun u64BI(v: Long): BigInteger {
    var r = BigInteger.valueOf(v and 0x7FFFFFFFFFFFFFFFL)
    if (v < 0) r = r.setBit(63)
    return r
}

fun load(path: String): DB {
    val data = Files.readAllBytes(Paths.get(path))
    val b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
    if (b.getInt(0) != 6) error("unsupported version")
    val h = LongArray(19) { b.getLong(8 + it * 8) }
    val cn = h[0].toInt(); val ln = h[1].toInt(); val v6n = h[2].toInt()
    val valn = h[3].toInt(); val strn = h[4].toInt()
    val oBucket = h[5].toInt(); val oSLo = h[6].toInt(); val oLens = h[7].toInt()
    val oVals = h[8].toInt(); val oLs = h[9].toInt(); val oLe = h[10].toInt()
    val oLv = h[11].toInt(); val oV6s = h[12].toInt(); val oV6e = h[13].toInt()
    val oV6v = h[14].toInt(); val oVt = h[15].toInt(); val oSi = h[16].toInt()
    val oSd = h[17].toInt()

    val bi = LongArray(65537) { (b.getInt(oBucket + it * 4).toLong()) and 0xFFFFFFFFL }
    val N = cn + ln
    val starts = LongArray(N); val ends = LongArray(N); val vals = IntArray(N)
    var j = 0L
    for (bk in 0 until 65536) {
        while (j < bi[bk + 1]) {
            val idx = j.toInt()
            val lo = (b.getShort(oSLo + idx * 2).toInt() and 0xFFFF).toLong()
            val s = (bk.toLong() shl 16) or lo
            starts[idx] = s
            ends[idx] = s + (b.getShort(oLens + idx * 2).toInt() and 0xFFFF)
            vals[idx] = b.getShort(oVals + idx * 2).toInt() and 0xFFFF
            j++
        }
    }
    for (i in 0 until ln) {
        starts[cn + i] = (b.getInt(oLs + i * 4).toLong()) and 0xFFFFFFFFL
        ends[cn + i] = (b.getInt(oLe + i * 4).toLong()) and 0xFFFFFFFFL
        vals[cn + i] = b.getShort(oLv + i * 2).toInt() and 0xFFFF
    }

    val order = (0 until N).sortedBy { starts[it] }
    val s2 = LongArray(N) { starts[order[it]] }
    val e2 = LongArray(N) { ends[order[it]] }
    val v2 = IntArray(N) { vals[order[it]] }
    val m4 = LongArray(N)
    var mx = 0L
    for (i in 0 until N) { if (e2[i] > mx) mx = e2[i]; m4[i] = mx }

    val v6s = Array(v6n) {
        u64BI(b.getLong(oV6s + it * 16 + 8)).shiftLeft(64)
            .or(u64BI(b.getLong(oV6s + it * 16)))
    }
    val v6e = Array(v6n) {
        u64BI(b.getLong(oV6e + it * 16 + 8)).shiftLeft(64)
            .or(u64BI(b.getLong(oV6e + it * 16)))
    }
    val v6v = IntArray(v6n) { b.getShort(oV6v + it * 2).toInt() and 0xFFFF }
    val v6m = Array(v6n) { BigInteger.ZERO }
    var m6 = BigInteger.ZERO
    for (i in 0 until v6n) { if (v6e[i] > m6) m6 = v6e[i]; v6m[i] = m6 }

    val vt = Array(valn) { i ->
        LongArray(4) { k -> (b.getInt(oVt + (i * 4 + k) * 4).toLong()) and 0xFFFFFFFFL }
    }
    val strings = Array(strn) {
        val so = (b.getInt(oSi + it * 8).toLong() and 0xFFFFFFFFL).toInt()
        val sl = (b.getInt(oSi + it * 8 + 4).toLong() and 0xFFFFFFFFL).toInt()
        String(data, oSd + so, sl, Charsets.UTF_8)
    }

    val weights = DoubleArray(20)
    if (N > 0) {
        val cnt = IntArray(20)
        for (vid in v2) {
            val bits = vt[vid][0]
            for (i in 0 until 20) if ((bits and (1L shl i)) != 0L) cnt[i]++
        }
        for (i in 0 until 20) {
            val cc = if (cnt[i] == 0) 1 else cnt[i]
            weights[i] = SEV[i] * (1 + ln(N.toDouble() / cc) / ln(2.0) / 24)
        }
    } else SEV.copyInto(weights)

    return DB(s2, e2, v2, m4, v6s, v6e, v6v, v6m, vt, strings, weights)
}

fun r1(x: Double) = round(x * 10) / 10.0

fun v4str(ip: Long) = "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}." +
    "${(ip shr 8) and 0xFF}.${ip and 0xFF}"

fun v6str(ip: BigInteger): String {
    val full = ByteArray(16)
    val raw = ip.toByteArray()
    val copy = min(raw.size, 16)
    System.arraycopy(raw, raw.size - copy, full, 16 - copy, copy)
    return InetAddress.getByAddress(full).hostAddress
}

fun buildMatch(db: DB, vid: Int, range: String): Match {
    val bits = db.vt[vid][0]
    val fl = mutableListOf<String>()
    var mxw = 0.0
    for (i in 0 until 20) {
        if ((bits and (1L shl i)) != 0L) {
            fl.add(FLAGS[i])
            if (db.weights[i] > mxw) mxw = db.weights[i]
        }
    }
    return Match(db.strings[db.vt[vid][2].toInt()],
        db.strings[db.vt[vid][1].toInt()], range, fl, r1(mxw))
}

fun upperBoundL(arr: LongArray, key: Long): Int {
    var lo = 0; var hi = arr.size
    while (lo < hi) {
        val mid = (lo + hi) ushr 1
        if (arr[mid] <= key) lo = mid + 1 else hi = mid
    }
    return lo
}

fun upperBoundB(arr: Array<BigInteger>, key: BigInteger): Int {
    var lo = 0; var hi = arr.size
    while (lo < hi) {
        val mid = (lo + hi) ushr 1
        if (arr[mid] <= key) lo = mid + 1 else hi = mid
    }
    return lo
}

fun lookup(db: DB, ipStr: String): String {
    val addr = InetAddress.getByName(ipStr)
    val raw = addr.address
    val matches = mutableListOf<Match>()
    if (raw.size == 4) {
        var ip = 0L
        for (v in raw) ip = (ip shl 8) or (v.toLong() and 0xFF)
        var i = upperBoundL(db.v4s, ip)
        while (i > 0) {
            i--
            if (db.v4m[i] < ip) break
            if (db.v4e[i] >= ip) matches.add(buildMatch(db, db.v4v[i],
                "${v4str(db.v4s[i])}-${v4str(db.v4e[i])}"))
        }
    } else {
        val ip = BigInteger(1, raw)
        var i = upperBoundB(db.v6s, ip)
        while (i > 0) {
            i--
            if (db.v6m[i] < ip) break
            if (db.v6e[i] >= ip) matches.add(buildMatch(db, db.v6v[i],
                "${v6str(db.v6s[i])}-${v6str(db.v6e[i])}"))
        }
    }
    matches.sortByDescending { it.weight }

    val allFlags = LinkedHashSet<String>()
    val providers = LinkedHashSet<String>()
    val srcs = LinkedHashSet<String>()
    val rankedSet = LinkedHashSet<String>()
    for (m in matches) {
        for (f in m.flags) { allFlags.add(f); rankedSet.add(f) }
        if (m.provider.isNotEmpty()) providers.add(m.provider)
        srcs.add("${m.provider}|${m.source}")
    }
    val flagIdx = FLAGS.withIndex().associate { (i, f) -> f to i }
    val ranked = rankedSet.sortedByDescending { db.weights[flagIdx[it]!!] }

    var score = 0.0
    if (ranked.isNotEmpty()) {
        val top = db.weights[flagIdx[ranked[0]]!!]
        val ex = ranked.drop(1).sumOf { db.weights[flagIdx[it]!!] }
        score = r1(min(100.0, (top + ex * 0.15) *
            (1 + 0.08 * ln(srcs.size + 1.0) / ln(2.0))))
    }
    var verdict = "clean"
    if (matches.isNotEmpty()) {
        verdict = "minimal"
        for ((t, name) in LEVELS) if (score >= t) { verdict = name; break }
    }

    val provList = providers.toMutableList()
    if (provList.any { it.equals("tor", true) }) {
        provList.removeAll { it.equals("tor", true) }
        provList.add(0, "Tor")
    }
    val reasons = ranked.take(5)
    val topProv = provList.firstOrNull() ?: ""

    return buildString {
        append("{\n")
        append("  \"ip\": ").append(jstr(ipStr)).append(",\n")
        append("  \"found\": ").append(matches.isNotEmpty()).append(",\n")
        append("  \"verdict\": ").append(jstr(verdict)).append(",\n")
        append("  \"score\": ").append(num(score)).append(",\n")
        append("  \"detections\": ").append(matches.size).append(",\n")
        append("  \"sources\": ").append(srcs.size).append(",\n")
        append("  \"top_provider\": ").append(jstr(topProv)).append(",\n")
        append("  \"providers\": ").append(jarr(provList, "  ")).append(",\n")
        append("  \"flags\": ").append(jarr(allFlags.toList(), "  ")).append(",\n")
        append("  \"reasons\": ").append(jarr(reasons, "  ")).append(",\n")
        append("  \"matches\": ").append(jmatches(matches, "  ")).append("\n")
        append("}")
    }
}

fun num(d: Double): String =
    if (d == d.toLong().toDouble()) "${d.toLong()}.0"
    else "%.1f".format(Locale.ROOT, d)

fun jstr(s: String): String {
    val b = StringBuilder("\"")
    for (c in s) when (c.code) {
        0x22 -> b.append("\\\"")
        0x5C -> b.append("\\\\")
        0x0A -> b.append("\\n")
        0x0D -> b.append("\\r")
        0x09 -> b.append("\\t")
        0x08 -> b.append("\\b")
        0x0C -> b.append("\\f")
        else -> if (c.code < 0x20) b.append("\\u%04x".format(c.code)) else b.append(c)
    }
    return b.append("\"").toString()
}

fun jarr(items: List<String>, indent: String): String {
    if (items.isEmpty()) return "[]"
    val inner = "$indent  "
    return items.joinToString(",\n", "[\n", "\n$indent]") { "$inner${jstr(it)}" }
}

fun jmatches(ms: List<Match>, indent: String): String {
    if (ms.isEmpty()) return "[]"
    val inner = "$indent  "
    val deep = "$inner  "
    return ms.joinToString(",\n", "[\n", "\n$indent]") { m ->
        "$inner{\n" +
        "$deep\"source\": ${jstr(m.source)},\n" +
        "$deep\"provider\": ${jstr(m.provider)},\n" +
        "$deep\"range\": ${jstr(m.range)},\n" +
        "$deep\"flags\": ${jarr(m.flags, deep)},\n" +
        "$deep\"weight\": ${num(m.weight)}\n" +
        "$inner}"
    }
}

fun main(args: Array<String>) {
    val ip = if (args.isNotEmpty()) args[0] else "8.8.8.8"
    val db = load("../intel.bin")
    println(lookup(db, ip))
}

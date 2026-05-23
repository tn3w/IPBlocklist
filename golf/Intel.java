import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;

public class Intel {
    static final String[] FLAGS = {"vpn","proxy","tor","malware","c2","scanner",
        "brute_force","spammer","compromised","datacenter","cdn","anycast","crawler",
        "bot","cloud","private_relay","anonymizer","mobile","isp","government"};
    static final double[] SEV = {30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0};
    static final Object[][] LEVELS = {{80.0,"critical"},{60.0,"high"},{35.0,"medium"},{15.0,"low"}};
    static final BigInteger U64 = BigInteger.ONE.shiftLeft(64);

    static class Match {
        String source, provider, range;
        List<String> flags;
        double weight;
    }

    static class DB {
        long[] v4s, v4e, v4m;
        int[] v4v;
        BigInteger[] v6s, v6e, v6m;
        int[] v6v;
        long[][] vt;
        String[] strings;
        double[] weights = new double[20];
    }

    static long u32(ByteBuffer b, int off) { return b.getInt(off) & 0xFFFFFFFFL; }
    static int u16(ByteBuffer b, int off) { return b.getShort(off) & 0xFFFF; }
    static long u64(ByteBuffer b, int off) { return b.getLong(off); }

    static BigInteger u64BI(long v) {
        BigInteger r = BigInteger.valueOf(v & 0x7FFFFFFFFFFFFFFFL);
        if (v < 0) r = r.setBit(63);
        return r;
    }

    static DB load(String path) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));
        ByteBuffer b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        if (b.getInt(0) != 6) throw new RuntimeException("unsupported version");
        long[] hdr = new long[19];
        for (int i = 0; i < 19; i++) hdr[i] = b.getLong(8 + i * 8);
        int cn = (int) hdr[0], ln = (int) hdr[1], v6n = (int) hdr[2];
        int valn = (int) hdr[3], strn = (int) hdr[4];
        int oBucket = (int) hdr[5], oSLo = (int) hdr[6], oLens = (int) hdr[7];
        int oVals = (int) hdr[8], oLs = (int) hdr[9], oLe = (int) hdr[10];
        int oLv = (int) hdr[11], oV6s = (int) hdr[12], oV6e = (int) hdr[13];
        int oV6v = (int) hdr[14], oVt = (int) hdr[15], oSi = (int) hdr[16];
        int oSd = (int) hdr[17];

        long[] bi = new long[65537];
        for (int i = 0; i < 65537; i++) bi[i] = u32(b, oBucket + i * 4);

        int N = cn + ln;
        long[] starts = new long[N], ends = new long[N];
        int[] vals = new int[N];
        long j = 0;
        for (int bk = 0; bk < 65536; bk++) {
            while (j < bi[bk + 1]) {
                int idx = (int) j;
                long lo = u16(b, oSLo + idx * 2);
                long s = ((long) bk << 16) | lo;
                starts[idx] = s;
                ends[idx] = s + u16(b, oLens + idx * 2);
                vals[idx] = u16(b, oVals + idx * 2);
                j++;
            }
        }
        for (int i = 0; i < ln; i++) {
            starts[cn + i] = u32(b, oLs + i * 4);
            ends[cn + i] = u32(b, oLe + i * 4);
            vals[cn + i] = u16(b, oLv + i * 2);
        }

        Integer[] idx = new Integer[N];
        for (int i = 0; i < N; i++) idx[i] = i;
        long[] sArr = starts;
        Arrays.sort(idx, (a, c) -> Long.compare(sArr[a], sArr[c]));
        long[] s2 = new long[N], e2 = new long[N];
        int[] v2 = new int[N];
        for (int i = 0; i < N; i++) {
            s2[i] = starts[idx[i]];
            e2[i] = ends[idx[i]];
            v2[i] = vals[idx[i]];
        }

        DB db = new DB();
        db.v4s = s2; db.v4e = e2; db.v4v = v2;
        db.v4m = new long[N];
        long mx = 0;
        for (int i = 0; i < N; i++) {
            if (e2[i] > mx) mx = e2[i];
            db.v4m[i] = mx;
        }

        db.v6s = new BigInteger[v6n];
        db.v6e = new BigInteger[v6n];
        db.v6v = new int[v6n];
        for (int i = 0; i < v6n; i++) {
            db.v6s[i] = u64BI(u64(b, oV6s + i * 16 + 8)).shiftLeft(64)
                .or(u64BI(u64(b, oV6s + i * 16)));
            db.v6e[i] = u64BI(u64(b, oV6e + i * 16 + 8)).shiftLeft(64)
                .or(u64BI(u64(b, oV6e + i * 16)));
            db.v6v[i] = u16(b, oV6v + i * 2);
        }
        db.v6m = new BigInteger[v6n];
        BigInteger m6 = BigInteger.ZERO;
        for (int i = 0; i < v6n; i++) {
            if (db.v6e[i].compareTo(m6) > 0) m6 = db.v6e[i];
            db.v6m[i] = m6;
        }

        db.vt = new long[valn][4];
        for (int i = 0; i < valn; i++)
            for (int k = 0; k < 4; k++)
                db.vt[i][k] = u32(b, oVt + (i * 4 + k) * 4);

        db.strings = new String[strn];
        for (int i = 0; i < strn; i++) {
            int so = (int) u32(b, oSi + i * 8);
            int sl = (int) u32(b, oSi + i * 8 + 4);
            db.strings[i] = new String(data, oSd + so, sl, java.nio.charset.StandardCharsets.UTF_8);
        }

        if (N > 0) {
            int[] cnt = new int[20];
            for (int vid : v2) {
                long bits = db.vt[vid][0];
                for (int i = 0; i < 20; i++) if ((bits & (1L << i)) != 0) cnt[i]++;
            }
            for (int i = 0; i < 20; i++) {
                int cc = cnt[i] == 0 ? 1 : cnt[i];
                db.weights[i] = SEV[i] * (1 + Math.log((double) N / cc) / Math.log(2) / 24);
            }
        } else {
            System.arraycopy(SEV, 0, db.weights, 0, 20);
        }
        return db;
    }

    static double r1(double x) { return Math.round(x * 10) / 10.0; }

    static String v4str(long ip) {
        return ((ip >> 24) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "."
            + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    static String v6str(BigInteger ip) throws Exception {
        byte[] full = new byte[16];
        byte[] raw = ip.toByteArray();
        int copy = Math.min(raw.length, 16);
        System.arraycopy(raw, raw.length - copy, full, 16 - copy, copy);
        return InetAddress.getByAddress(full).getHostAddress();
    }

    static Match buildMatch(DB db, int vid, String range) {
        long bits = db.vt[vid][0];
        List<String> fl = new ArrayList<>();
        double mxw = 0;
        for (int i = 0; i < 20; i++) {
            if ((bits & (1L << i)) != 0) {
                fl.add(FLAGS[i]);
                if (db.weights[i] > mxw) mxw = db.weights[i];
            }
        }
        Match m = new Match();
        m.source = db.strings[(int) db.vt[vid][2]];
        m.provider = db.strings[(int) db.vt[vid][1]];
        m.range = range;
        m.flags = fl;
        m.weight = r1(mxw);
        return m;
    }

    static int upperBoundV4(long[] arr, long key) {
        int lo = 0, hi = arr.length;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (arr[mid] <= key) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    static int upperBoundV6(BigInteger[] arr, BigInteger key) {
        int lo = 0, hi = arr.length;
        while (lo < hi) {
            int mid = (lo + hi) >>> 1;
            if (arr[mid].compareTo(key) <= 0) lo = mid + 1;
            else hi = mid;
        }
        return lo;
    }

    static String lookup(DB db, String ipStr) throws Exception {
        InetAddress addr = InetAddress.getByName(ipStr);
        byte[] raw = addr.getAddress();
        List<Match> matches = new ArrayList<>();
        if (raw.length == 4) {
            long ip = 0;
            for (byte v : raw) ip = (ip << 8) | (v & 0xFF);
            int i = upperBoundV4(db.v4s, ip);
            while (i > 0) {
                i--;
                if (db.v4m[i] < ip) break;
                if (db.v4e[i] >= ip)
                    matches.add(buildMatch(db, db.v4v[i],
                        v4str(db.v4s[i]) + "-" + v4str(db.v4e[i])));
            }
        } else {
            BigInteger ip = new BigInteger(1, raw);
            int i = upperBoundV6(db.v6s, ip);
            while (i > 0) {
                i--;
                if (db.v6m[i].compareTo(ip) < 0) break;
                if (db.v6e[i].compareTo(ip) >= 0)
                    matches.add(buildMatch(db, db.v6v[i],
                        v6str(db.v6s[i]) + "-" + v6str(db.v6e[i])));
            }
        }
        matches.sort((a, c) -> Double.compare(c.weight, a.weight));

        LinkedHashSet<String> allFlags = new LinkedHashSet<>();
        LinkedHashSet<String> providers = new LinkedHashSet<>();
        LinkedHashSet<String> srcs = new LinkedHashSet<>();
        LinkedHashMap<String, Integer> flagIdx = new LinkedHashMap<>();
        for (int i = 0; i < 20; i++) flagIdx.put(FLAGS[i], i);
        LinkedHashSet<String> rankedSet = new LinkedHashSet<>();
        for (Match m : matches) {
            for (String f : m.flags) { allFlags.add(f); rankedSet.add(f); }
            if (!m.provider.isEmpty()) providers.add(m.provider);
            srcs.add(m.provider + "|" + m.source);
        }
        List<String> ranked = new ArrayList<>(rankedSet);
        ranked.sort((a, c) -> Double.compare(db.weights[flagIdx.get(c)], db.weights[flagIdx.get(a)]));

        double score = 0;
        if (!ranked.isEmpty()) {
            double top = db.weights[flagIdx.get(ranked.get(0))];
            double ex = 0;
            for (int k = 1; k < ranked.size(); k++) ex += db.weights[flagIdx.get(ranked.get(k))];
            score = r1(Math.min(100, (top + ex * 0.15)
                * (1 + 0.08 * Math.log(srcs.size() + 1) / Math.log(2))));
        }
        String verdict = "clean";
        if (!matches.isEmpty()) {
            verdict = "minimal";
            for (Object[] lv : LEVELS) {
                if (score >= (double) lv[0]) { verdict = (String) lv[1]; break; }
            }
        }

        List<String> provList = new ArrayList<>(providers);
        boolean hasTor = provList.stream().anyMatch(p -> p.equalsIgnoreCase("tor"));
        if (hasTor) {
            provList.removeIf(p -> p.equalsIgnoreCase("tor"));
            provList.add(0, "Tor");
        }
        List<String> reasons = ranked.subList(0, Math.min(5, ranked.size()));
        String topProv = provList.isEmpty() ? "" : provList.get(0);

        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"ip\": ").append(jstr(ipStr)).append(",\n");
        sb.append("  \"found\": ").append(!matches.isEmpty()).append(",\n");
        sb.append("  \"verdict\": ").append(jstr(verdict)).append(",\n");
        sb.append("  \"score\": ").append(num(score)).append(",\n");
        sb.append("  \"detections\": ").append(matches.size()).append(",\n");
        sb.append("  \"sources\": ").append(srcs.size()).append(",\n");
        sb.append("  \"top_provider\": ").append(jstr(topProv)).append(",\n");
        sb.append("  \"providers\": ").append(jarr(provList, "  ")).append(",\n");
        sb.append("  \"flags\": ").append(jarr(new ArrayList<>(allFlags), "  ")).append(",\n");
        sb.append("  \"reasons\": ").append(jarr(reasons, "  ")).append(",\n");
        sb.append("  \"matches\": ").append(jmatches(matches, "  ")).append("\n");
        sb.append("}");
        return sb.toString();
    }

    static String num(double d) {
        if (d == Math.floor(d) && !Double.isInfinite(d)) {
            long l = (long) d;
            if (l == d) return l + ".0";
        }
        String s = String.valueOf(d);
        return s;
    }

    static String jstr(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') b.append("\\\"");
            else if (c == '\\') b.append("\\\\");
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c == '\b') b.append("\\b");
            else if (c == '\f') b.append("\\f");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append("\"").toString();
    }

    static String jarr(List<String> items, String indent) {
        if (items.isEmpty()) return "[]";
        StringBuilder b = new StringBuilder("[\n");
        String inner = indent + "  ";
        for (int i = 0; i < items.size(); i++) {
            b.append(inner).append(jstr(items.get(i)));
            if (i < items.size() - 1) b.append(",");
            b.append("\n");
        }
        return b.append(indent).append("]").toString();
    }

    static String jmatches(List<Match> ms, String indent) {
        if (ms.isEmpty()) return "[]";
        StringBuilder b = new StringBuilder("[\n");
        String inner = indent + "  ";
        String deep = inner + "  ";
        for (int i = 0; i < ms.size(); i++) {
            Match m = ms.get(i);
            b.append(inner).append("{\n");
            b.append(deep).append("\"source\": ").append(jstr(m.source)).append(",\n");
            b.append(deep).append("\"provider\": ").append(jstr(m.provider)).append(",\n");
            b.append(deep).append("\"range\": ").append(jstr(m.range)).append(",\n");
            b.append(deep).append("\"flags\": ").append(jarr(m.flags, deep)).append(",\n");
            b.append(deep).append("\"weight\": ").append(num(m.weight)).append("\n");
            b.append(inner).append("}");
            if (i < ms.size() - 1) b.append(",");
            b.append("\n");
        }
        return b.append(indent).append("]").toString();
    }

    public static void main(String[] args) throws Exception {
        String ip = args.length > 0 ? args[0] : "8.8.8.8";
        DB db = load("../intel.bin");
        System.out.println(lookup(db, ip));
    }
}

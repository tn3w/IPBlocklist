using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

static class C
{
    public static readonly string[] FLAGS = "vpn proxy tor malware c2 scanner brute_force spammer compromised datacenter cdn anycast crawler bot cloud private_relay anonymizer mobile isp government".Split();
    public static readonly double[] SEV = { 30, 25, 45, 95, 95, 55, 70, 65, 75, 15, 5, 0, 10, 40, 10, 15, 35, 0, 0, 0 };
    public static readonly (double t, string n)[] LEVELS = { (80, "critical"), (60, "high"), (35, "medium"), (15, "low") };
}

class DB
{
    public uint[] V4s, V4e, V4m;
    public ushort[] V4v, V6v;
    public UInt128[] V6s, V6e, V6m;
    public uint[][] Vt;
    public string[] St;
    public double[] W = new double[20];
}

static class Loader
{
    static ushort U16(byte[] d, long o) => BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan((int)o));
    static uint U32(byte[] d, long o) => BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan((int)o));
    static ulong U64(byte[] d, long o) => BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan((int)o));

    public static DB Load(string path)
    {
        var d = File.ReadAllBytes(path);
        if (U32(d, 0) != 6) throw new Exception("version");
        var o = new long[19];
        for (int i = 0; i < 19; i++) o[i] = (long)U64(d, 8 + i * 8);
        int cn = (int)o[0], ln = (int)o[1], v6n = (int)o[2], valn = (int)o[3], strn = (int)o[4];
        long bucket = o[5], starts_lo = o[6], lens = o[7], vals = o[8];
        long lstarts = o[9], lends = o[10], lvals = o[11];
        long v6sO = o[12], v6eO = o[13], v6vO = o[14];
        long vtO = o[15], siO = o[16], sdO = o[17];

        var bi = new uint[65537];
        for (int i = 0; i < 65537; i++) bi[i] = U32(d, bucket + i * 4);

        int N = cn + ln;
        var s = new uint[N];
        var e = new uint[N];
        var v = new ushort[N];
        uint j = 0;
        for (uint b = 0; b < 65536; b++)
        {
            for (; j < bi[b + 1]; j++)
            {
                uint lo = U16(d, starts_lo + j * 2);
                s[j] = (b << 16) | lo;
                e[j] = s[j] + U16(d, lens + j * 2);
                v[j] = U16(d, vals + j * 2);
            }
        }
        for (int i = 0; i < ln; i++)
        {
            s[cn + i] = U32(d, lstarts + i * 4);
            e[cn + i] = U32(d, lends + i * 4);
            v[cn + i] = U16(d, lvals + i * 2);
        }

        var idx = Enumerable.Range(0, N).ToArray();
        Array.Sort(idx, (a, b) => s[a].CompareTo(s[b]));
        var ts = new uint[N]; var te = new uint[N]; var tv = new ushort[N];
        for (int i = 0; i < N; i++) { ts[i] = s[idx[i]]; te[i] = e[idx[i]]; tv[i] = v[idx[i]]; }
        var v4m = new uint[N];
        uint mx = 0;
        for (int i = 0; i < N; i++) { if (te[i] > mx) mx = te[i]; v4m[i] = mx; }

        var v6s = new UInt128[v6n];
        var v6e = new UInt128[v6n];
        var v6v = new ushort[v6n];
        for (int i = 0; i < v6n; i++)
        {
            ulong lo1 = U64(d, v6sO + i * 16), hi1 = U64(d, v6sO + i * 16 + 8);
            ulong lo2 = U64(d, v6eO + i * 16), hi2 = U64(d, v6eO + i * 16 + 8);
            v6s[i] = ((UInt128)hi1 << 64) | lo1;
            v6e[i] = ((UInt128)hi2 << 64) | lo2;
            v6v[i] = U16(d, v6vO + i * 2);
        }
        var v6m = new UInt128[v6n];
        UInt128 mm = 0;
        for (int i = 0; i < v6n; i++) { if (v6e[i] > mm) mm = v6e[i]; v6m[i] = mm; }

        var vt = new uint[valn][];
        for (int i = 0; i < valn; i++)
        {
            vt[i] = new uint[4];
            for (int k = 0; k < 4; k++) vt[i][k] = U32(d, vtO + (i * 4 + k) * 4);
        }

        var st = new string[strn];
        for (int i = 0; i < strn; i++)
        {
            uint so = U32(d, siO + i * 8), sl = U32(d, siO + i * 8 + 4);
            st[i] = Encoding.UTF8.GetString(d, (int)(sdO + so), (int)sl);
        }

        var db = new DB
        {
            V4s = ts, V4e = te, V4m = v4m, V4v = tv,
            V6s = v6s, V6e = v6e, V6m = v6m, V6v = v6v,
            Vt = vt, St = st
        };
        if (N > 0)
        {
            var cnt = new int[20];
            foreach (var vid in tv)
            {
                uint b = vt[vid][0];
                for (int i = 0; i < 20; i++) if ((b & (1u << i)) != 0) cnt[i]++;
            }
            for (int i = 0; i < 20; i++)
            {
                int cc = cnt[i] == 0 ? 1 : cnt[i];
                db.W[i] = C.SEV[i] * (1 + Math.Log2((double)N / cc) / 24);
            }
        }
        else Array.Copy(C.SEV, db.W, 20);
        return db;
    }
}

class Match
{
    public string source, provider, range;
    public List<string> flags;
    public double weight;
}

static class Program
{
    static double R1(double x) => Math.Round(x * 10) / 10;

    static string V4Fmt(uint x)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, x);
        return new IPAddress(b).ToString();
    }

    static string V6Fmt(UInt128 x)
    {
        var b = new byte[16];
        ulong hi = (ulong)(x >> 64), lo = (ulong)x;
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(0, 8), hi);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8, 8), lo);
        return new IPAddress(b).ToString();
    }

    static int UpperBoundU32(uint[] a, uint x)
    {
        int lo = 0, hi = a.Length;
        while (lo < hi) { int m = (lo + hi) >> 1; if (a[m] > x) hi = m; else lo = m + 1; }
        return lo;
    }

    static int UpperBoundU128(UInt128[] a, UInt128 x)
    {
        int lo = 0, hi = a.Length;
        while (lo < hi) { int m = (lo + hi) >> 1; if (a[m] > x) hi = m; else lo = m + 1; }
        return lo;
    }

    static Match MakeMatch(DB db, ushort vid, string range)
    {
        uint b = db.Vt[vid][0];
        var fl = new List<string>();
        double mxw = 0;
        for (int i = 0; i < 20; i++)
        {
            if ((b & (1u << i)) != 0)
            {
                fl.Add(C.FLAGS[i]);
                if (db.W[i] > mxw) mxw = db.W[i];
            }
        }
        return new Match
        {
            source = db.St[db.Vt[vid][2]],
            provider = db.St[db.Vt[vid][1]],
            range = range,
            flags = fl,
            weight = R1(mxw)
        };
    }

    static object Lookup(DB db, string ipStr)
    {
        var addr = IPAddress.Parse(ipStr);
        var matches = new List<Match>();
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var bytes = addr.GetAddressBytes();
            uint ip = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            int i = UpperBoundU32(db.V4s, ip);
            while (i > 0)
            {
                i--;
                if (db.V4m[i] < ip) break;
                if (db.V4e[i] >= ip)
                    matches.Add(MakeMatch(db, db.V4v[i], V4Fmt(db.V4s[i]) + "-" + V4Fmt(db.V4e[i])));
            }
        }
        else
        {
            var bytes = addr.GetAddressBytes();
            ulong hi = BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(0, 8));
            ulong lo = BinaryPrimitives.ReadUInt64BigEndian(bytes.AsSpan(8, 8));
            UInt128 ip = ((UInt128)hi << 64) | lo;
            int i = UpperBoundU128(db.V6s, ip);
            while (i > 0)
            {
                i--;
                if (db.V6m[i] < ip) break;
                if (db.V6e[i] >= ip)
                    matches.Add(MakeMatch(db, db.V6v[i], V6Fmt(db.V6s[i]) + "-" + V6Fmt(db.V6e[i])));
            }
        }

        matches = matches.OrderByDescending(m => m.weight).ToList();

        var fi = new Dictionary<string, int>();
        for (int i = 0; i < 20; i++) fi[C.FLAGS[i]] = i;

        var seenFlags = new HashSet<string>();
        var srcSet = new HashSet<string>();
        foreach (var m in matches)
        {
            foreach (var f in m.flags) seenFlags.Add(f);
            srcSet.Add(m.provider + "|" + m.source);
        }
        var ranked = seenFlags.OrderByDescending(f => db.W[fi[f]]).ToList();

        double score = 0;
        if (ranked.Count > 0)
        {
            double top = db.W[fi[ranked[0]]];
            double ex = ranked.Skip(1).Sum(f => db.W[fi[f]]);
            score = R1(Math.Min(100, (top + ex * 0.15) * (1 + 0.08 * Math.Log2(srcSet.Count + 1))));
        }

        string verdict = "clean";
        if (matches.Count > 0)
        {
            verdict = "minimal";
            foreach (var lv in C.LEVELS) if (score >= lv.t) { verdict = lv.n; break; }
        }

        var allFlags = new List<string>();
        var sf = new HashSet<string>();
        var providers = new List<string>();
        var sp = new HashSet<string>();
        foreach (var m in matches)
        {
            foreach (var f in m.flags) if (sf.Add(f)) allFlags.Add(f);
            if (!string.IsNullOrEmpty(m.provider) && sp.Add(m.provider)) providers.Add(m.provider);
        }
        for (int i = 0; i < providers.Count; i++)
        {
            if (string.Equals(providers[i], "tor", StringComparison.OrdinalIgnoreCase))
            {
                var p = providers[i];
                providers.RemoveAt(i);
                providers.Insert(0, "Tor");
                break;
            }
        }
        var reasons = ranked.Take(5).ToList();
        string topProv = providers.Count > 0 ? providers[0] : "";

        return new
        {
            ip = ipStr,
            found = matches.Count > 0,
            verdict,
            score,
            detections = matches.Count,
            sources = srcSet.Count,
            top_provider = topProv,
            providers,
            flags = allFlags,
            reasons,
            matches
        };
    }

    static string JsonEscape(string s)
    {
        var sb = new StringBuilder();
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (c < 0x20) sb.Append("\\u" + ((int)c).ToString("x4"));
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    static string FmtNum(double d)
    {
        if (d == Math.Floor(d) && !double.IsInfinity(d))
            return ((long)d).ToString(CultureInfo.InvariantCulture) + ".0";
        return d.ToString("R", CultureInfo.InvariantCulture);
    }

    static void Write(StringBuilder sb, object o, int indent)
    {
        string pad = new string(' ', indent * 2);
        string pad2 = new string(' ', (indent + 1) * 2);
        switch (o)
        {
            case null: sb.Append("null"); return;
            case bool b: sb.Append(b ? "true" : "false"); return;
            case string s: sb.Append('"').Append(JsonEscape(s)).Append('"'); return;
            case int i: sb.Append(i.ToString(CultureInfo.InvariantCulture)); return;
            case long l: sb.Append(l.ToString(CultureInfo.InvariantCulture)); return;
            case double d: sb.Append(FmtNum(d)); return;
            case System.Collections.IDictionary _: break;
            case Match m:
                WriteObj(sb, new (string, object)[] {
                    ("source", m.source), ("provider", m.provider),
                    ("range", m.range), ("flags", m.flags), ("weight", m.weight)
                }, indent);
                return;
            case System.Collections.IEnumerable en:
                var items = en.Cast<object>().ToList();
                if (items.Count == 0) { sb.Append("[]"); return; }
                sb.Append("[\n");
                for (int i = 0; i < items.Count; i++)
                {
                    sb.Append(pad2);
                    Write(sb, items[i], indent + 1);
                    if (i < items.Count - 1) sb.Append(',');
                    sb.Append('\n');
                }
                sb.Append(pad).Append(']');
                return;
        }
        var props = o.GetType().GetProperties();
        var entries = props.Select(p => (p.Name, p.GetValue(o))).ToArray();
        WriteObj(sb, entries, indent);
    }

    static void WriteObj(StringBuilder sb, (string k, object v)[] entries, int indent)
    {
        string pad = new string(' ', indent * 2);
        string pad2 = new string(' ', (indent + 1) * 2);
        if (entries.Length == 0) { sb.Append("{}"); return; }
        sb.Append("{\n");
        for (int i = 0; i < entries.Length; i++)
        {
            sb.Append(pad2).Append('"').Append(entries[i].k).Append("\": ");
            Write(sb, entries[i].v, indent + 1);
            if (i < entries.Length - 1) sb.Append(',');
            sb.Append('\n');
        }
        sb.Append(pad).Append('}');
    }

    static int Main(string[] args)
    {
        var ip = args.Length > 0 ? args[0] : "8.8.8.8";
        var db = Loader.Load("../intel.bin");
        var result = Lookup(db, ip);
        var sb = new StringBuilder();
        Write(sb, result, 0);
        Console.WriteLine(sb.ToString());
        return 0;
    }
}

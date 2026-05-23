const std = @import("std");

const FLAGS = [_][]const u8{
    "vpn", "proxy", "tor", "malware", "c2", "scanner", "brute_force", "spammer",
    "compromised", "datacenter", "cdn", "anycast", "crawler", "bot", "cloud",
    "private_relay", "anonymizer", "mobile", "isp", "government",
};
const SEV = [_]f64{ 30, 25, 45, 95, 95, 55, 70, 65, 75, 15, 5, 0, 10, 40, 10, 15, 35, 0, 0, 0 };
const Level = struct { t: f64, n: []const u8 };
const LEVELS = [_]Level{
    .{ .t = 80, .n = "critical" }, .{ .t = 60, .n = "high" },
    .{ .t = 35, .n = "medium" },   .{ .t = 15, .n = "low" },
};

fn rd(comptime T: type, d: []const u8, o: usize) T {
    return std.mem.readInt(T, d[o..][0..@sizeOf(T)], .little);
}

const DB = struct {
    v4s: []u32, v4e: []u32, v4m: []u32, v4v: []u16,
    v6s: []u128, v6e: []u128, v6m: []u128, v6v: []u16,
    vt: [][4]u32,
    st: [][]const u8,
    w: [20]f64,
};

fn load(alloc: std.mem.Allocator, io: std.Io, path: []const u8) !DB {
    const d = try std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .unlimited);
    if (rd(u32, d, 0) != 6) return error.BadVersion;
    var o: [19]usize = undefined;
    for (0..19) |i| o[i] = @intCast(rd(u64, d, 8 + i * 8));
    const cn = o[0]; const ln = o[1]; const v6n = o[2]; const valn = o[3]; const strn = o[4];
    const off = o[5..];

    const bi = try alloc.alloc(u32, 65537);
    defer alloc.free(bi);
    for (0..65537) |i| bi[i] = rd(u32, d, off[0] + i * 4);

    const N = cn + ln;
    const s = try alloc.alloc(u32, N);
    const e = try alloc.alloc(u32, N);
    const v = try alloc.alloc(u16, N);
    defer alloc.free(s);
    defer alloc.free(e);
    defer alloc.free(v);
    var j: usize = 0;
    for (0..65536) |b| {
        while (j < bi[b + 1]) : (j += 1) {
            const lo: u32 = rd(u16, d, off[1] + j * 2);
            s[j] = (@as(u32, @intCast(b)) << 16) | lo;
            e[j] = s[j] + @as(u32, rd(u16, d, off[2] + j * 2));
            v[j] = rd(u16, d, off[3] + j * 2);
        }
    }
    for (0..ln) |i| {
        s[cn + i] = rd(u32, d, off[4] + i * 4);
        e[cn + i] = rd(u32, d, off[5] + i * 4);
        v[cn + i] = rd(u16, d, off[6] + i * 2);
    }
    const idx = try alloc.alloc(usize, N);
    defer alloc.free(idx);
    for (0..N) |i| idx[i] = i;
    const SortCtx = struct {
        s: []u32,
        pub fn lt(c: @This(), a: usize, b: usize) bool { return c.s[a] < c.s[b]; }
    };
    std.mem.sort(usize, idx, SortCtx{ .s = s }, SortCtx.lt);
    const v4s = try alloc.alloc(u32, N);
    const v4e = try alloc.alloc(u32, N);
    const v4v = try alloc.alloc(u16, N);
    for (idx, 0..) |k, i| { v4s[i] = s[k]; v4e[i] = e[k]; v4v[i] = v[k]; }
    const v4m = try alloc.alloc(u32, N);
    var mx: u32 = 0;
    for (0..N) |i| { if (v4e[i] > mx) mx = v4e[i]; v4m[i] = mx; }

    const v6s = try alloc.alloc(u128, v6n);
    const v6e = try alloc.alloc(u128, v6n);
    const v6v = try alloc.alloc(u16, v6n);
    for (0..v6n) |i| {
        const lo = rd(u64, d, off[7] + i * 16);
        const hi = rd(u64, d, off[7] + i * 16 + 8);
        v6s[i] = (@as(u128, hi) << 64) | lo;
        const lo2 = rd(u64, d, off[8] + i * 16);
        const hi2 = rd(u64, d, off[8] + i * 16 + 8);
        v6e[i] = (@as(u128, hi2) << 64) | lo2;
        v6v[i] = rd(u16, d, off[9] + i * 2);
    }
    const v6m = try alloc.alloc(u128, v6n);
    var mm: u128 = 0;
    for (0..v6n) |i| { if (v6e[i] > mm) mm = v6e[i]; v6m[i] = mm; }

    const vt = try alloc.alloc([4]u32, valn);
    for (0..valn) |i| {
        for (0..4) |k| vt[i][k] = rd(u32, d, off[10] + (i * 4 + k) * 4);
    }
    const sd = off[12];
    const st = try alloc.alloc([]const u8, strn);
    for (0..strn) |i| {
        const so: usize = @intCast(rd(u32, d, off[11] + i * 8));
        const sl: usize = @intCast(rd(u32, d, off[11] + i * 8 + 4));
        st[i] = d[sd + so .. sd + so + sl];
    }

    var w: [20]f64 = SEV;
    if (N > 0) {
        var c = [_]usize{0} ** 20;
        for (v4v) |vid| {
            const b = vt[vid][0];
            for (0..20) |i| { if (b & (@as(u32, 1) << @intCast(i)) != 0) c[i] += 1; }
        }
        for (0..20) |i| {
            const cc: f64 = @floatFromInt(if (c[i] == 0) 1 else c[i]);
            w[i] = SEV[i] * (1 + std.math.log2(@as(f64, @floatFromInt(N)) / cc) / 24);
        }
    }
    return DB{
        .v4s = v4s, .v4e = v4e, .v4m = v4m, .v4v = v4v,
        .v6s = v6s, .v6e = v6e, .v6m = v6m, .v6v = v6v,
        .vt = vt, .st = st, .w = w,
    };
}

fn r1(x: f64) f64 { return @round(x * 10) / 10; }

fn upperU32(a: []const u32, ip: u32) usize {
    var lo: usize = 0; var hi: usize = a.len;
    while (lo < hi) { const m = (lo + hi) / 2; if (a[m] > ip) hi = m else lo = m + 1; }
    return lo;
}
fn upperU128(a: []const u128, ip: u128) usize {
    var lo: usize = 0; var hi: usize = a.len;
    while (lo < hi) { const m = (lo + hi) / 2; if (a[m] > ip) hi = m else lo = m + 1; }
    return lo;
}

fn fmtV4(buf: []u8, ip: u32) ![]const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff,
    });
}

fn fmtV6(buf: []u8, ip: u128) ![]const u8 {
    var groups: [8]u16 = undefined;
    for (0..8) |i| groups[i] = @intCast((ip >> @intCast((7 - i) * 16)) & 0xffff);
    var best_start: i32 = -1;
    var best_len: usize = 0;
    var cur_start: i32 = -1;
    var cur_len: usize = 0;
    for (groups, 0..) |g, i| {
        if (g == 0) {
            if (cur_start == -1) cur_start = @intCast(i);
            cur_len += 1;
            if (cur_len > best_len) { best_start = cur_start; best_len = cur_len; }
        } else { cur_start = -1; cur_len = 0; }
    }
    var n: usize = 0;
    const writeGroup = struct {
        fn f(b: []u8, pos: *usize, g: u16) !void {
            const w = try std.fmt.bufPrint(b[pos.*..], "{x}", .{g});
            pos.* += w.len;
        }
    }.f;
    if (best_len < 2) {
        for (groups, 0..) |g, i| {
            if (i > 0) { buf[n] = ':'; n += 1; }
            try writeGroup(buf, &n, g);
        }
    } else {
        const bs: usize = @intCast(best_start);
        for (0..bs) |i| {
            if (i > 0) { buf[n] = ':'; n += 1; }
            try writeGroup(buf, &n, groups[i]);
        }
        buf[n] = ':'; n += 1; buf[n] = ':'; n += 1;
        var first = true;
        for (bs + best_len..8) |i| {
            if (!first) { buf[n] = ':'; n += 1; }
            try writeGroup(buf, &n, groups[i]);
            first = false;
        }
    }
    return buf[0..n];
}

fn parseV6(s: []const u8) !u128 {
    var head_buf: [8]u16 = undefined;
    var tail_buf: [8]u16 = undefined;
    var head_n: usize = 0;
    var tail_n: usize = 0;
    var seen_dc = false;
    var i: usize = 0;
    var current = &head_buf;
    var current_n = &head_n;
    while (i < s.len) {
        if (i + 1 < s.len and s[i] == ':' and s[i + 1] == ':') {
            seen_dc = true;
            current = &tail_buf;
            current_n = &tail_n;
            i += 2;
            continue;
        }
        if (s[i] == ':') { i += 1; continue; }
        var j = i;
        while (j < s.len and s[j] != ':') j += 1;
        const grp = try std.fmt.parseInt(u16, s[i..j], 16);
        current.*[current_n.*] = grp;
        current_n.* += 1;
        i = j;
    }
    var groups: [8]u16 = .{0} ** 8;
    for (0..head_n) |k| groups[k] = head_buf[k];
    const offset = 8 - tail_n;
    for (0..tail_n) |k| groups[offset + k] = tail_buf[k];
    _ = &seen_dc;
    var ip: u128 = 0;
    for (groups) |g| ip = (ip << 16) | g;
    return ip;
}

fn parseV4(s: []const u8) !u32 {
    var ip: u32 = 0;
    var i: usize = 0;
    var parts: usize = 0;
    while (parts < 4) : (parts += 1) {
        var j = i;
        while (j < s.len and s[j] != '.') j += 1;
        const oct = try std.fmt.parseInt(u8, s[i..j], 10);
        ip = (ip << 8) | oct;
        i = j + 1;
    }
    return ip;
}

const Match = struct {
    source: []const u8,
    provider: []const u8,
    range: []const u8,
    flags: std.ArrayList([]const u8),
    weight: f64,
};

pub fn main(init: std.process.Init) !void {
    const alloc = init.arena.allocator();
    const io = init.io;
    var it = try init.minimal.args.iterateAllocator(alloc);
    defer it.deinit();
    _ = it.skip();
    const ip_str: []const u8 = if (it.next()) |a| a else "8.8.8.8";
    const db = try load(alloc, io, "../intel.bin");

    var matches = std.ArrayList(Match).empty;
    var is_v4 = true;
    for (ip_str) |ch| if (ch == ':') { is_v4 = false; break; };

    if (is_v4) {
        const ip = try parseV4(ip_str);
        var i = upperU32(db.v4s, ip);
        while (i > 0) {
            i -= 1;
            if (db.v4m[i] < ip) break;
            if (db.v4e[i] >= ip) {
                var b1: [16]u8 = undefined;
                var b2: [16]u8 = undefined;
                const sstr = try fmtV4(&b1, db.v4s[i]);
                const estr = try fmtV4(&b2, db.v4e[i]);
                const rng = try std.fmt.allocPrint(alloc, "{s}-{s}", .{ sstr, estr });
                try buildMatch(alloc, &matches, db, db.v4v[i], rng);
            }
        }
    } else {
        const ip = try parseV6(ip_str);
        var i = upperU128(db.v6s, ip);
        while (i > 0) {
            i -= 1;
            if (db.v6m[i] < ip) break;
            if (db.v6e[i] >= ip) {
                var b1: [64]u8 = undefined;
                var b2: [64]u8 = undefined;
                const sstr = try fmtV6(&b1, db.v6s[i]);
                const estr = try fmtV6(&b2, db.v6e[i]);
                const rng = try std.fmt.allocPrint(alloc, "{s}-{s}", .{ sstr, estr });
                try buildMatch(alloc, &matches, db, db.v6v[i], rng);
            }
        }
    }
    std.mem.sort(Match, matches.items, {}, struct {
        pub fn lt(_: void, a: Match, b: Match) bool { return a.weight > b.weight; }
    }.lt);

    var all_flags = std.ArrayList([]const u8).empty;
    var providers = std.ArrayList([]const u8).empty;
    var sources_map = std.StringHashMap(void).init(alloc);
    var seen_f = std.StringHashMap(void).init(alloc);
    var seen_p = std.StringHashMap(void).init(alloc);
    for (matches.items) |m| {
        for (m.flags.items) |f| {
            if (!seen_f.contains(f)) {
                try seen_f.put(f, {});
                try all_flags.append(alloc, f);
            }
        }
        if (m.provider.len > 0 and !seen_p.contains(m.provider)) {
            try seen_p.put(m.provider, {});
            try providers.append(alloc, m.provider);
        }
        const k = try std.fmt.allocPrint(alloc, "{s}|{s}", .{ m.provider, m.source });
        try sources_map.put(k, {});
    }
    var ranked = try alloc.alloc([]const u8, all_flags.items.len);
    for (all_flags.items, 0..) |f, i| ranked[i] = f;
    const RCtx = struct {
        w: [20]f64,
        pub fn fIdx(_: @This(), f: []const u8) usize {
            for (FLAGS, 0..) |fl, k| { if (std.mem.eql(u8, fl, f)) return k; }
            return 0;
        }
        pub fn lt(c: @This(), a: []const u8, b: []const u8) bool {
            return c.w[c.fIdx(a)] > c.w[c.fIdx(b)];
        }
    };
    std.mem.sort([]const u8, ranked, RCtx{ .w = db.w }, RCtx.lt);

    var score: f64 = 0;
    const ctx = RCtx{ .w = db.w };
    if (ranked.len > 0) {
        const top = db.w[ctx.fIdx(ranked[0])];
        var ex: f64 = 0;
        for (ranked[1..]) |f| ex += db.w[ctx.fIdx(f)];
        const ns: f64 = @floatFromInt(sources_map.count() + 1);
        score = r1(@min(100, (top + ex * 0.15) * (1 + 0.08 * std.math.log2(ns))));
    }

    var verdict: []const u8 = "clean";
    if (matches.items.len > 0) {
        verdict = "minimal";
        for (LEVELS) |lv| { if (score >= lv.t) { verdict = lv.n; break; } }
    }

    for (providers.items, 0..) |p, i| {
        if (std.ascii.eqlIgnoreCase(p, "tor")) {
            _ = providers.orderedRemove(i);
            try providers.insert(alloc, 0, "Tor");
            break;
        }
    }

    const reasons_n = @min(5, ranked.len);
    const reasons = ranked[0..reasons_n];

    var out = std.ArrayList(u8).empty;
    try out.appendSlice(alloc, "{\n  \"ip\": ");
    try writeJsonString(&out, alloc, ip_str);
    try out.print(alloc, ",\n  \"found\": {s},\n  \"verdict\": ", .{if (matches.items.len > 0) "true" else "false"});
    try writeJsonString(&out, alloc, verdict);
    try out.print(alloc, ",\n  \"score\": {s},\n  \"detections\": {d},\n  \"sources\": {d},\n  \"top_provider\": ", .{ try fmtNum(alloc, score), matches.items.len, sources_map.count() });
    try writeJsonString(&out, alloc, if (providers.items.len > 0) providers.items[0] else "");
    try out.appendSlice(alloc, ",\n  \"providers\": ");
    try writeArr(&out, alloc, providers.items, "  ");
    try out.appendSlice(alloc, ",\n  \"flags\": ");
    try writeArr(&out, alloc, all_flags.items, "  ");
    try out.appendSlice(alloc, ",\n  \"reasons\": ");
    try writeArr(&out, alloc, reasons, "  ");
    try out.appendSlice(alloc, ",\n  \"matches\": ");
    if (matches.items.len == 0) {
        try out.appendSlice(alloc, "[]");
    } else {
        try out.appendSlice(alloc, "[\n");
        for (matches.items, 0..) |m, i| {
            try out.appendSlice(alloc, "    {\n      \"source\": ");
            try writeJsonString(&out, alloc, m.source);
            try out.appendSlice(alloc, ",\n      \"provider\": ");
            try writeJsonString(&out, alloc, m.provider);
            try out.appendSlice(alloc, ",\n      \"range\": ");
            try writeJsonString(&out, alloc, m.range);
            try out.appendSlice(alloc, ",\n      \"flags\": ");
            try writeArr(&out, alloc, m.flags.items, "      ");
            try out.print(alloc, ",\n      \"weight\": {s}\n    }}", .{try fmtNum(alloc, m.weight)});
            if (i + 1 < matches.items.len) try out.append(alloc, ',');
            try out.append(alloc, '\n');
        }
        try out.appendSlice(alloc, "  ]");
    }
    try out.appendSlice(alloc, "\n}\n");
    const so = std.Io.File.stdout();
    try so.writeStreamingAll(io, out.items);
}

fn buildMatch(alloc: std.mem.Allocator, matches: *std.ArrayList(Match), db: DB, vid: u16, rng: []const u8) !void {
    const b = db.vt[vid][0];
    var fl = std.ArrayList([]const u8).empty;
    var mxw: f64 = 0;
    for (0..20) |i| {
        if (b & (@as(u32, 1) << @intCast(i)) != 0) {
            try fl.append(alloc, FLAGS[i]);
            if (db.w[i] > mxw) mxw = db.w[i];
        }
    }
    try matches.append(alloc, .{
        .source = db.st[db.vt[vid][2]],
        .provider = db.st[db.vt[vid][1]],
        .range = rng,
        .flags = fl,
        .weight = r1(mxw),
    });
}

fn writeJsonString(out: *std.ArrayList(u8), alloc: std.mem.Allocator, s: []const u8) !void {
    try out.append(alloc, '"');
    for (s) |c| switch (c) {
        '"' => try out.appendSlice(alloc, "\\\""),
        '\\' => try out.appendSlice(alloc, "\\\\"),
        '\n' => try out.appendSlice(alloc, "\\n"),
        '\r' => try out.appendSlice(alloc, "\\r"),
        '\t' => try out.appendSlice(alloc, "\\t"),
        0...0x07, 0x0b, 0x0e...0x1f => try out.print(alloc, "\\u{x:0>4}", .{c}),
        0x08 => try out.appendSlice(alloc, "\\b"),
        0x0c => try out.appendSlice(alloc, "\\f"),
        else => try out.append(alloc, c),
    };
    try out.append(alloc, '"');
}

fn writeArr(out: *std.ArrayList(u8), alloc: std.mem.Allocator, items: [][]const u8, indent: []const u8) !void {
    if (items.len == 0) { try out.appendSlice(alloc, "[]"); return; }
    try out.appendSlice(alloc, "[\n");
    for (items, 0..) |s, i| {
        try out.print(alloc, "{s}  ", .{indent});
        try writeJsonString(out, alloc, s);
        if (i + 1 < items.len) try out.append(alloc, ',');
        try out.append(alloc, '\n');
    }
    try out.print(alloc, "{s}]", .{indent});
}

fn fmtNum(alloc: std.mem.Allocator, v: f64) ![]const u8 {
    const r = @round(v);
    if (v == r) return std.fmt.allocPrint(alloc, "{d}.0", .{@as(i64, @intFromFloat(r))});
    return std.fmt.allocPrint(alloc, "{d:.1}", .{v});
}

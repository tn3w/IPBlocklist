local FLAGS = {"vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
    "compromised","datacenter","cdn","anycast","crawler","bot","cloud","private_relay",
    "anonymizer","mobile","isp","government"}
local SEV = {30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0}
local LEVELS = {{80,"critical"},{60,"high"},{35,"medium"},{15,"low"}}

local function read_u32_array(d, off, n)
    local out = {}
    local p = off + 1
    for i = 1, n do
        out[i], p = string.unpack("<I4", d, p)
    end
    return out
end

local function read_u16_array(d, off, n)
    local out = {}
    local p = off + 1
    for i = 1, n do
        out[i], p = string.unpack("<I2", d, p)
    end
    return out
end

local function load_db(path)
    local f = assert(io.open(path, "rb"))
    local d = f:read("*a")
    f:close()
    local ver = string.unpack("<I4", d, 1)
    if ver ~= 6 then os.exit(1) end
    local o = {}
    local p = 9
    for i = 1, 19 do o[i], p = string.unpack("<I8", d, p) end
    local cn, ln, v6n, valn, strn = o[1], o[2], o[3], o[4], o[5]
    local bucket = read_u32_array(d, o[6], 65537)
    local s_lo = read_u16_array(d, o[7], cn)
    local s_len = read_u16_array(d, o[8], cn)
    local s_val = read_u16_array(d, o[9], cn)
    local l_s = read_u32_array(d, o[10], ln)
    local l_e = read_u32_array(d, o[11], ln)
    local l_v = read_u16_array(d, o[12], ln)

    local small_s, small_e, small_v = {}, {}, {}
    local bid = 0
    for i = 1, cn do
        while bid < 65536 and i > bucket[bid + 2] do bid = bid + 1 end
        local s = (bid << 16) | s_lo[i]
        small_s[i] = s
        small_e[i] = s + s_len[i]
        small_v[i] = s_val[i]
    end

    local total = cn + ln
    local idx = {}
    for i = 1, total do idx[i] = i end
    table.sort(idx, function(a, b)
        local sa = a <= cn and small_s[a] or l_s[a - cn]
        local sb = b <= cn and small_s[b] or l_s[b - cn]
        if sa == sb then return a < b end
        return sa < sb
    end)
    local v4s, v4e, v4v = {}, {}, {}
    for i = 1, total do
        local j = idx[i]
        if j <= cn then
            v4s[i], v4e[i], v4v[i] = small_s[j], small_e[j], small_v[j]
        else
            local k = j - cn
            v4s[i], v4e[i], v4v[i] = l_s[k], l_e[k], l_v[k]
        end
    end
    local v4max = {}
    local mx = 0
    for i = 1, total do
        if v4e[i] > mx then mx = v4e[i] end
        v4max[i] = mx
    end

    local v6s, v6e, v6max = {}, {}, {}
    local p6s, p6e = o[13] + 1, o[14] + 1
    for i = 1, v6n do
        local lo, hi
        lo, hi, p6s = string.unpack("<I8<I8", d, p6s)
        v6s[i] = {hi, lo}
        lo, hi, p6e = string.unpack("<I8<I8", d, p6e)
        v6e[i] = {hi, lo}
    end
    local v6v = read_u16_array(d, o[15], v6n)
    local function cmp6(a, b)
        if a[1] ~= b[1] then return a[1] < b[1] and -1 or 1 end
        if a[2] ~= b[2] then return a[2] < b[2] and -1 or 1 end
        return 0
    end
    for i = 1, v6n do
        if i == 1 or cmp6(v6e[i], v6max[i-1]) > 0 then
            v6max[i] = v6e[i]
        else
            v6max[i] = v6max[i-1]
        end
    end

    local values = {}
    local pv = o[16] + 1
    for i = 1, valn do
        local b, pr, sr, _
        b, pr, sr, _, pv = string.unpack("<I4<I4<I4<I4", d, pv)
        values[i] = {b, pr, sr}
    end

    local sidx = {}
    local ps = o[17] + 1
    for i = 1, strn do
        local off, len
        off, len, ps = string.unpack("<I4<I4", d, ps)
        sidx[i] = {off, len}
    end
    local sd, sl = o[18], o[19]
    local blob = d:sub(sd + 1, sd + sl)
    local strings = {}
    for i = 1, strn do
        strings[i] = blob:sub(sidx[i][1] + 1, sidx[i][1] + sidx[i][2])
    end

    local weights = {}
    if total > 0 then
        for i, f in ipairs(FLAGS) do
            local c = 0
            local bit = 1 << (i - 1)
            for k = 1, total do
                if (values[v4v[k] + 1][1] & bit) ~= 0 then c = c + 1 end
            end
            if c < 1 then c = 1 end
            weights[f] = SEV[i] * (1 + math.log(total / c) / math.log(2) / 24)
        end
    else
        for i, f in ipairs(FLAGS) do weights[f] = SEV[i] end
    end

    return {
        v4s=v4s, v4e=v4e, v4v=v4v, v4max=v4max,
        v6s=v6s, v6e=v6e, v6v=v6v, v6max=v6max,
        values=values, strings=strings, weights=weights,
        cmp6=cmp6,
    }
end

local function parse_ip4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return (tonumber(a) << 24) | (tonumber(b) << 16) | (tonumber(c) << 8) | tonumber(d)
end

local function parse_ip6(s)
    local left, right = s:match("^(.-)::(.*)$")
    local lp, rp = {}, {}
    if left then
        if #left > 0 then for g in left:gmatch("[^:]+") do lp[#lp+1] = g end end
        if #right > 0 then for g in right:gmatch("[^:]+") do rp[#rp+1] = g end end
    else
        for g in s:gmatch("[^:]+") do lp[#lp+1] = g end
        if #lp ~= 8 then return nil end
    end
    local groups = {}
    for i = 1, #lp do groups[i] = lp[i] end
    local fill = 8 - #lp - #rp
    for i = 1, fill do groups[#groups+1] = "0" end
    for i = 1, #rp do groups[#groups+1] = rp[i] end
    if #groups ~= 8 then return nil end
    local hi, lo = 0, 0
    for i = 1, 4 do hi = (hi << 16) | tonumber(groups[i], 16) end
    for i = 5, 8 do lo = (lo << 16) | tonumber(groups[i], 16) end
    return {hi, lo}
end

local function fmt_v4(ip)
    return string.format("%d.%d.%d.%d",
        (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff)
end

local function fmt_v6(pair)
    local hi, lo = pair[1], pair[2]
    local g = {}
    for i = 1, 4 do g[i] = (hi >> (16 * (4 - i))) & 0xffff end
    for i = 1, 4 do g[4+i] = (lo >> (16 * (4 - i))) & 0xffff end
    local best_s, best_l, cur_s, cur_l = 0, 0, 0, 0
    for i = 1, 8 do
        if g[i] == 0 then
            if cur_l == 0 then cur_s = i end
            cur_l = cur_l + 1
            if cur_l > best_l then best_s, best_l = cur_s, cur_l end
        else
            cur_l = 0
        end
    end
    local parts = {}
    for i = 1, 8 do parts[i] = string.format("%x", g[i]) end
    if best_l >= 2 then
        local left = {}
        for i = 1, best_s - 1 do left[#left+1] = parts[i] end
        local right = {}
        for i = best_s + best_l, 8 do right[#right+1] = parts[i] end
        return table.concat(left, ":") .. "::" .. table.concat(right, ":")
    end
    return table.concat(parts, ":")
end

local function hits_v4(db, ip)
    local s, e, m, v = db.v4s, db.v4e, db.v4max, db.v4v
    local n = #s
    if n == 0 then return {} end
    local lo, hi = 1, n + 1
    while lo < hi do
        local mid = (lo + hi) // 2
        if s[mid] <= ip then lo = mid + 1 else hi = mid end
    end
    local i = lo - 1
    local out = {}
    while i >= 1 do
        if m[i] < ip then break end
        if e[i] >= ip then out[#out+1] = {s[i], e[i], v[i]} end
        i = i - 1
    end
    return out
end

local function hits_v6(db, ip)
    local s, e, m, v = db.v6s, db.v6e, db.v6max, db.v6v
    local n = #s
    if n == 0 then return {} end
    local cmp = db.cmp6
    local lo, hi = 1, n + 1
    while lo < hi do
        local mid = (lo + hi) // 2
        if cmp(s[mid], ip) <= 0 then lo = mid + 1 else hi = mid end
    end
    local i = lo - 1
    local out = {}
    while i >= 1 do
        if cmp(m[i], ip) < 0 then break end
        if cmp(e[i], ip) >= 0 then out[#out+1] = {s[i], e[i], v[i]} end
        i = i - 1
    end
    return out
end

local function round1(x)
    return math.floor(x * 10 + 0.5) / 10
end

local function lookup(db, ip_str)
    local v4 = ip_str:find(":") == nil
    local ip, hits, fmt
    if v4 then
        ip = parse_ip4(ip_str)
        hits = hits_v4(db, ip)
        fmt = fmt_v4
    else
        ip = parse_ip6(ip_str)
        hits = hits_v6(db, ip)
        fmt = fmt_v6
    end
    local matches = {}
    for _, h in ipairs(hits) do
        local val = db.values[h[3] + 1]
        local b, prov, src = val[1], val[2], val[3]
        local flags = {}
        for i = 1, 20 do
            if (b & (1 << (i - 1))) ~= 0 then flags[#flags+1] = FLAGS[i] end
        end
        local w = 0
        for _, f in ipairs(flags) do
            if db.weights[f] > w then w = db.weights[f] end
        end
        matches[#matches+1] = {
            source = db.strings[src + 1],
            provider = db.strings[prov + 1],
            range = fmt(h[1]) .. "-" .. fmt(h[2]),
            flags = flags,
            weight = round1(w),
        }
    end
    table.sort(matches, function(a, b) return a.weight > b.weight end)

    local seen = {}
    local ranked = {}
    for _, m in ipairs(matches) do
        for _, f in ipairs(m.flags) do
            if not seen[f] then
                seen[f] = true
                ranked[#ranked+1] = f
            end
        end
    end
    table.sort(ranked, function(a, b) return db.weights[a] > db.weights[b] end)

    local src_seen, src_count = {}, 0
    for _, m in ipairs(matches) do
        local k = m.provider .. "\0" .. m.source
        if not src_seen[k] then src_seen[k] = true; src_count = src_count + 1 end
    end

    local score = 0.0
    if #ranked > 0 then
        local s = db.weights[ranked[1]]
        for i = 2, #ranked do s = s + db.weights[ranked[i]] * 0.15 end
        s = s * (1 + 0.08 * math.log(src_count + 1) / math.log(2))
        if s > 100 then s = 100 end
        score = round1(s)
    end

    local verdict = "clean"
    if #matches > 0 then
        verdict = "minimal"
        for _, lv in ipairs(LEVELS) do
            if score >= lv[1] then verdict = lv[2]; break end
        end
    end

    local flag_seen, all_flags = {}, {}
    for _, m in ipairs(matches) do
        for _, f in ipairs(m.flags) do
            if not flag_seen[f] then
                flag_seen[f] = true
                all_flags[#all_flags+1] = f
            end
        end
    end

    local pseen, providers = {}, {}
    for _, m in ipairs(matches) do
        local p = m.provider
        if p ~= "" and not pseen[p] then
            pseen[p] = true
            providers[#providers+1] = p
        end
    end
    local has_tor = false
    for _, p in ipairs(providers) do
        if p:lower() == "tor" then has_tor = true; break end
    end
    if has_tor then
        local np = {"Tor"}
        for _, p in ipairs(providers) do
            if p:lower() ~= "tor" then np[#np+1] = p end
        end
        providers = np
    end

    local reasons = {}
    for i = 1, math.min(5, #ranked) do reasons[i] = ranked[i] end

    return {
        ip = ip_str, found = #matches > 0, verdict = verdict, score = score,
        detections = #matches, sources = src_count,
        top_provider = providers[1] or "",
        providers = providers, flags = all_flags,
        reasons = reasons, matches = matches,
    }, {"ip","found","verdict","score","detections","sources","top_provider",
        "providers","flags","reasons","matches"}
end

local MATCH_KEYS = {"source","provider","range","flags","weight"}

local function esc_str(s)
    s = s:gsub("\\", "\\\\"):gsub("\"", "\\\"")
    s = s:gsub("[%z\1-\31]", function(c) return string.format("\\u%04x", c:byte()) end)
    return "\"" .. s .. "\""
end

local function fmt_num(n, is_float)
    if is_float then return string.format("%.1f", n) end
    if math.type(n) == "integer" then return tostring(n) end
    if n == math.floor(n) then return string.format("%.1f", n) end
    return string.format("%.1f", n)
end

local function is_array(t)
    local n = 0
    for _ in pairs(t) do n = n + 1 end
    for i = 1, n do if t[i] == nil then return false end end
    return true, n
end

local FLOAT_KEYS = {score=true, weight=true}

local function encode(v, indent, key)
    if v == nil then return "null" end
    if v == true then return "true" end
    if v == false then return "false" end
    if type(v) == "number" then
        return fmt_num(v, FLOAT_KEYS[key or ""] == true)
    end
    if type(v) == "string" then return esc_str(v) end
    if type(v) == "table" then
        local arr, n = is_array(v)
        local pad = string.rep("  ", indent + 1)
        local close_pad = string.rep("  ", indent)
        if arr then
            if n == 0 then return "[]" end
            local parts = {}
            for i = 1, n do
                parts[i] = pad .. encode(v[i], indent + 1, key)
            end
            return "[\n" .. table.concat(parts, ",\n") .. "\n" .. close_pad .. "]"
        end
        return nil
    end
    return "null"
end

local function encode_obj(obj, keys, indent)
    local pad = string.rep("  ", indent + 1)
    local close_pad = string.rep("  ", indent)
    local parts = {}
    for _, k in ipairs(keys) do
        local v = obj[k]
        local enc
        if type(v) == "table" then
            local arr, n = is_array(v)
            if arr and n > 0 and type(v[1]) == "table" and v[1].flags then
                local items = {}
                for i = 1, n do
                    items[i] = string.rep("  ", indent + 2) ..
                        encode_obj(v[i], MATCH_KEYS, indent + 2)
                end
                enc = "[\n" .. table.concat(items, ",\n") .. "\n" .. pad .. "]"
            else
                enc = encode(v, indent + 1, k)
            end
        else
            enc = encode(v, indent + 1, k)
        end
        parts[#parts+1] = pad .. esc_str(k) .. ": " .. enc
    end
    return "{\n" .. table.concat(parts, ",\n") .. "\n" .. close_pad .. "}"
end

local db = load_db("../intel.bin")
local arg_ip = arg[1] or "8.8.8.8"
local result, keys = lookup(db, arg_ip)
print(encode_obj(result, keys, 0))

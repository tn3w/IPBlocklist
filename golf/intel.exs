import Bitwise

defmodule Intel do
  @flags ~w(vpn proxy tor malware c2 scanner brute_force spammer compromised
            datacenter cdn anycast crawler bot cloud private_relay anonymizer
            mobile isp government)
  @sev [30, 25, 45, 95, 95, 55, 70, 65, 75, 15, 5, 0, 10, 40, 10, 15, 35, 0, 0, 0]
  @levels [{80, "critical"}, {60, "high"}, {35, "medium"}, {15, "low"}]

  def flags, do: @flags
  def sev, do: @sev
  def levels, do: @levels

  def unpack_u16(bin, n) do
    for <<x::little-16 <- binary_part(bin, 0, n * 2)>>, do: x
  end

  def unpack_u32(bin, n) do
    for <<x::little-32 <- binary_part(bin, 0, n * 4)>>, do: x
  end

  def unpack_u64(bin, n) do
    for <<x::little-64 <- binary_part(bin, 0, n * 8)>>, do: x
  end

  def slice(d, off, len), do: binary_part(d, off, len)

  def load(path) do
    d = File.read!(path)
    <<ver::little-32, _::little-32, rest::binary>> = d
    if ver != 6, do: raise("unsupported version #{ver}")
    [cn, ln, v6n, valn, strn | o] = unpack_u64(rest, 19)

    bi = unpack_u32(slice(d, Enum.at(o, 0), 65537 * 4), 65537)
    bid = build_bid(bi)

    starts_lo = if cn > 0, do: unpack_u16(slice(d, Enum.at(o, 1), cn * 2), cn), else: []
    lens = if cn > 0, do: unpack_u16(slice(d, Enum.at(o, 2), cn * 2), cn), else: []
    vals_s = if cn > 0, do: unpack_u16(slice(d, Enum.at(o, 3), cn * 2), cn), else: []

    small = build_small(bid, starts_lo, lens, vals_s)

    lstarts = if ln > 0, do: unpack_u32(slice(d, Enum.at(o, 4), ln * 4), ln), else: []
    lends = if ln > 0, do: unpack_u32(slice(d, Enum.at(o, 5), ln * 4), ln), else: []
    lvals = if ln > 0, do: unpack_u16(slice(d, Enum.at(o, 6), ln * 2), ln), else: []

    large = Enum.zip([lstarts, lends, lvals])
    all = Enum.sort_by(small ++ large, fn {s, _, _} -> s end)
    v4s = Enum.map(all, fn {s, _, _} -> s end)
    v4e = Enum.map(all, fn {_, e, _} -> e end)
    v4v = Enum.map(all, fn {_, _, v} -> v end)
    v4m = running_max(v4e)

    v6_raw_s = if v6n > 0, do: unpack_u64(slice(d, Enum.at(o, 7), v6n * 16), v6n * 2), else: []
    v6_raw_e = if v6n > 0, do: unpack_u64(slice(d, Enum.at(o, 8), v6n * 16), v6n * 2), else: []
    v6s = combine128(v6_raw_s)
    v6e = combine128(v6_raw_e)
    v6v = if v6n > 0, do: unpack_u16(slice(d, Enum.at(o, 9), v6n * 2), v6n), else: []
    v6m = running_max(v6e)

    values_flat =
      if valn > 0, do: unpack_u32(slice(d, Enum.at(o, 10), valn * 16), valn * 4), else: []

    values = chunk4(values_flat)

    sidx_flat =
      if strn > 0, do: unpack_u32(slice(d, Enum.at(o, 11), strn * 8), strn * 2), else: []

    blob = slice(d, Enum.at(o, 12), Enum.at(o, 13))
    strings = build_strings(sidx_flat, blob)

    weights = compute_weights(v4v, values)

    %{
      v4s: List.to_tuple(v4s),
      v4e: List.to_tuple(v4e),
      v4v: List.to_tuple(v4v),
      v4m: List.to_tuple(v4m),
      v4n: length(v4s),
      v6s: List.to_tuple(v6s),
      v6e: List.to_tuple(v6e),
      v6v: List.to_tuple(v6v),
      v6m: List.to_tuple(v6m),
      v6cn: length(v6s),
      values: List.to_tuple(values),
      strings: List.to_tuple(strings),
      weights: weights
    }
  end

  defp build_bid(bi) do
    pairs = Enum.zip(Enum.with_index(bi), tl(bi) ++ [0])
    pairs
    |> Enum.take(65536)
    |> Enum.flat_map(fn {{cur, b}, nxt} -> List.duplicate(b, nxt - cur) end)
  end

  defp build_small(bid, starts_lo, lens, vals) do
    Enum.zip([bid, starts_lo, lens, vals])
    |> Enum.map(fn {b, lo, l, v} ->
      s = bsl(b, 16) ||| lo
      {s, s + l, v}
    end)
  end

  defp combine128([]), do: []
  defp combine128([lo, hi | rest]), do: [bsl(hi, 64) ||| lo | combine128(rest)]

  defp chunk4([]), do: []
  defp chunk4([a, b, c, d | rest]), do: [{a, b, c, d} | chunk4(rest)]

  defp build_strings([], _blob), do: []

  defp build_strings([off, len | rest], blob),
    do: [binary_part(blob, off, len) | build_strings(rest, blob)]

  defp running_max(list) do
    {acc, _} =
      Enum.map_reduce(list, 0, fn e, m ->
        nm = max(m, e)
        {nm, nm}
      end)

    acc
  end

  defp compute_weights([], _values), do: Map.new(Enum.zip(@flags, @sev))

  defp compute_weights(v4v, values) do
    values_t = List.to_tuple(values)
    bits_list = Enum.map(v4v, fn vid -> elem(elem(values_t, vid), 0) end)
    tot = length(bits_list)

    @flags
    |> Enum.with_index()
    |> Enum.map(fn {f, i} ->
      mask = bsl(1, i)
      cnt = Enum.count(bits_list, fn b -> band(b, mask) != 0 end)
      w = Enum.at(@sev, i) * (1 + :math.log2(tot / max(cnt, 1)) / 24)
      {f, w}
    end)
    |> Map.new()
  end

  def upper_bound(tup, x, n) do
    ub(tup, x, 0, n)
  end

  defp ub(_tup, _x, lo, hi) when lo >= hi, do: lo

  defp ub(tup, x, lo, hi) do
    mid = div(lo + hi, 2)
    if elem(tup, mid) <= x, do: ub(tup, x, mid + 1, hi), else: ub(tup, x, lo, mid)
  end

  def hits(db, ip, true) do
    n = db.v4n
    if n == 0, do: [], else: collect(db.v4s, db.v4e, db.v4m, db.v4v, ip, upper_bound(db.v4s, ip, n))
  end

  def hits(db, ip, false) do
    n = db.v6cn
    if n == 0, do: [], else: collect(db.v6s, db.v6e, db.v6m, db.v6v, ip, upper_bound(db.v6s, ip, n))
  end

  defp collect(s, e, m, v, ip, i, acc \\ [])
  defp collect(_, _, _, _, _, 0, acc), do: Enum.reverse(acc)

  defp collect(s, e, m, v, ip, i, acc) do
    j = i - 1
    if elem(m, j) < ip do
      Enum.reverse(acc)
    else
      acc2 =
        if elem(e, j) >= ip,
          do: [{elem(s, j), elem(e, j), elem(v, j)} | acc],
          else: acc

      collect(s, e, m, v, ip, j, acc2)
    end
  end

  def parse_ip(str) do
    cl = String.to_charlist(str)

    case :inet.parse_address(cl) do
      {:ok, {a, b, c, d}} ->
        {bsl(a, 24) ||| bsl(b, 16) ||| bsl(c, 8) ||| d, true}

      {:ok, {a, b, c, d, e, f, g, h}} ->
        n =
          bsl(a, 112) ||| bsl(b, 96) ||| bsl(c, 80) ||| bsl(d, 64) |||
            bsl(e, 48) ||| bsl(f, 32) ||| bsl(g, 16) ||| h

        {n, false}

      _ ->
        raise "invalid ip"
    end
  end

  def fmt_ip(n, true) do
    a = band(bsr(n, 24), 255)
    b = band(bsr(n, 16), 255)
    c = band(bsr(n, 8), 255)
    d = band(n, 255)
    List.to_string(:inet.ntoa({a, b, c, d}))
  end

  def fmt_ip(n, false) do
    parts = for i <- 7..0//-1, do: band(bsr(n, i * 16), 0xFFFF)
    [a, b, c, d, e, f, g, h] = parts
    List.to_string(:inet.ntoa({a, b, c, d, e, f, g, h}))
  end

  def round1(v) do
    Float.round(v * 1.0, 1)
  end

  def lookup(db, ip_str) do
    {ip, v4} = parse_ip(ip_str)

    matches =
      hits(db, ip, v4)
      |> Enum.map(fn {s, e, vid} ->
        {bits, prov, src, _} = elem(db.values, vid)

        flags =
          0..19
          |> Enum.filter(fn i -> band(bits, bsl(1, i)) != 0 end)
          |> Enum.map(&Enum.at(@flags, &1))

        w =
          case flags do
            [] -> 0.0
            _ -> flags |> Enum.map(&db.weights[&1]) |> Enum.max()
          end

        %{
          source: elem(db.strings, src),
          provider: elem(db.strings, prov),
          range: "#{fmt_ip(s, v4)}-#{fmt_ip(e, v4)}",
          flags: flags,
          weight: round1(w)
        }
      end)
      |> Enum.sort_by(& &1.weight, :desc)

    ranked =
      matches
      |> Enum.flat_map(& &1.flags)
      |> Enum.uniq()
      |> Enum.sort_by(&(-db.weights[&1]))

    sources =
      matches
      |> Enum.map(&{&1.provider, &1.source})
      |> MapSet.new()

    score =
      case ranked do
        [] ->
          0.0

        [h | t] ->
          base = db.weights[h] + Enum.sum(Enum.map(t, &db.weights[&1])) * 0.15
          round1(min(100.0, base * (1 + 0.08 * :math.log2(MapSet.size(sources) + 1))))
      end

    all_flags = matches |> Enum.flat_map(& &1.flags) |> Enum.uniq()

    providers =
      matches
      |> Enum.map(& &1.provider)
      |> Enum.reject(&(&1 == ""))
      |> Enum.uniq()

    providers =
      if Enum.any?(providers, &(String.downcase(&1) == "tor")) do
        ["Tor" | Enum.reject(providers, &(String.downcase(&1) == "tor"))]
      else
        providers
      end

    verdict =
      cond do
        matches == [] -> "clean"
        true -> (Enum.find(@levels, fn {t, _} -> score >= t end) || {0, "minimal"}) |> elem(1)
      end

    %{
      ip: ip_str,
      found: matches != [],
      verdict: verdict,
      score: score,
      detections: length(matches),
      sources: MapSet.size(sources),
      top_provider: List.first(providers) || "",
      providers: providers,
      flags: all_flags,
      reasons: Enum.take(ranked, 5),
      matches: matches
    }
  end
end

defmodule JSON do
  def encode(v), do: enc(v, 0) |> IO.iodata_to_binary()

  defp enc(nil, _), do: "null"
  defp enc(true, _), do: "true"
  defp enc(false, _), do: "false"
  defp enc(v, _) when is_integer(v), do: Integer.to_string(v)
  defp enc(v, _) when is_float(v), do: num(v)
  defp enc(v, _) when is_binary(v), do: [?", esc(v), ?"]

  defp enc([], _), do: "[]"

  defp enc(list, depth) when is_list(list) do
    pad = String.duplicate("  ", depth + 1)
    close = String.duplicate("  ", depth)
    items = Enum.map(list, fn x -> [pad, enc(x, depth + 1)] end)
    ["[\n", Enum.intersperse(items, ",\n"), "\n", close, "]"]
  end

  defp enc(m, depth) when is_map(m) do
    pairs = Map.to_list(m)
    if pairs == [] do
      "{}"
    else
      pad = String.duplicate("  ", depth + 1)
      close = String.duplicate("  ", depth)

      items =
        Enum.map(pairs, fn {k, v} ->
          [pad, ?", to_string(k), ?", ": ", enc(v, depth + 1)]
        end)

      ["{\n", Enum.intersperse(items, ",\n"), "\n", close, "}"]
    end
  end

  defp num(v) do
    t = trunc(v)
    if v == t * 1.0, do: "#{t}.0", else: :erlang.float_to_binary(v, decimals: 1)
  end

  defp esc(s) do
    for <<c <- s>>, into: <<>> do
      case c do
        ?" -> "\\\""
        ?\\ -> "\\\\"
        ?\n -> "\\n"
        ?\r -> "\\r"
        ?\t -> "\\t"
        c when c < 0x20 -> :io_lib.format("\\u~4.16.0b", [c]) |> IO.iodata_to_binary()
        c -> <<c>>
      end
    end
  end
end

ip = List.first(System.argv()) || "8.8.8.8"
db = Intel.load("../intel.bin")
result = Intel.lookup(db, ip)

ordered = [
  {"ip", result.ip},
  {"found", result.found},
  {"verdict", result.verdict},
  {"score", result.score},
  {"detections", result.detections},
  {"sources", result.sources},
  {"top_provider", result.top_provider},
  {"providers", result.providers},
  {"flags", result.flags},
  {"reasons", result.reasons},
  {"matches", Enum.map(result.matches, fn m ->
    [
      {"source", m.source},
      {"provider", m.provider},
      {"range", m.range},
      {"flags", m.flags},
      {"weight", m.weight}
    ]
  end)}
]

defmodule Out do
  def render(pairs) do
    inner =
      pairs
      |> Enum.map(fn {k, v} -> ["  \"", k, "\": ", encv(v, 1)] end)
      |> Enum.intersperse(",\n")

    IO.iodata_to_binary(["{\n", inner, "\n}"])
  end

  defp encv(v, _) when is_binary(v), do: [?", JSON.encode(v) |> String.slice(1..-2//1), ?"]
  defp encv(v, _) when is_boolean(v), do: if(v, do: "true", else: "false")
  defp encv(v, _) when is_integer(v), do: Integer.to_string(v)
  defp encv(v, _) when is_float(v), do: numf(v)

  defp encv([], _), do: "[]"

  defp encv(list, depth) when is_list(list) do
    pad = String.duplicate("  ", depth + 1)
    close = String.duplicate("  ", depth)

    items =
      Enum.map(list, fn x ->
        case x do
          pairs when is_list(pairs) ->
            case pairs do
              [{_, _} | _] ->
                inner =
                  pairs
                  |> Enum.map(fn {k, v} -> [pad, "  \"", k, "\": ", encv(v, depth + 2)] end)
                  |> Enum.intersperse(",\n")

                [pad, "{\n", inner, "\n", pad, "}"]

              _ ->
                [pad, encv(x, depth + 1)]
            end

          _ ->
            [pad, encv(x, depth + 1)]
        end
      end)
      |> Enum.intersperse(",\n")

    ["[\n", items, "\n", close, "]"]
  end

  defp numf(v) do
    t = trunc(v)
    if v == t * 1.0, do: "#{t}.0", else: :erlang.float_to_binary(v, decimals: 1)
  end
end

IO.puts(Out.render(ordered))

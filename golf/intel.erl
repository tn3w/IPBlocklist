#!/usr/bin/env escript
%%! -smp disable

-mode(compile).

flags() ->
    ["vpn","proxy","tor","malware","c2","scanner","brute_force","spammer",
     "compromised","datacenter","cdn","anycast","crawler","bot","cloud",
     "private_relay","anonymizer","mobile","isp","government"].

sev() -> [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0].

levels() -> [{80,"critical"},{60,"high"},{35,"medium"},{15,"low"}].

main([IpStr]) ->
    {ok, D} = file:read_file("../intel.bin"),
    <<Ver:32/little, _:32, Rest/binary>> = D,
    case Ver of
        6 -> ok;
        _ -> io:format("unsupported version ~p~n", [Ver]), halt(1)
    end,
    {Hdr, _} = split_binary(Rest, 19*8),
    [Cn,Ln,V6n,Valn,Strn,Bucket,StartsLo,Lens,Vals,Lstarts,Lends,Lvals,
     V6s,V6e,V6v,Vt,Si,Sd,Sl] = [X || <<X:64/little>> <= Hdr],
    Bi = read_u32s(D, Bucket, 65537),
    Slo = read_u16s(D, StartsLo, Cn),
    LensA = read_u16s(D, Lens, Cn),
    ValsA = read_u16s(D, Vals, Cn),
    LstartsA = read_u32s(D, Lstarts, Ln),
    LendsA = read_u32s(D, Lends, Ln),
    LvalsA = read_u16s(D, Lvals, Ln),
    V6sA = read_u128s(D, V6s, V6n),
    V6eA = read_u128s(D, V6e, V6n),
    V6vA = read_u16s(D, V6v, V6n),
    Values = read_vt(D, Vt, Valn),
    Sidx = read_si(D, Si, Strn),
    <<_:Sd/binary, Blob:Sl/binary, _/binary>> = D,
    Strings = [decode_str(Blob, Off, L) || {Off, L} <- Sidx],
    Small = expand_small(Bi, Slo, LensA, ValsA),
    Large = lists:zip3(LstartsA, LendsA, LvalsA),
    V4Sorted = lists:keysort(1, Small ++ Large),
    {V4s, V4e_, V4v} = unzip3(V4Sorted),
    V4Max = running_max(V4e_),
    V6Max = running_max(V6eA),
    Weights = weights(V4v, Values),
    {ok, Addr} = inet:parse_address(IpStr),
    Ip = ip_to_int(Addr),
    IsV4 = tuple_size(Addr) == 4,
    Hits = case IsV4 of
        true -> hits(V4s, V4e_, V4Max, V4v, Ip);
        false -> hits(V6sA, V6eA, V6Max, V6vA, Ip)
    end,
    Matches = build_matches(Hits, Values, Strings, Weights, IsV4),
    Sorted = lists:sort(fun(A, B) ->
        maps:get(weight, A) >= maps:get(weight, B) end, Matches),
    Result = summarize(IpStr, Sorted, Weights),
    io:format("~s~n", [to_json(Result)]);
main(_) -> main(["8.8.8.8"]).

read_u32s(_, _, 0) -> [];
read_u32s(D, Off, N) ->
    Sz = N * 4,
    <<_:Off/binary, S:Sz/binary, _/binary>> = D,
    [X || <<X:32/little>> <= S].

read_u16s(_, _, 0) -> [];
read_u16s(D, Off, N) ->
    Sz = N * 2,
    <<_:Off/binary, S:Sz/binary, _/binary>> = D,
    [X || <<X:16/little>> <= S].

read_u128s(_, _, 0) -> [];
read_u128s(D, Off, N) ->
    Sz = N * 16,
    <<_:Off/binary, S:Sz/binary, _/binary>> = D,
    [(Hi bsl 64) bor Lo || <<Lo:64/little, Hi:64/little>> <= S].

read_vt(_, _, 0) -> [];
read_vt(D, Off, N) ->
    Sz = N * 16,
    <<_:Off/binary, S:Sz/binary, _/binary>> = D,
    [{B, P, Sr, X} || <<B:32/little, P:32/little, Sr:32/little, X:32/little>> <= S].

read_si(_, _, 0) -> [];
read_si(D, Off, N) ->
    Sz = N * 8,
    <<_:Off/binary, S:Sz/binary, _/binary>> = D,
    [{O, L} || <<O:32/little, L:32/little>> <= S].

decode_str(Blob, Off, L) ->
    <<_:Off/binary, S:L/binary, _/binary>> = Blob,
    binary_to_list(S).

expand_small(Bi, Slo, Lens, Vals) ->
    expand_small(Bi, Slo, Lens, Vals, 0, []).

expand_small([_], _, _, _, _, Acc) -> lists:reverse(Acc);
expand_small([A, B | RB], Slo, Lens, Vals, Idx, Acc) ->
    Cnt = B - A,
    {Hs, Rs} = take(Slo, Cnt),
    {Hl, Rl} = take(Lens, Cnt),
    {Hv, Rv} = take(Vals, Cnt),
    Entries = [begin
        Start = (Idx bsl 16) bor S,
        {Start, Start + L, V}
    end || {S, L, V} <- lists:zip3(Hs, Hl, Hv)],
    expand_small([B | RB], Rs, Rl, Rv, Idx + 1,
                 lists:reverse(Entries) ++ Acc).

take(L, N) -> lists:split(N, L).

unzip3([]) -> {[], [], []};
unzip3(L) ->
    {A, B, C} = lists:foldr(fun({X, Y, Z}, {As, Bs, Cs}) ->
        {[X|As], [Y|Bs], [Z|Cs]} end, {[], [], []}, L),
    {A, B, C}.

running_max([]) -> [];
running_max([H | T]) ->
    {_, R} = lists:mapfoldl(fun(X, M) ->
        Nm = max(X, M), {Nm, Nm} end, H, [H | T]),
    R.

weights(V4v, Values) ->
    Flags = flags(),
    Sevs = sev(),
    case V4v of
        [] -> maps:from_list(lists:zip(Flags, [float(S) || S <- Sevs]));
        _ ->
            Tot = length(V4v),
            Bits = [element(1, lists:nth(V+1, Values)) || V <- V4v],
            maps:from_list([begin
                C = length([1 || B <- Bits, (B bsr I) band 1 == 1]),
                W = S * (1 + math:log2(Tot / max(C, 1)) / 24),
                {F, W}
            end || {I, F, S} <- lists:zip3(lists:seq(0, 19), Flags, Sevs)])
    end.

ip_to_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
ip_to_int({A, B, C, D, E, F, G, H}) ->
    (A bsl 112) bor (B bsl 96) bor (C bsl 80) bor (D bsl 64) bor
    (E bsl 48) bor (F bsl 32) bor (G bsl 16) bor H.

int_to_v4(N) ->
    {(N bsr 24) band 255, (N bsr 16) band 255,
     (N bsr 8) band 255, N band 255}.

int_to_v6(N) ->
    {(N bsr 112) band 65535, (N bsr 96) band 65535,
     (N bsr 80) band 65535, (N bsr 64) band 65535,
     (N bsr 48) band 65535, (N bsr 32) band 65535,
     (N bsr 16) band 65535, N band 65535}.

hits([], _, _, _, _) -> [];
hits(S, E, M, V, Ip) ->
    Sa = list_to_tuple(S),
    Ea = list_to_tuple(E),
    Ma = list_to_tuple(M),
    Va = list_to_tuple(V),
    N = tuple_size(Sa),
    I = upper_bound(Sa, Ip, 1, N + 1),
    collect(I - 1, Sa, Ea, Ma, Va, Ip, []).

upper_bound(_, _, Lo, Hi) when Lo >= Hi -> Lo;
upper_bound(Sa, Ip, Lo, Hi) ->
    Mid = (Lo + Hi) div 2,
    case element(Mid, Sa) =< Ip of
        true -> upper_bound(Sa, Ip, Mid + 1, Hi);
        false -> upper_bound(Sa, Ip, Lo, Mid)
    end.

collect(0, _, _, _, _, _, Acc) -> lists:reverse(Acc);
collect(I, Sa, Ea, Ma, Va, Ip, Acc) ->
    case element(I, Ma) < Ip of
        true -> lists:reverse(Acc);
        false ->
            End = element(I, Ea),
            Acc2 = case End >= Ip of
                true -> [{element(I, Sa), End, element(I, Va)} | Acc];
                false -> Acc
            end,
            collect(I - 1, Sa, Ea, Ma, Va, Ip, Acc2)
    end.

build_matches(Hits, Values, Strings, Weights, IsV4) ->
    Flags = flags(),
    [begin
        {Bits, Prov, Src, _} = lists:nth(Vid + 1, Values),
        Fs = [lists:nth(I+1, Flags) ||
              I <- lists:seq(0, 19), (Bits bsr I) band 1 == 1],
        W = case Fs of
            [] -> 0.0;
            _ -> round1(lists:max([maps:get(F, Weights) || F <- Fs]))
        end,
        #{source => lists:nth(Src + 1, Strings),
          provider => lists:nth(Prov + 1, Strings),
          range => fmt_range(S, E, IsV4),
          flags => Fs, weight => W}
    end || {S, E, Vid} <- Hits].

fmt_range(S, E, true) ->
    inet:ntoa(int_to_v4(S)) ++ "-" ++ inet:ntoa(int_to_v4(E));
fmt_range(S, E, false) ->
    inet:ntoa(int_to_v6(S)) ++ "-" ++ inet:ntoa(int_to_v6(E)).

round1(X) -> round(X * 10) / 10.

summarize(IpStr, Matches, Weights) ->
    AllFlagsRaw = lists:flatten([maps:get(flags, M) || M <- Matches]),
    Ranked = lists:sort(fun(A, B) ->
        maps:get(A, Weights) >= maps:get(B, Weights)
    end, dedup(AllFlagsRaw)),
    Sources = sets:from_list([{maps:get(provider, M), maps:get(source, M)}
                              || M <- Matches]),
    Nsrc = sets:size(Sources),
    Score = case Ranked of
        [] -> 0.0;
        [H | T] ->
            Base = maps:get(H, Weights) +
                   lists:sum([maps:get(F, Weights) || F <- T]) * 0.15,
            round1(min(100, Base * (1 + 0.08 * math:log2(Nsrc + 1))))
    end,
    AllFlags = dedup(AllFlagsRaw),
    ProvRaw = dedup([maps:get(provider, M) || M <- Matches,
                                              maps:get(provider, M) =/= ""]),
    Providers = case lists:any(fun(P) -> string:lowercase(P) == "tor" end, ProvRaw) of
        true -> ["Tor" | [P || P <- ProvRaw, string:lowercase(P) =/= "tor"]];
        false -> ProvRaw
    end,
    TopProv = case Providers of [] -> ""; [P|_] -> P end,
    Verdict = case Matches of
        [] -> "clean";
        _ ->
            case [N || {T, N} <- levels(), Score >= T] of
                [] -> "minimal";
                [N|_] -> N
            end
    end,
    Reasons = lists:sublist(Ranked, 5),
    #{ip => IpStr, found => Matches =/= [], verdict => Verdict,
      score => Score, detections => length(Matches), sources => Nsrc,
      top_provider => TopProv, providers => Providers, flags => AllFlags,
      reasons => Reasons, matches => Matches}.

dedup(L) -> dedup(L, [], sets:new()).
dedup([], Acc, _) -> lists:reverse(Acc);
dedup([H | T], Acc, S) ->
    case sets:is_element(H, S) of
        true -> dedup(T, Acc, S);
        false -> dedup(T, [H | Acc], sets:add_element(H, S))
    end.

num(V) when is_float(V) ->
    case V == trunc(V) of
        true -> integer_to_list(trunc(V)) ++ ".0";
        false -> lists:flatten(io_lib:format("~.1f", [V]))
    end;
num(V) when is_integer(V) -> integer_to_list(V).

jstr(S) when is_list(S) -> [$", esc(S), $"];
jstr(S) when is_binary(S) -> jstr(binary_to_list(S)).

esc([]) -> [];
esc([$" | T]) -> [$\\, $" | esc(T)];
esc([$\\ | T]) -> [$\\, $\\ | esc(T)];
esc([$\n | T]) -> [$\\, $n | esc(T)];
esc([$\r | T]) -> [$\\, $r | esc(T)];
esc([$\t | T]) -> [$\\, $t | esc(T)];
esc([C | T]) when C < 32 -> io_lib:format("\\u~4.16.0b", [C]) ++ esc(T);
esc([C | T]) -> [C | esc(T)].

jarr_strs(L, Ind) ->
    case L of
        [] -> "[]";
        _ ->
            Items = [[Ind, "  ", jstr(X)] || X <- L],
            ["[\n", lists:join(",\n", Items), "\n", Ind, "]"]
    end.

jbool(true) -> "true";
jbool(false) -> "false".

jmatch(M, Ind) ->
    Src = maps:get(source, M),
    Pr = maps:get(provider, M),
    Rg = maps:get(range, M),
    Fs = maps:get(flags, M),
    W = maps:get(weight, M),
    Inner = Ind ++ "  ",
    [
        "{\n",
        Inner, "\"source\": ", jstr(Src), ",\n",
        Inner, "\"provider\": ", jstr(Pr), ",\n",
        Inner, "\"range\": ", jstr(Rg), ",\n",
        Inner, "\"flags\": ", jarr_strs(Fs, Inner), ",\n",
        Inner, "\"weight\": ", num(W), "\n",
        Ind, "}"
    ].

jmatches(L, Ind) ->
    case L of
        [] -> "[]";
        _ ->
            Inner = Ind ++ "  ",
            Items = [[Inner, jmatch(M, Inner)] || M <- L],
            ["[\n", lists:join(",\n", Items), "\n", Ind, "]"]
    end.

to_json(R) ->
    Ind = "  ",
    [
        "{\n",
        Ind, "\"ip\": ", jstr(maps:get(ip, R)), ",\n",
        Ind, "\"found\": ", jbool(maps:get(found, R)), ",\n",
        Ind, "\"verdict\": ", jstr(maps:get(verdict, R)), ",\n",
        Ind, "\"score\": ", num(maps:get(score, R)), ",\n",
        Ind, "\"detections\": ", num(maps:get(detections, R)), ",\n",
        Ind, "\"sources\": ", num(maps:get(sources, R)), ",\n",
        Ind, "\"top_provider\": ", jstr(maps:get(top_provider, R)), ",\n",
        Ind, "\"providers\": ", jarr_strs(maps:get(providers, R), Ind), ",\n",
        Ind, "\"flags\": ", jarr_strs(maps:get(flags, R), Ind), ",\n",
        Ind, "\"reasons\": ", jarr_strs(maps:get(reasons, R), Ind), ",\n",
        Ind, "\"matches\": ", jmatches(maps:get(matches, R), Ind), "\n",
        "}"
    ].

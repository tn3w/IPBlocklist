<?php
ini_set('memory_limit', '1G');
$FLAGS =['vpn','proxy','tor','malware','c2','scanner','brute_force','spammer','compromised','datacenter','cdn','anycast','crawler','bot','cloud','private_relay','anonymizer','mobile','isp','government'];
$SEV = [30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0];
$LEVELS = [[80,'critical'],[60,'high'],[35,'medium'],[15,'low']];

function load($path) {
    $d = file_get_contents($path);
    if (unpack('V', substr($d, 0, 4))[1] !== 6) { fwrite(STDERR, "bad version\n"); exit(1); }
    $o = array_values(unpack('P19', substr($d, 8, 152)));
    [$cn, $ln, $v6n, $valn, $strn] = $o;
    $off = array_slice($o, 5);

    $bi = array_values(unpack("V65537", substr($d, $off[0], 65537 * 4)));
    $slo = $cn ? array_values(unpack("v$cn", substr($d, $off[1], $cn * 2))) : [];
    $lens = $cn ? array_values(unpack("v$cn", substr($d, $off[2], $cn * 2))) : [];
    $sv = $cn ? array_values(unpack("v$cn", substr($d, $off[3], $cn * 2))) : [];
    $ls = $ln ? array_values(unpack("V$ln", substr($d, $off[4], $ln * 4))) : [];
    $le = $ln ? array_values(unpack("V$ln", substr($d, $off[5], $ln * 4))) : [];
    $lv = $ln ? array_values(unpack("v$ln", substr($d, $off[6], $ln * 2))) : [];

    $N = $cn + $ln;
    $s = array_fill(0, $N, 0); $e = array_fill(0, $N, 0); $v = array_fill(0, $N, 0);
    for ($b = 0, $j = 0; $b < 65536; $b++) {
        for (; $j < $bi[$b+1]; $j++) {
            $s[$j] = ($b << 16) | $slo[$j];
            $e[$j] = $s[$j] + $lens[$j];
            $v[$j] = $sv[$j];
        }
    }
    for ($i = 0; $i < $ln; $i++) {
        $s[$cn+$i] = $ls[$i]; $e[$cn+$i] = $le[$i]; $v[$cn+$i] = $lv[$i];
    }
    $idx = range(0, $N - 1);
    usort($idx, fn($a, $b) => $s[$a] <=> $s[$b]);
    $v4s = []; $v4e = []; $v4v = [];
    foreach ($idx as $i) { $v4s[] = $s[$i]; $v4e[] = $e[$i]; $v4v[] = $v[$i]; }
    $v4m = []; $mx = 0;
    for ($i = 0; $i < $N; $i++) { if ($v4e[$i] > $mx) $mx = $v4e[$i]; $v4m[] = $mx; }

    $v6 = function($oo) use ($d, $v6n) {
        if (!$v6n) return [];
        $raw = array_values(unpack("P" . ($v6n * 2), substr($d, $oo, $v6n * 16)));
        $r = [];
        for ($i = 0; $i < $v6n; $i++) $r[] = [$raw[$i*2+1], $raw[$i*2]];
        return $r;
    };
    $v6s = $v6($off[7]); $v6e = $v6($off[8]);
    $v6v = $v6n ? array_values(unpack("v$v6n", substr($d, $off[9], $v6n * 2))) : [];
    $v6m = []; $mh = 0; $ml = 0;
    foreach ($v6e as $p) {
        if (cmp6($p, [$mh, $ml]) > 0) { [$mh, $ml] = $p; }
        $v6m[] = [$mh, $ml];
    }

    $vt = $valn ? array_values(unpack("V" . ($valn * 4), substr($d, $off[10], $valn * 16))) : [];
    $sd = $off[12]; $sl = $off[13];
    $sidx = $strn ? array_values(unpack("V" . ($strn * 2), substr($d, $off[11], $strn * 8))) : [];
    $blob = substr($d, $sd, $sl);
    $st = [];
    for ($i = 0; $i < $strn; $i++) $st[] = substr($blob, $sidx[$i*2], $sidx[$i*2+1]);

    $w = [];
    if ($N > 0) {
        $c = array_fill(0, 20, 0);
        foreach ($v4v as $vid) {
            $b = $vt[$vid * 4];
            for ($i = 0; $i < 20; $i++) if ($b & (1 << $i)) $c[$i]++;
        }
        for ($i = 0; $i < 20; $i++) {
            global $FLAGS, $SEV;
            $cc = $c[$i] ?: 1;
            $w[$FLAGS[$i]] = $SEV[$i] * (1 + log($N / $cc, 2) / 24);
        }
    } else {
        global $FLAGS, $SEV;
        foreach ($FLAGS as $i => $f) $w[$f] = $SEV[$i];
    }
    return compact('v4s','v4e','v4m','v4v','v6s','v6e','v6m','v6v','vt','st','w');
}

function cmp6($a, $b) {
    if ($a[0] !== $b[0]) return ($a[0] <=> $b[0]) | 0;
    return ($a[1] <=> $b[1]) | 0;
}

function upper_u32($a, $ip) {
    $lo = 0; $hi = count($a);
    while ($lo < $hi) { $m = ($lo + $hi) >> 1; if ($a[$m] > $ip) $hi = $m; else $lo = $m + 1; }
    return $lo;
}
function upper_u128($a, $ip) {
    $lo = 0; $hi = count($a);
    while ($lo < $hi) { $m = ($lo + $hi) >> 1; if (cmp6($a[$m], $ip) > 0) $hi = $m; else $lo = $m + 1; }
    return $lo;
}

function fmt6($p) {
    $bytes = pack('J2', $p[0], $p[1]);
    return inet_ntop($bytes);
}

function lookup($db, $ip_str) {
    global $FLAGS, $LEVELS;
    $is_v6 = str_contains($ip_str, ':');
    $bin = inet_pton($ip_str);
    $matches = [];
    $push = function($vid, $rng) use (&$matches, $db, $FLAGS) {
        $b = $db['vt'][$vid * 4];
        $fl = []; $mxw = 0.0;
        for ($i = 0; $i < 20; $i++) {
            if ($b & (1 << $i)) {
                $fl[] = $FLAGS[$i];
                $w = $db['w'][$FLAGS[$i]];
                if ($w > $mxw) $mxw = $w;
            }
        }
        $matches[] = [
            'source' => $db['st'][$db['vt'][$vid*4+2]],
            'provider' => $db['st'][$db['vt'][$vid*4+1]],
            'range' => $rng,
            'flags' => $fl,
            'weight' => round($mxw, 1),
        ];
    };

    if (!$is_v6) {
        $ip = unpack('N', $bin)[1];
        $i = upper_u32($db['v4s'], $ip);
        while ($i > 0) {
            $i--;
            if ($db['v4m'][$i] < $ip) break;
            if ($db['v4e'][$i] >= $ip) {
                $s = long2ip($db['v4s'][$i]); $e = long2ip($db['v4e'][$i]);
                $push($db['v4v'][$i], "$s-$e");
            }
        }
    } else {
        $u = unpack('J2', $bin);
        $ip = [$u[1], $u[2]];
        $i = upper_u128($db['v6s'], $ip);
        while ($i > 0) {
            $i--;
            if (cmp6($db['v6m'][$i], $ip) < 0) break;
            if (cmp6($db['v6e'][$i], $ip) >= 0) {
                $push($db['v6v'][$i], fmt6($db['v6s'][$i]) . '-' . fmt6($db['v6e'][$i]));
            }
        }
    }
    usort($matches, fn($a, $b) => $b['weight'] <=> $a['weight']);

    $all_flags = []; $providers = []; $sources = [];
    foreach ($matches as $m) {
        foreach ($m['flags'] as $f) if (!in_array($f, $all_flags)) $all_flags[] = $f;
        if ($m['provider'] && !in_array($m['provider'], $providers)) $providers[] = $m['provider'];
        $sources[$m['provider'] . '|' . $m['source']] = true;
    }
    $ranked = $all_flags;
    usort($ranked, fn($a, $b) => $db['w'][$b] <=> $db['w'][$a]);
    $score = 0.0;
    if ($ranked) {
        $top = $db['w'][$ranked[0]];
        $ex = 0.0;
        foreach (array_slice($ranked, 1) as $f) $ex += $db['w'][$f];
        $score = round(min(100, ($top + $ex * 0.15) * (1 + 0.08 * log(count($sources) + 1, 2))), 1);
    }
    $verdict = 'clean';
    if ($matches) {
        $verdict = 'minimal';
        foreach ($LEVELS as [$t, $n]) if ($score >= $t) { $verdict = $n; break; }
    }
    foreach ($providers as $i => $p) {
        if (strcasecmp($p, 'tor') === 0) {
            array_splice($providers, $i, 1);
            array_unshift($providers, 'Tor');
            break;
        }
    }
    return [
        'ip' => $ip_str,
        'found' => !empty($matches),
        'verdict' => $verdict,
        'score' => $score,
        'detections' => count($matches),
        'sources' => count($sources),
        'top_provider' => $providers[0] ?? '',
        'providers' => $providers,
        'flags' => $all_flags,
        'reasons' => array_slice($ranked, 0, 5),
        'matches' => $matches,
    ];
}

$db = load('../intel.bin');
$ip = $argv[1] ?? '8.8.8.8';
echo json_encode(lookup($db, $ip), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

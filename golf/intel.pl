#!/usr/bin/perl
use strict;
use warnings;
use Socket qw(inet_pton inet_ntop AF_INET AF_INET6);
use List::Util qw(min max sum0);
use JSON::PP;

my @FLAGS = qw(vpn proxy tor malware c2 scanner brute_force spammer compromised datacenter cdn anycast crawler bot cloud private_relay anonymizer mobile isp government);
my @SEV = (30,25,45,95,95,55,70,65,75,15,5,0,10,40,10,15,35,0,0,0);
my @LEVELS = ([80,'critical'],[60,'high'],[35,'medium'],[15,'low']);

sub load_db {
    my $path = shift;
    open my $f, '<:raw', $path or die "open: $!";
    local $/;
    my $d = <$f>;
    close $f;
    my $ver = unpack 'V', substr($d, 0, 4);
    die "bad version $ver" unless $ver == 6;
    my @o = unpack 'Q<19', substr($d, 8, 152);
    my ($cn, $ln, $v6n, $valn, $strn) = @o[0..4];
    my @off = @o[5..18];

    my @bi = unpack "V65537", substr($d, $off[0], 65537 * 4);
    my @slo = $cn ? unpack "v$cn", substr($d, $off[1], $cn * 2) : ();
    my @lens = $cn ? unpack "v$cn", substr($d, $off[2], $cn * 2) : ();
    my @sv  = $cn ? unpack "v$cn", substr($d, $off[3], $cn * 2) : ();
    my @ls  = $ln ? unpack "V$ln", substr($d, $off[4], $ln * 4) : ();
    my @le2 = $ln ? unpack "V$ln", substr($d, $off[5], $ln * 4) : ();
    my @lv  = $ln ? unpack "v$ln", substr($d, $off[6], $ln * 2) : ();

    my $N = $cn + $ln;
    my (@s, @e, @v);
    $#s = $N - 1; $#e = $N - 1; $#v = $N - 1;
    my $j = 0;
    for (my $b = 0; $b < 65536; $b++) {
        while ($j < $bi[$b+1]) {
            $s[$j] = ($b << 16) | $slo[$j];
            $e[$j] = $s[$j] + $lens[$j];
            $v[$j] = $sv[$j];
            $j++;
        }
    }
    for (my $i = 0; $i < $ln; $i++) {
        $s[$cn+$i] = $ls[$i]; $e[$cn+$i] = $le2[$i]; $v[$cn+$i] = $lv[$i];
    }
    my @idx = sort { $s[$a] <=> $s[$b] } 0..$N-1;
    my (@v4s, @v4e, @v4v);
    for my $i (@idx) { push @v4s, $s[$i]; push @v4e, $e[$i]; push @v4v, $v[$i]; }
    my @v4m; my $mx = 0;
    for my $i (0..$N-1) { $mx = $v4e[$i] if $v4e[$i] > $mx; $v4m[$i] = $mx; }

    my (@v6s, @v6e);
    if ($v6n) {
        my @raw_s = unpack "Q<" . ($v6n * 2), substr($d, $off[7], $v6n * 16);
        my @raw_e = unpack "Q<" . ($v6n * 2), substr($d, $off[8], $v6n * 16);
        for (my $i = 0; $i < $v6n; $i++) {
            push @v6s, [$raw_s[$i*2+1], $raw_s[$i*2]];
            push @v6e, [$raw_e[$i*2+1], $raw_e[$i*2]];
        }
    }
    my @v6v = $v6n ? unpack "v$v6n", substr($d, $off[9], $v6n * 2) : ();
    my @v6m; my @mp = (0, 0);
    for my $p (@v6e) {
        @mp = @$p if cmp6($p, \@mp) > 0;
        push @v6m, [@mp];
    }

    my @vt = $valn ? unpack "V" . ($valn * 4), substr($d, $off[10], $valn * 16) : ();
    my $sd = $off[12]; my $sl = $off[13];
    my @sidx = $strn ? unpack "V" . ($strn * 2), substr($d, $off[11], $strn * 8) : ();
    my $blob = substr($d, $sd, $sl);
    my @st;
    for (my $i = 0; $i < $strn; $i++) {
        push @st, substr($blob, $sidx[$i*2], $sidx[$i*2+1]);
    }

    my %w;
    if ($N > 0) {
        my @c = (0) x 20;
        for my $vid (@v4v) {
            my $b = $vt[$vid * 4];
            for (my $i = 0; $i < 20; $i++) { $c[$i]++ if $b & (1 << $i); }
        }
        for (my $i = 0; $i < 20; $i++) {
            my $cc = $c[$i] || 1;
            $w{$FLAGS[$i]} = $SEV[$i] * (1 + log($N / $cc) / log(2) / 24);
        }
    } else {
        for (my $i = 0; $i < 20; $i++) { $w{$FLAGS[$i]} = $SEV[$i]; }
    }
    return {
        v4s => \@v4s, v4e => \@v4e, v4m => \@v4m, v4v => \@v4v,
        v6s => \@v6s, v6e => \@v6e, v6m => \@v6m, v6v => \@v6v,
        vt => \@vt, st => \@st, w => \%w,
    };
}

sub cmp6 { $_[0][0] <=> $_[1][0] || $_[0][1] <=> $_[1][1] }

sub upper_u32 {
    my ($a, $ip) = @_;
    my ($lo, $hi) = (0, scalar @$a);
    while ($lo < $hi) { my $m = ($lo + $hi) >> 1; $a->[$m] > $ip ? ($hi = $m) : ($lo = $m + 1); }
    $lo;
}
sub upper_u128 {
    my ($a, $ip) = @_;
    my ($lo, $hi) = (0, scalar @$a);
    while ($lo < $hi) { my $m = ($lo + $hi) >> 1; cmp6($a->[$m], $ip) > 0 ? ($hi = $m) : ($lo = $m + 1); }
    $lo;
}

sub fmt6 {
    my $p = shift;
    my $bin = pack 'Q>2', $p->[0], $p->[1];
    return inet_ntop(AF_INET6, $bin);
}

sub lookup {
    my ($db, $ip_str) = @_;
    my $is_v6 = index($ip_str, ':') >= 0;
    my @matches;
    my $push = sub {
        my ($vid, $rng) = @_;
        my $b = $db->{vt}[$vid * 4];
        my @fl; my $mxw = 0;
        for (my $i = 0; $i < 20; $i++) {
            if ($b & (1 << $i)) {
                push @fl, $FLAGS[$i];
                $mxw = $db->{w}{$FLAGS[$i]} if $db->{w}{$FLAGS[$i]} > $mxw;
            }
        }
        push @matches, {
            source => $db->{st}[$db->{vt}[$vid*4+2]],
            provider => $db->{st}[$db->{vt}[$vid*4+1]],
            range => $rng,
            flags => \@fl,
            weight => 0 + sprintf("%.1f", $mxw),
        };
    };

    if (!$is_v6) {
        my $bin = inet_pton(AF_INET, $ip_str);
        my $ip = unpack 'N', $bin;
        my $i = upper_u32($db->{v4s}, $ip);
        while ($i > 0) {
            $i--;
            last if $db->{v4m}[$i] < $ip;
            if ($db->{v4e}[$i] >= $ip) {
                my $s = inet_ntop(AF_INET, pack('N', $db->{v4s}[$i]));
                my $e = inet_ntop(AF_INET, pack('N', $db->{v4e}[$i]));
                $push->($db->{v4v}[$i], "$s-$e");
            }
        }
    } else {
        my $bin = inet_pton(AF_INET6, $ip_str);
        my @parts = unpack 'Q>2', $bin;
        my $ip = [$parts[0], $parts[1]];
        my $i = upper_u128($db->{v6s}, $ip);
        while ($i > 0) {
            $i--;
            last if cmp6($db->{v6m}[$i], $ip) < 0;
            if (cmp6($db->{v6e}[$i], $ip) >= 0) {
                $push->($db->{v6v}[$i], fmt6($db->{v6s}[$i]) . '-' . fmt6($db->{v6e}[$i]));
            }
        }
    }
    @matches = sort { $b->{weight} <=> $a->{weight} } @matches;

    my (@all_flags, @providers, %seen_f, %seen_p, %sources);
    for my $m (@matches) {
        for my $f (@{$m->{flags}}) {
            unless ($seen_f{$f}++) { push @all_flags, $f; }
        }
        if ($m->{provider} && !$seen_p{$m->{provider}}++) {
            push @providers, $m->{provider};
        }
        $sources{$m->{provider} . '|' . $m->{source}} = 1;
    }
    my @ranked = sort { $db->{w}{$b} <=> $db->{w}{$a} } @all_flags;
    my $score = 0.0;
    if (@ranked) {
        my $top = $db->{w}{$ranked[0]};
        my $ex = sum0 map { $db->{w}{$_} } @ranked[1..$#ranked];
        $score = 0 + sprintf("%.1f", min(100, ($top + $ex * 0.15) * (1 + 0.08 * log(scalar(keys %sources) + 1) / log(2))));
    }
    my $verdict = 'clean';
    if (@matches) {
        $verdict = 'minimal';
        for my $lv (@LEVELS) { if ($score >= $lv->[0]) { $verdict = $lv->[1]; last; } }
    }
    for (my $i = 0; $i < @providers; $i++) {
        if (lc $providers[$i] eq 'tor') {
            splice @providers, $i, 1;
            unshift @providers, 'Tor';
            last;
        }
    }
    return {
        ip => $ip_str,
        found => @matches ? JSON::PP::true : JSON::PP::false,
        verdict => $verdict,
        score => $score,
        detections => scalar @matches,
        sources => scalar keys %sources,
        top_provider => $providers[0] // '',
        providers => \@providers,
        flags => \@all_flags,
        reasons => [@ranked[0..min($#ranked, 4)]],
        matches => \@matches,
    };
}

my $ip = $ARGV[0] // '8.8.8.8';
my $db = load_db('../intel.bin');
my $json = JSON::PP->new->pretty->indent_length(2)->canonical(0);
print $json->encode(lookup($db, $ip));

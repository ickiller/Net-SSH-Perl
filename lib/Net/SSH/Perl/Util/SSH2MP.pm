# $Id: SSH2MP.pm,v 1.1 2001/04/16 16:08:25 btrott Exp $

package Net::SSH::Perl::Util::SSH2MP;
use strict;

use Math::Pari qw( PARI floor pari2num );

sub bitsize {
    return pari2num(floor(Math::Pari::log($_[0])/Math::Pari::log(2)) + 1);
}

sub bin2mp {
    my $s = shift;
    my $p = PARI(0);
    for my $b (split //, $s) {
        $p = $p * 256 + ord $b;
    }
    $p;
}

sub mp2bin {
    my $p = shift;
    my $base = PARI(256);
    my $res = '';
    {
        my $r = $p % $base;
        my $d = PARI($p-$r) / $base;
        $res = chr($r) . $res;
        if ($d >= $base) {
            $p = $d;
            redo;
        }
        elsif ($d != 0) {
            $res = chr($d) . $res;
        }
    }
    $res;
}

1;

package Net::SSH::Perl::Cipher::Blowfish;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl::Cipher;
use base qw/Net::SSH::Perl::Cipher/;

use Net::SSH::Perl::Cipher::CBC;
use Crypt::Blowfish;

sub new {
    my $class = shift;
    my $key = shift;
    my $blow = Crypt::Blowfish->new(substr $key, 0, 16);
    my $cbc = Net::SSH::Perl::Cipher::CBC->new($blow);
    bless { cbc => $cbc }, $class;
}

sub encrypt {
    my($ciph, $text) = @_;
    _swap_bytes($ciph->{cbc}->encrypt(_swap_bytes($text)));
}

sub decrypt {
    my($ciph, $text) = @_;
    _swap_bytes($ciph->{cbc}->decrypt(_swap_bytes($text)));
}

sub _swap_bytes {
    my @str = split //, $_[0];
    my $n = @str;
    my($i) = (0);
    my $dst;
    for ($n=$n/4; $n>0; $n--) {
        my @c;
        $c[3] = $str[$i++];
        $c[2] = $str[$i++];
        $c[1] = $str[$i++];
        $c[0] = $str[$i++];
        $dst .= join '', @c[0..3];
    }
    $dst;
}

## Return 0 (unsupported) until we can get it working.
0;

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
    my $blow = Crypt::Blowfish->new(substr $key, 0, 32);
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
    my $str = $_[0];
    $str =~ s/(.{4})/reverse $1/sge;
    $str;
}

1;

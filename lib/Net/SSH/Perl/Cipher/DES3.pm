package Net::SSH::Perl::Cipher::DES3;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl::Cipher;
use base qw/Net::SSH::Perl::Cipher/;

use Net::SSH::Perl::Cipher::CBC;
use Crypt::DES;

sub new {
    my $class = shift;
    my $key = shift;
    my $ciph = {};

    for my $i (1..3) {
        my $this_key = $i == 3 && length($key) <= 16 ?
            substr $key, 0, 8 :
            substr $key, 8*($i-1), 8;
        $ciph->{"cbc$i"} = Net::SSH::Perl::Cipher::CBC->new(
            Crypt::DES->new($this_key)
        );
    }

    bless $ciph, $class;
}

sub encrypt {
    my($ciph, $text) = @_;
    $ciph->{cbc3}->encrypt(
        $ciph->{cbc2}->decrypt(
            $ciph->{cbc1}->encrypt($text)
        )
    );
}

sub decrypt {
    my($ciph, $text) = @_;
    $ciph->{cbc1}->decrypt(
        $ciph->{cbc2}->encrypt(
            $ciph->{cbc3}->decrypt($text)
        )
    );
}

1;

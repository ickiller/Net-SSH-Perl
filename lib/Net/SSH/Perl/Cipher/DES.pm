package Net::SSH::Perl::Cipher::DES;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl::Cipher;
use base qw/Net::SSH::Perl::Cipher/;

use Net::SSH::Perl::Cipher::CBC;
use Crypt::DES;

sub new {
    my $class = shift;
    my $key = shift;
    my $des = Crypt::DES->new(substr $key, 0, 8);
    my $cbc = Net::SSH::Perl::Cipher::CBC->new($des);
    bless { cbc => $cbc }, $class;
}

sub encrypt {
    my($ciph, $text) = @_;
    $ciph->{cbc}->encrypt($text);
}

sub decrypt {
    my($ciph, $text) = @_;
    $ciph->{cbc}->decrypt($text);
}

1;

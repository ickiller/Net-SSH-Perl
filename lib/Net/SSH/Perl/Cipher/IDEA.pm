package Net::SSH::Perl::Cipher::IDEA;

use strict;
use Carp qw/croak/;

use Net::SSH::Perl::Cipher;
use base qw/Net::SSH::Perl::Cipher/;

use Net::SSH::Perl::Cipher::CFB;
use Crypt::IDEA;

sub new {
    my $class = shift;
    my $key = shift;
    my $idea = IDEA->new(substr $key, 0, 16);
    my $cfb = Net::SSH::Perl::Cipher::CFB->new($idea);
    bless { cfb => $cfb }, $class;
}

sub encrypt {
    my($ciph, $text) = @_;
    $ciph->{cfb}->encrypt($text);
}

sub decrypt {
    my($ciph, $text) = @_;
    $ciph->{cfb}->decrypt($text);
}

1;

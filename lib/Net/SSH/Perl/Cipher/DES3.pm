# $Id: DES3.pm,v 1.4 2001/03/05 22:54:16 btrott Exp $

package Net::SSH::Perl::Cipher::DES3;

use strict;

use Net::SSH::Perl::Cipher;
use base qw( Net::SSH::Perl::Cipher );

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
__END__

=head1 NAME

Net::SSH::Perl::Cipher::DES3 - Wrapper for SSH 3DES support

=head1 SYNOPSIS

    use Net::SSH::Cipher;
    my $cipher = Net::SSH::Cipher->new('DES3', $key);
    print $cipher->encrypt($plaintext);

=head1 DESCRIPTION

I<Net::SSH::Perl::Cipher::DES3> provides 3DES encryption
support for I<Net::SSH::Perl>. To do so it wraps around
I<Crypt::DES>, a C/XS implementation of the DES algorithm.

The 3DES (three-key triple-DES) algorithm used here is in
CBC mode with a key length of 24 bytes.

The first 8 bytes of the key are used as the first DES
key, the second 8 bytes for the second key, etc. If the
key I<$key> that you pass to I<new> is only 16 bytes, the
first 8 bytes of I<$key> will be used as the key for both
the first and third DES ciphers.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut

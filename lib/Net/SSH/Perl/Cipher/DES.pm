# $Id: DES.pm,v 1.4 2001/03/05 22:54:16 btrott Exp $

package Net::SSH::Perl::Cipher::DES;

use strict;

use Net::SSH::Perl::Cipher;
use base qw( Net::SSH::Perl::Cipher );

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
__END__

=head1 NAME

Net::SSH::Perl::Cipher::DES - Wrapper for SSH DES support

=head1 SYNOPSIS

    use Net::SSH::Cipher;
    my $cipher = Net::SSH::Cipher->new('DES', $key);
    print $cipher->encrypt($plaintext);

=head1 DESCRIPTION

I<Net::SSH::Perl::Cipher::DES> provides DES encryption
support for I<Net::SSH::Perl>. To do so it wraps around
I<Crypt::DES>, a C/XS implementation of the DES algorithm.

The DES algorithm used here is in CBC filter mode with a
key length of 8 bytes.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut

# $Id: IDEA.pm,v 1.3 2001/02/22 00:03:09 btrott Exp $

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
__END__

=head1 NAME

Net::SSH::Perl::Cipher::IDEA - Wrapper for SSH IDEA support

=head1 SYNOPSIS

    use Net::SSH::Cipher;
    my $cipher = Net::SSH::Cipher->new('IDEA', $key);
    print $cipher->encrypt($plaintext);

=head1 DESCRIPTION

I<Net::SSH::Perl::Cipher::IDEA> provides IDEA encryption
support for I<Net::SSH::Perl>. To do so it wraps around
I<Crypt::IDEA>, a C/XS implementation of the IDEA algorithm.

The IDEA algorithm used here is in CFB filter mode with a
key length of 16 bytes.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut

# $Id: RSA.pm,v 1.9 2001/05/03 18:22:29 btrott Exp $

package Net::SSH::Perl::Key::RSA;
use strict;

use Net::SSH::Perl::Util qw( :ssh1mp :authfile );

use Net::SSH::Perl::Key;
use base qw( Net::SSH::Perl::Key );

use Carp qw( croak );
use Math::GMP;
use Digest::MD5 qw( md5 );

sub init {
    my $key = shift;
    $key->{rsa} = {};

    my($blob) = @_;
    return unless $blob;
    my($bits, $e, $n) = split /\s+/, $blob, 3;
    $key->{rsa}{bits} = $bits;
    $key->{rsa}{e} = $e;
    $key->{rsa}{n} = $n;
}

sub size { $_[0]->{rsa}{bits} }

sub keygen { die "RSA key generation is unimplemented" }

sub read_private {
    my $class = shift;
    my($keyfile, $passphrase) = @_;
    my $key;
    eval {
        $key = _load_private_key($keyfile, $passphrase);
    };
    !$key || $@ ? undef : $key;
}

sub write_private {
    my $key = shift;
    my($keyfile, $passphrase) = @_;
    _save_private_key($keyfile, $key, $passphrase);
}

sub extract_public {
    my $class = shift;
    $class->new(@_);
}

sub dump_public { $_[0]->as_blob }

sub equal {
    my($keyA, $keyB) = @_;
    $keyA->{rsa}{bits} == $keyB->{rsa}{bits} &&
    $keyA->{rsa}{n} == $keyB->{rsa}{n} &&
    $keyA->{rsa}{e} == $keyB->{rsa}{e};
}

sub as_blob {
    my $key = shift;
    join ' ', $key->{rsa}{bits}, $key->{rsa}{e}, $key->{rsa}{n};
}

sub fingerprint_raw {
    my $key = shift;
    _mp_linearize($key->{rsa}->{n}) . _mp_linearize($key->{rsa}->{e});
}

1;
__END__

=head1 NAME

Net::SSH::Perl::Key::RSA - RSA key object

=head1 SYNOPSIS

    use Net::SSH::Perl::Key::RSA;
    my $key = Net::SSH::Perl::Key::RSA->new;

=head1 DESCRIPTION

I<Net::SSH::Perl::Key::RSA> subclasses I<Net::SSH::Perl::Key>
to implement a key object, SSH style. This object provides
functionality needed by I<Net::SSH::Perl>, ie. for checking
host key files, determining whether keys are equal, generating
key fingerprints, etc.

=head1 USAGE

I<Net::SSH::Perl::Key::RSA> implements the interface described in
the documentation for I<Net::SSH::Perl::Key>.

=head1 AUTHOR & COPYRIGHTS

Please see the Net::SSH::Perl manpage for author, copyright,
and license information.

=cut
